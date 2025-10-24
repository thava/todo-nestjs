import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
  Inject,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { eq } from 'drizzle-orm';
import { createHash } from 'crypto';
import * as schema from '../../database/schema';
import { users, refreshTokenSessions } from '../../database/schema';
import { DATABASE_CONNECTION } from '../../database/database.module';
import { PasswordService } from '../../common/services/password.service';
import { TokenService } from '../../common/services/jwt.service';
import { AuditService } from '../audit/audit.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuthResponseDto } from './dto/auth-response.dto';

@Injectable()
export class AuthService {
  constructor(
    @Inject(DATABASE_CONNECTION)
    private readonly db: PostgresJsDatabase<typeof schema>,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
    private readonly configService: ConfigService,
    private readonly auditService: AuditService,
  ) {}

  /**
   * Register a new user
   */
  async register(
    registerDto: RegisterDto,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<AuthResponseDto> {
    const { email, password, fullName } = registerDto;

    // Normalize email
    const normalizedEmail = email.toLowerCase().trim();

    // Validate password strength
    const passwordValidation = this.passwordService.validatePasswordStrength(
      password,
      normalizedEmail,
    );

    if (!passwordValidation.isValid) {
      throw new BadRequestException({
        message: 'Password does not meet security requirements',
        errors: passwordValidation.errors,
      });
    }

    // Check if user already exists
    const existingUser = await this.db.query.users.findFirst({
      where: eq(users.email, normalizedEmail),
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Hash password
    const passwordHash = await this.passwordService.hashPassword(password);

    // Create user
    const [newUser] = await this.db
      .insert(users)
      .values({
        email: normalizedEmail,
        fullName: fullName.trim(),
        passwordHashPrimary: passwordHash,
        role: 'guest',
      })
      .returning();

    // Log registration
    await this.auditService.logAuth(
      'REGISTER',
      newUser.id,
      { email: newUser.email },
      ipAddress,
      userAgent,
    );

    // Generate tokens and create session
    return this.createAuthResponse(newUser, userAgent, ipAddress);
  }

  /**
   * Login user
   */
  async login(
    loginDto: LoginDto,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    // Normalize email
    const normalizedEmail = email.toLowerCase().trim();

    // Find user
    const user = await this.db.query.users.findFirst({
      where: eq(users.email, normalizedEmail),
    });

    if (!user) {
      // Log failed login attempt
      await this.auditService.logAuth(
        'LOGIN_FAILURE',
        undefined,
        { email: normalizedEmail, reason: 'user_not_found' },
        ipAddress,
        userAgent,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verifyPassword(
      user.passwordHashPrimary,
      password,
    );

    if (!isPasswordValid) {
      // Log failed login attempt
      await this.auditService.logAuth(
        'LOGIN_FAILURE',
        user.id,
        { email: user.email, reason: 'invalid_password' },
        ipAddress,
        userAgent,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // Log successful login
    await this.auditService.logAuth(
      'LOGIN_SUCCESS',
      user.id,
      { email: user.email },
      ipAddress,
      userAgent,
    );

    // Generate tokens and create session
    return this.createAuthResponse(user, userAgent, ipAddress);
  }

  /**
   * Refresh access token
   */
  async refreshAccessToken(
    refreshToken: string,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<AuthResponseDto> {
    // Verify refresh token
    let payload;
    try {
      payload = await this.tokenService.verifyRefreshToken(refreshToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Hash the refresh token for lookup
    const tokenHash = this.hashToken(refreshToken);

    // Find session
    const session = await this.db.query.refreshTokenSessions.findFirst({
      where: eq(refreshTokenSessions.refreshTokenHash, tokenHash),
    });

    if (!session) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Check if session is revoked
    if (session.revokedAt) {
      throw new UnauthorizedException('Refresh token has been revoked');
    }

    // Check if session is expired
    if (new Date() > session.expiresAt) {
      throw new UnauthorizedException('Refresh token has expired');
    }

    // Get user
    const user = await this.db.query.users.findFirst({
      where: eq(users.id, payload.sub),
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Revoke old refresh token (rotation)
    await this.db
      .update(refreshTokenSessions)
      .set({ revokedAt: new Date() })
      .where(eq(refreshTokenSessions.id, session.id));

    // Log token refresh
    await this.auditService.logAuth(
      'REFRESH_TOKEN_ROTATED',
      user.id,
      { sessionId: session.id },
      ipAddress,
      userAgent,
    );

    // Generate new tokens and create new session
    return this.createAuthResponse(user, userAgent, ipAddress);
  }

  /**
   * Logout (revoke refresh token)
   */
  async logout(refreshToken: string, userId?: string, ipAddress?: string, userAgent?: string): Promise<void> {
    const tokenHash = this.hashToken(refreshToken);

    await this.db
      .update(refreshTokenSessions)
      .set({ revokedAt: new Date() })
      .where(eq(refreshTokenSessions.refreshTokenHash, tokenHash));

    // Log logout
    if (userId) {
      await this.auditService.logAuth(
        'LOGOUT',
        userId,
        {},
        ipAddress,
        userAgent,
      );
    }
  }

  /**
   * Create auth response with tokens and session
   */
  private async createAuthResponse(
    user: typeof users.$inferSelect,
    userAgent?: string,
    ipAddress?: string,
  ): Promise<AuthResponseDto> {
    // Generate access token
    const accessToken = await this.tokenService.generateAccessToken({
      sub: user.id,
      email: user.email,
      role: user.role,
    });

    // Create refresh token session
    const expiresAt = new Date();
    const expiryDays = 7; // 7 days
    expiresAt.setDate(expiresAt.getDate() + expiryDays);

    const [session] = await this.db
      .insert(refreshTokenSessions)
      .values({
        userId: user.id,
        refreshTokenHash: '', // Will be updated below
        userAgent,
        ipAddress,
        expiresAt,
      })
      .returning();

    // Generate refresh token with session ID
    const refreshToken = await this.tokenService.generateRefreshToken({
      sub: user.id,
      sessionId: session.id,
    });

    // Update session with hashed refresh token
    const tokenHash = this.hashToken(refreshToken);
    await this.db
      .update(refreshTokenSessions)
      .set({ refreshTokenHash: tokenHash })
      .where(eq(refreshTokenSessions.id, session.id));

    return {
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        emailVerified: !!user.emailVerifiedAt,
      },
    };
  }

  /**
   * Hash token for storage (SHA-256)
   */
  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
