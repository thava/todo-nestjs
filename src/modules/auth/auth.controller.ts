import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  Req,
  Ip,
} from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { AuthResponseDto } from './dto/auth-response.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(
    @Body() registerDto: RegisterDto,
    @Req() req: Request,
    @Ip() ip: string,
  ): Promise<AuthResponseDto> {
    const userAgent = req.headers['user-agent'];
    return this.authService.register(registerDto, userAgent, ip);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Req() req: Request,
    @Ip() ip: string,
  ): Promise<AuthResponseDto> {
    const userAgent = req.headers['user-agent'];
    return this.authService.login(loginDto, userAgent, ip);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Req() req: Request,
    @Ip() ip: string,
  ): Promise<AuthResponseDto> {
    const userAgent = req.headers['user-agent'];
    return this.authService.refreshAccessToken(
      refreshTokenDto.refreshToken,
      userAgent,
      ip,
    );
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Req() req: Request,
    @Ip() ip: string,
  ): Promise<void> {
    const userAgent = req.headers['user-agent'];
    // Note: User might not be authenticated for logout, so we don't extract userId
    await this.authService.logout(refreshTokenDto.refreshToken, undefined, ip, userAgent);
  }
}
