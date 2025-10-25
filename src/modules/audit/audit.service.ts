import { Injectable, Inject } from '@nestjs/common';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import * as schema from '../../database/schema';
import { auditLogs } from '../../database/schema';
import { DATABASE_CONNECTION } from '../../database/database.module';

export interface AuditLogData {
  userId?: string;
  action: string;
  entityType?: string;
  entityId?: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

@Injectable()
export class AuditService {
  constructor(
    @Inject(DATABASE_CONNECTION)
    private readonly db: PostgresJsDatabase<typeof schema>,
  ) {}

  /**
   * Create an audit log entry
   */
  async log(data: AuditLogData): Promise<void> {
    try {
      await this.db.insert(auditLogs).values({
        userId: data.userId,
        action: data.action,
        entityType: data.entityType,
        entityId: data.entityId,
        metadata: data.metadata,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      });
    } catch (error) {
      // Log error but don't throw - audit logging should not break app flow
      console.error('Failed to create audit log:', error);
    }
  }

  /**
   * Log authentication events
   */
  async logAuth(
    action: 'LOGIN_SUCCESS' | 'LOGIN_FAILURE' | 'REGISTER' | 'LOGOUT' | 'REFRESH_TOKEN_USED' | 'REFRESH_TOKEN_ROTATED',
    userId?: string,
    metadata?: Record<string, unknown>,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action,
      entityType: 'auth',
      metadata,
      ipAddress,
      userAgent,
    });
  }

  /**
   * Log todo events
   */
  async logTodo(
    action: 'TODO_CREATED' | 'TODO_UPDATED' | 'TODO_DELETED' | 'TODO_VIEWED',
    userId: string,
    todoId: string,
    metadata?: Record<string, unknown>,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action,
      entityType: 'todo',
      entityId: todoId,
      metadata,
      ipAddress,
      userAgent,
    });
  }

  /**
   * Log admin actions
   */
  async logAdmin(
    action: 'ADMIN_TODO_VIEWED' | 'ADMIN_TODO_DELETED' | 'ADMIN_USER_VIEWED',
    userId: string,
    entityType: string,
    entityId?: string,
    metadata?: Record<string, unknown>,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action,
      entityType,
      entityId,
      metadata,
      ipAddress,
      userAgent,
    });
  }

  /**
   * Log failed authorization attempts
   */
  async logAuthorizationFailure(
    userId: string,
    action: string,
    entityType: string,
    entityId?: string,
    metadata?: Record<string, unknown>,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.log({
      userId,
      action: `AUTHORIZATION_FAILED_${action}`,
      entityType,
      entityId,
      metadata,
      ipAddress,
      userAgent,
    });
  }
}
