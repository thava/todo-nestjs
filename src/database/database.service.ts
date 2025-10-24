import { Injectable, Inject } from '@nestjs/common';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { sql } from 'drizzle-orm';
import { DATABASE_CONNECTION } from './database.module';
import * as schema from './schema';

@Injectable()
export class DatabaseService {
  constructor(
    @Inject(DATABASE_CONNECTION)
    private readonly db: PostgresJsDatabase<typeof schema>,
  ) {}

  /**
   * Check database connection health
   */
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.db.execute(sql`SELECT 1 as health`);
      return result.length > 0;
    } catch (error) {
      console.error('Database health check failed:', error);
      return false;
    }
  }

  /**
   * Get the database instance
   */
  getDb(): PostgresJsDatabase<typeof schema> {
    return this.db;
  }
}
