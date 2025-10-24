import { Module, Global } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';

export const DATABASE_CONNECTION = Symbol('DATABASE_CONNECTION');

const databaseProviders = [
  {
    provide: DATABASE_CONNECTION,
    useFactory: (configService: ConfigService) => {
      const connectionString = configService.get<string>('database.url');

      if (!connectionString) {
        throw new Error('DATABASE_URL is not defined');
      }

      const client = postgres(connectionString, {
        max: configService.get<number>('database.poolMax', 10),
        idle_timeout: 20,
        connect_timeout: 10,
      });

      return drizzle(client, { schema });
    },
    inject: [ConfigService],
  },
];

@Global()
@Module({
  providers: [...databaseProviders],
  exports: [DATABASE_CONNECTION],
})
export class DatabaseModule {}
