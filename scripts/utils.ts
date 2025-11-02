#!/usr/bin/env tsx

/**
 * CLI Utility for Todo NestJS API
 *
 * Usage:
 *   npx tsx scripts/utils.ts register test@example.com password123 "Test User"
 *   npx tsx scripts/utils.ts login test@example.com password123
 *   npx tsx scripts/utils.ts todos:create "Buy groceries" --priority=high --due="2025-12-31"
 *   npx tsx scripts/utils.ts todos:list
 *   npx tsx scripts/utils.ts todos:delete <todo_id>
 *   npx tsx scripts/utils.ts db:reinit
 */

import { config } from 'dotenv';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';
import { resolve, dirname } from 'path';
import * as postgresImport from 'postgres';
const postgres = (postgresImport as any).default || postgresImport;
import { drizzle } from 'drizzle-orm/postgres-js';
import { hash } from '@node-rs/argon2';
import { sql } from 'drizzle-orm';
import * as schema from '../src/database/schema/index.js';

// Load .env file from root directory
const __dirname = process.cwd();
const envPath = resolve(__dirname, '.env');

if (existsSync(envPath)) {
  config({ path: envPath });
  console.log(`✓ Loaded environment variables from ${envPath}`);
} else {
  console.log(`⚠ No .env file found at ${envPath}, using existing environment variables`);
}

// Configuration
const API_URL = process.env.API_URL || 'http://localhost:3000';
const TOKEN_FILE = resolve(process.cwd(), '.dev-tokens.json');

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
};

// Types
interface TokenData {
  accessToken: string;
  refreshToken: string;
  timestamp: string;
}

interface AuthResponse {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    fullName: string;
    role: string;
  };
}

interface Todo {
  id: string;
  description: string;
  priority: 'low' | 'medium' | 'high';
  dueDate?: string;
  createdAt: string;
  updatedAt: string;
}

// Helper functions
function printSuccess(message: string): void {
  console.log(`${colors.green}✓ ${message}${colors.reset}`);
}

function printError(message: string): void {
  console.error(`${colors.red}✗ ${message}${colors.reset}`);
}

function printInfo(message: string): void {
  console.log(`${colors.blue}ℹ ${message}${colors.reset}`);
}

function printWarning(message: string): void {
  console.log(`${colors.yellow}⚠ ${message}${colors.reset}`);
}

function printJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

// Token management
function saveTokens(accessToken: string, refreshToken: string): void {
  const tokenData: TokenData = {
    accessToken,
    refreshToken,
    timestamp: new Date().toISOString(),
  };
  writeFileSync(TOKEN_FILE, JSON.stringify(tokenData, null, 2));
  printSuccess(`Tokens saved to ${TOKEN_FILE}`);
}

function loadTokens(): TokenData | null {
  if (!existsSync(TOKEN_FILE)) {
    printError(`Token file not found: ${TOKEN_FILE}`);
    return null;
  }

  try {
    const data = readFileSync(TOKEN_FILE, 'utf-8');
    const tokens = JSON.parse(data) as TokenData;
    printSuccess('Tokens loaded');
    return tokens;
  } catch (error) {
    printError(`Failed to load tokens: ${error}`);
    return null;
  }
}

function clearTokens(): void {
  if (existsSync(TOKEN_FILE)) {
    unlinkSync(TOKEN_FILE);
    printSuccess('Token file deleted');
  } else {
    printInfo('No token file to delete');
  }
}

// HTTP helper
async function apiRequest<T>(
  endpoint: string,
  options: {
    method?: string;
    body?: unknown;
    useAuth?: boolean;
  } = {}
): Promise<{ status: number; data: T | null }> {
  const { method = 'GET', body, useAuth = false } = options;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (useAuth) {
    const tokens = loadTokens();
    if (!tokens) {
      throw new Error('No authentication tokens found. Please login first.');
    }
    headers['Authorization'] = `Bearer ${tokens.accessToken}`;
  }

  try {
    const response = await fetch(`${API_URL}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    let data: T | null = null;
    const contentType = response.headers.get('content-type');

    if (contentType?.includes('application/json')) {
      data = (await response.json()) as T;
    }

    return { status: response.status, data };
  } catch (error) {
    printError(`API request failed: ${error}`);
    throw error;
  }
}

// Commands

async function register(email: string, password: string, fullName: string): Promise<void> {
  printInfo(`Registering user: ${email}`);

  const { status, data } = await apiRequest<AuthResponse>('/auth/register', {
    method: 'POST',
    body: { email, password, fullName },
  });

  if (status === 201 && data) {
    printSuccess('User registered successfully');
    printJson(data.user);
    saveTokens(data.accessToken, data.refreshToken);
  } else {
    printError(`Registration failed (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function login(email: string, password: string): Promise<void> {
  printInfo(`Logging in: ${email}`);

  const { status, data } = await apiRequest<AuthResponse>('/auth/login', {
    method: 'POST',
    body: { email, password },
  });

  if (status === 200 && data) {
    printSuccess('Login successful');
    printJson(data.user);
    saveTokens(data.accessToken, data.refreshToken);
  } else {
    printError(`Login failed (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function refreshToken(): Promise<void> {
  const tokens = loadTokens();
  if (!tokens) {
    process.exit(1);
  }

  printInfo('Refreshing access token');

  const { status, data } = await apiRequest<AuthResponse>('/auth/refresh', {
    method: 'POST',
    body: { refreshToken: tokens.refreshToken },
  });

  if (status === 200 && data) {
    printSuccess('Token refreshed successfully');
    saveTokens(data.accessToken, data.refreshToken);
  } else {
    printError(`Token refresh failed (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function logout(): Promise<void> {
  const tokens = loadTokens();
  if (!tokens) {
    process.exit(1);
  }

  printInfo('Logging out');

  const { status } = await apiRequest('/auth/logout', {
    method: 'POST',
    body: { refreshToken: tokens.refreshToken },
  });

  if (status === 204) {
    printSuccess('Logout successful');
    clearTokens();
  } else {
    printError(`Logout failed (HTTP ${status})`);
    process.exit(1);
  }
}

async function getProfile(): Promise<void> {
  printInfo('Fetching user profile');

  const { status, data } = await apiRequest('/me', {
    useAuth: true,
  });

  if (status === 200 && data) {
    printSuccess('Profile retrieved');
    printJson(data);
  } else {
    printError(`Failed to get profile (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function createTodo(
  description: string,
  priority: 'low' | 'medium' | 'high' = 'medium',
  dueDate?: string
): Promise<void> {
  printInfo(`Creating todo: ${description}`);

  const body: Record<string, unknown> = { description, priority };
  if (dueDate) {
    body.dueDate = dueDate;
  }

  const { status, data } = await apiRequest<Todo>('/todos', {
    method: 'POST',
    body,
    useAuth: true,
  });

  if (status === 201 && data) {
    printSuccess('Todo created');
    printJson(data);
  } else {
    printError(`Failed to create todo (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function listTodos(): Promise<void> {
  printInfo('Fetching todos');

  const { status, data } = await apiRequest<Todo[]>('/todos', {
    useAuth: true,
  });

  if (status === 200 && data) {
    printSuccess(`Found ${data.length} todos`);
    printJson(data);
  } else {
    printError(`Failed to get todos (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function getTodo(todoId: string): Promise<void> {
  printInfo(`Fetching todo: ${todoId}`);

  const { status, data } = await apiRequest<Todo>(`/todos/${todoId}`, {
    useAuth: true,
  });

  if (status === 200 && data) {
    printSuccess('Todo retrieved');
    printJson(data);
  } else {
    printError(`Failed to get todo (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function updateTodo(
  todoId: string,
  updates: {
    description?: string;
    priority?: 'low' | 'medium' | 'high';
    dueDate?: string;
  }
): Promise<void> {
  printInfo(`Updating todo: ${todoId}`);

  const { status, data } = await apiRequest<Todo>(`/todos/${todoId}`, {
    method: 'PATCH',
    body: updates,
    useAuth: true,
  });

  if (status === 200 && data) {
    printSuccess('Todo updated');
    printJson(data);
  } else {
    printError(`Failed to update todo (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function deleteTodo(todoId: string): Promise<void> {
  printInfo(`Deleting todo: ${todoId}`);

  const { status, data } = await apiRequest(`/todos/${todoId}`, {
    method: 'DELETE',
    useAuth: true,
  });

  if (status === 204) {
    printSuccess('Todo deleted');
  } else {
    printError(`Failed to delete todo (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function healthCheck(): Promise<void> {
  printInfo('Checking API health');

  const { status, data } = await apiRequest('/health');

  if (status === 200 && data) {
    printSuccess('API is healthy');
    printJson(data);
  } else {
    printError(`API health check failed (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function readinessCheck(): Promise<void> {
  printInfo('Checking API readiness');

  const { status, data } = await apiRequest('/readiness');

  if (status === 200 && data) {
    printSuccess('API is ready');
    printJson(data);
  } else {
    printError(`API readiness check failed (HTTP ${status})`);
    if (data) printJson(data);
    process.exit(1);
  }
}

async function dbReinit(): Promise<void> {
  printInfo('Starting database reinitialization');

  // Get database connection string from environment
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    printError('DATABASE_URL environment variable not set');
    process.exit(1);
  }

  // Create database connection
  const client = postgres(databaseUrl);
  const db = drizzle(client, { schema });

  try {
    // Delete all data from tables (in reverse dependency order)
    printInfo('Deleting all data from tables...');
    await db.delete(schema.todos);
    await db.delete(schema.emailVerificationTokens);
    await db.delete(schema.passwordResetTokens);
    await db.delete(schema.refreshTokenSessions);
    await db.delete(schema.auditLogs);
    await db.delete(schema.users);
    printSuccess('All tables cleared');

    // Create test users
    const testUsers = [
      { email: 'guest1@example.com', password: 'Guest@123', fullName: 'Guest User 1', role: 'guest' as const },
      { email: 'admin1@example.com', password: 'Admin@123', fullName: 'Admin User 1', role: 'admin' as const },
      { email: 'sysadmin1@example.com', password: 'Sysadmin@123', fullName: 'Sysadmin User 1', role: 'sysadmin' as const },
    ];

    printInfo('Creating test users...');
    const createdUsers: Array<{ id: string; email: string; username: string }> = [];

    for (const userData of testUsers) {
      // Hash password using Argon2id
      const passwordHash = await hash(userData.password, {
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1,
      });

      // Insert user with email already verified
      const [user] = await db.insert(schema.users).values({
        email: userData.email,
        fullName: userData.fullName,
        passwordHashPrimary: passwordHash,
        role: userData.role,
        emailVerifiedAt: new Date(),
      }).returning();

      createdUsers.push({ ...user, username: userData.email.split('@')[0] });
      printSuccess(`Created user: ${userData.email} (${userData.role})`);
    }

    // Create 3 todos for each user
    printInfo('Creating todos for each user...');
    const todoTemplates = [
      { action: 'to visit dentist', priority: 'high' as const },
      { action: 'to buy groceries', priority: 'medium' as const },
      { action: 'to finish project', priority: 'low' as const },
    ];

    for (const user of createdUsers) {
      for (const template of todoTemplates) {
        await db.insert(schema.todos).values({
          ownerId: user.id,
          description: `${user.username} ${template.action}`,
          priority: template.priority,
        });
      }
      printSuccess(`Created 3 todos for ${user.email}`);
    }

    printSuccess('Database reinitialization completed successfully');
    printInfo('\nTest accounts created:');
    printInfo('  guest1@example.com / Guest@123 (role: guest)');
    printInfo('  admin1@example.com / Admin@123 (role: admin)');
    printInfo('  sysadmin1@example.com / Sysadmin@123 (role: sysadmin)');
    printInfo('\n9 todos created (3 per user)');

  } catch (error) {
    printError(`Database reinitialization failed: ${error}`);
    throw error;
  } finally {
    await client.end();
  }
}

// Parse command line arguments
function parseArgs(args: string[]): Record<string, string> {
  const parsed: Record<string, string> = {};

  for (const arg of args) {
    if (arg.startsWith('--')) {
      const [key, value] = arg.slice(2).split('=');
      if (key && value) {
        parsed[key] = value;
      }
    }
  }

  return parsed;
}

// Help message
function showHelp(): void {
  console.log(`
${colors.blue}Todo NestJS API - CLI Utility${colors.reset}

${colors.green}Configuration:${colors.reset}
  API_URL=${API_URL}
  TOKEN_FILE=${TOKEN_FILE}

${colors.green}Authentication:${colors.reset}
  register <email> <password> <fullName>  - Register a new user
  login <email> <password>                - Login and save tokens
  refresh                                 - Refresh access token
  logout                                  - Logout and clear tokens
  profile                                 - Get current user profile

${colors.green}Todo Operations:${colors.reset}
  todos:create <description> [--priority=high] [--due=2025-12-31]
  todos:list                              - List all todos
  todos:get <todo_id>                     - Get a specific todo
  todos:update <todo_id> [--description="New"] [--priority=low] [--due=2025-12-31]
  todos:delete <todo_id>                  - Delete a todo

${colors.green}Health:${colors.reset}
  health                                  - Check API health
  readiness                               - Check API readiness

${colors.green}Token Management:${colors.reset}
  tokens:clear                            - Delete token file

${colors.green}Database Management:${colors.reset}
  db:reinit                               - Reinitialize database with test data

${colors.green}Examples:${colors.reset}
  npx tsx scripts/utils.ts register test@example.com password123 "Test User"
  npx tsx scripts/utils.ts login test@example.com password123
  npx tsx scripts/utils.ts todos:create "Buy groceries" --priority=high --due=2025-12-31
  npx tsx scripts/utils.ts todos:list
  npx tsx scripts/utils.ts todos:delete <todo_id>

${colors.yellow}Note: Requires tsx to be installed: pnpm add -D tsx${colors.reset}
`);
}

// Main CLI handler
async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    showHelp();
    return;
  }

  try {
    switch (command) {
      // Authentication
      case 'register':
        if (args.length < 3) {
          printError('Usage: register <email> <password> <fullName>');
          process.exit(1);
        }
        await register(args[0], args[1], args[2]);
        break;

      case 'login':
        if (args.length < 2) {
          printError('Usage: login <email> <password>');
          process.exit(1);
        }
        await login(args[0], args[1]);
        break;

      case 'refresh':
        await refreshToken();
        break;

      case 'logout':
        await logout();
        break;

      case 'profile':
        await getProfile();
        break;

      // Todos
      case 'todos:create': {
        if (args.length < 1) {
          printError('Usage: todos:create <description> [--priority=high] [--due=2025-12-31]');
          process.exit(1);
        }
        const description = args[0];
        const options = parseArgs(args.slice(1));
        await createTodo(
          description,
          (options.priority as 'low' | 'medium' | 'high') || 'medium',
          options.due
        );
        break;
      }

      case 'todos:list':
        await listTodos();
        break;

      case 'todos:get':
        if (args.length < 1) {
          printError('Usage: todos:get <todo_id>');
          process.exit(1);
        }
        await getTodo(args[0]);
        break;

      case 'todos:update': {
        if (args.length < 1) {
          printError('Usage: todos:update <todo_id> [--description="New"] [--priority=low]');
          process.exit(1);
        }
        const todoId = args[0];
        const options = parseArgs(args.slice(1));
        const updates: Record<string, unknown> = {};
        if (options.description) updates.description = options.description;
        if (options.priority) updates.priority = options.priority;
        if (options.due) updates.dueDate = options.due;
        await updateTodo(todoId, updates);
        break;
      }

      case 'todos:delete':
        if (args.length < 1) {
          printError('Usage: todos:delete <todo_id>');
          process.exit(1);
        }
        await deleteTodo(args[0]);
        break;

      // Health
      case 'health':
        await healthCheck();
        break;

      case 'readiness':
        await readinessCheck();
        break;

      // Token management
      case 'tokens:clear':
        clearTokens();
        break;

      // Database management
      case 'db:reinit':
        await dbReinit();
        break;

      default:
        printError(`Unknown command: ${command}`);
        showHelp();
        process.exit(1);
    }
  } catch (error) {
    printError(`Command failed: ${error}`);
    process.exit(1);
  }
}

// Run CLI
main();
