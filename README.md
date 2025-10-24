# Todo NestJS Backend

A production-ready backend providing **user authentication, authorization, and CRUD modules** with a ToDo feature, built with NestJS, Drizzle ORM, and PostgreSQL.

## Tech Stack

- **Framework**: NestJS 11
- **Language**: TypeScript (strict mode)
- **Database**: PostgreSQL
- **ORM**: Drizzle ORM with drizzle-kit
- **APIs**: REST + GraphQL (Apollo Server)
- **Authentication**: JWT (Access + Refresh tokens)
- **Password Hashing**: Argon2id
- **Validation**: class-validator, class-transformer, Zod

## Features

- ✅ User authentication with JWT (access + refresh tokens)
- ✅ Role-based access control (guest, admin, sysadmin)
- ✅ Email verification
- ✅ Password reset flow
- ✅ Session management with refresh token rotation
- ✅ Todo CRUD with ownership and RBAC
- ✅ Audit logging for security events
- ✅ PostgreSQL with connection pooling
- ✅ Environment variable validation
- 🚧 REST API endpoints (coming soon)
- 🚧 GraphQL API (coming soon)
- 🚧 Rate limiting (coming soon)
- 🚧 Email service integration (coming soon)

## Prerequisites

- Node.js 18+ and pnpm
- Docker and Docker Compose (recommended for development)
- OR PostgreSQL 14+ running locally

## Quick Start with Docker (Recommended)

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Start PostgreSQL with Docker Compose

```bash
# Start PostgreSQL and pgAdmin
docker-compose up -d

# Check if containers are running
docker-compose ps
```

This will start:
- **PostgreSQL** on `localhost:5432`
- **pgAdmin** (web UI) on `http://localhost:5050`
  - Email: `admin@todo.local`
  - Password: `admin`

### 3. Environment Variables

The project includes a `.env.development` file pre-configured for Docker. You can use it as-is:

```bash
# Use the development environment (already configured)
# The .env file is already set up with Docker database credentials
```

Or create your own `.env.local`:

```bash
cp .env.example .env.local
# Edit .env.local with your configuration
```

### 4. Run Database Migrations

```bash
# Apply database migrations
pnpm run migration:run
```

### 5. Start Development Server

```bash
# Watch mode with hot reload
pnpm run start:dev
```

The API will be available at `http://localhost:3000`

### 6. Test the API

```bash
# Check health
curl http://localhost:3000/health

# Check database connectivity
curl http://localhost:3000/readiness
```

### 7. Stop Docker Containers

```bash
# Stop containers
docker-compose down

# Stop and remove volumes (deletes all data)
docker-compose down -v
```

## Quick Start without Docker

If you prefer to use a local PostgreSQL installation:

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Set Up Environment Variables

```bash
cp .env.example .env.local
```

Edit `.env.local` with your database credentials:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/todo_nestjs
JWT_ACCESS_SECRET=your-256-bit-secret-here
JWT_REFRESH_SECRET=your-256-bit-secret-here
```

### 3. Create Database and Run Migrations

```bash
# Create database
createdb todo_nestjs

# Run migrations
pnpm run migration:run
```

### 4. Start Development Server

```bash
pnpm run start:dev
```

## Database Management

### Generate New Migration

After modifying schemas in `src/database/schema/`:

```bash
pnpm run migration:generate
```

This will create a new migration file in `src/database/migrations/`.

### Run Migrations

Apply pending migrations to the database:

```bash
pnpm run migration:run
```

### Push Schema Changes (Development Only)

Push schema changes directly without creating migration files:

```bash
pnpm run db:push
```

⚠️ **Warning**: This is for development only and will not create migration files.

### Drizzle Studio (Database GUI)

Launch a web-based database explorer:

```bash
pnpm run db:studio
```

Open `https://local.drizzle.studio` in your browser.

## Project Structure

```
src/
├── common/               # Shared utilities
│   ├── config/          # Configuration and env validation
│   ├── guards/          # Auth guards (RBAC)
│   ├── decorators/      # Custom decorators
│   ├── interceptors/    # Request/response interceptors
│   ├── filters/         # Exception filters
│   └── pipes/           # Validation pipes
├── database/            # Database layer
│   ├── schema/          # Drizzle ORM schemas
│   └── migrations/      # SQL migration files
├── modules/             # Feature modules
│   ├── auth/            # Authentication module
│   ├── users/           # Users module
│   ├── todos/           # Todos module
│   ├── email/           # Email service module
│   └── audit/           # Audit logging module
├── app.module.ts        # Root module
└── main.ts              # Application entry point
```

## Database Schema

### Tables

- **users**: User accounts with email, password hash, role
- **refresh_token_sessions**: Active refresh token sessions
- **password_reset_tokens**: One-time password reset tokens
- **email_verification_tokens**: Email verification tokens
- **todos**: Todo items with owner, description, priority, due date
- **audit_logs**: Security and activity audit trail

### Roles

- `guest`: Regular user (default)
- `admin`: Can view all todos, manage own
- `sysadmin`: Full system access

## Scripts

```bash
# Development
pnpm run start:dev       # Start with hot reload
pnpm run start:debug     # Start with debug mode

# Build
pnpm run build           # Build for production
pnpm run start:prod      # Run production build

# Testing
pnpm run test            # Run unit tests
pnpm run test:watch      # Run tests in watch mode
pnpm run test:cov        # Run tests with coverage
pnpm run test:e2e        # Run end-to-end tests

# Code Quality
pnpm run lint            # Lint and fix code
pnpm run format          # Format code with Prettier

# Database
pnpm run migration:generate  # Generate migration from schema
pnpm run migration:run       # Apply migrations
pnpm run db:push            # Push schema (dev only)
pnpm run db:studio          # Launch Drizzle Studio
```

## Environment Variables

See `.env.example` for all available configuration options.

### Required Variables

- `DATABASE_URL`: PostgreSQL connection string
- `JWT_ACCESS_SECRET`: Secret for access tokens
- `JWT_REFRESH_SECRET`: Secret for refresh tokens
- `EMAIL_FROM`: Sender email address

### Optional Variables

- `PORT`: Server port (default: 3000)
- `CORS_ALLOWED_ORIGINS`: Comma-separated allowed origins
- `ENABLE_DEV_REVERSIBLE_PASSWORDS`: Dev-only reversible password encryption
- `LOG_LEVEL`: Logging level (error, warn, info, debug)

## Security Features

- **Argon2id** password hashing with configurable parameters
- **JWT** access tokens (15min) + refresh tokens (7 days)
- **Refresh token rotation** on every use
- **Session management** with device tracking
- **Rate limiting** on sensitive endpoints (coming soon)
- **Audit logging** for all security events
- **CORS** configuration for cross-origin requests
- **Helmet** security headers (coming soon)

## Development Guidelines

### Adding a New Feature Module

1. Generate module: `nest g module modules/feature-name`
2. Create schema in `src/database/schema/feature-name.schema.ts`
3. Generate migration: `pnpm run migration:generate`
4. Apply migration: `pnpm run migration:run`
5. Implement service, controller, and resolvers

### Password Requirements

- Minimum 8 characters
- At least 3 of: uppercase, lowercase, number, special character
- Cannot be same as email
- Cannot reuse last 3 passwords (coming soon)

## Roadmap

- [ ] Implement authentication endpoints
- [ ] Implement users module endpoints
- [ ] Implement todos CRUD endpoints
- [ ] Add GraphQL API
- [ ] Add email service (SendGrid/SMTP)
- [ ] Add rate limiting with Redis
- [ ] Add password history tracking
- [ ] Implement OAuth providers (Google, Microsoft)
- [ ] Add health check endpoints
- [ ] Add Prometheus metrics
- [ ] Set up CI/CD pipeline
- [ ] Add comprehensive test suite

## License

UNLICENSED

## Support

For detailed requirements and architecture decisions, see [CLAUDE.md](./CLAUDE.md).
