# Requirements Document

## **Extensible Auth ToDo Backend (NestJS + Drizzle + Postgres + Next.js SPA)**

A production-ready backend providing **user authentication, authorization, and CRUD modules**, with a placeholder **ToDo** feature and a fully extensible architecture to support future modules and additional identity providers.

---

## **1. Technology Stack**

| Component | Choice / Notes |
|-----------|----------------|
| Language | **TypeScript** (strict mode enabled) |
| Backend Framework | **NestJS** (modular architecture) |
| API Interfaces | **REST** + **GraphQL** (`@nestjs/graphql` + Apollo Server, code-first) |
| ORM | **Drizzle ORM** |
| DB Schema & Migrations | **drizzle-kit** with versioned migrations |
| Database | **PostgreSQL** (single instance, connection pooling enabled) |
| Frontend Consumer | **Next.js SPA** (UI at different domain than API) |
| Hosting Model | UI and API **on different domains** (e.g., `foo.com` UI and `bar.com` API) |
| Environments | `development`, `test`, `production` |
| Deployment Policy | Dev auto-deploy; test/prod deploy manually after migration approval |

---

## **2. Authentication & Identity**

### **2.1 Login Methods**

#### Current
- Local **email + password**

#### Future Expandability (Planned)
- OAuth (Google, Microsoft), OIDC, SAML, corporate SSO
- All external identity providers **map to internal user record by email**

### **2.2 Token Strategy**

| Token | Stored In | Lifetime | Risk | Notes |
|-------|-----------|----------|------|-------|
| **Access Token (JWT)** | **In memory only** (React state) | 15 minutes | XSS-risk only | Sent via `Authorization: Bearer` header |
| **Refresh Token (JWT)** | **localStorage** | 7 days (rotated on every use) | XSS-risk only | Sent manually in refresh call, not via cookie |

**Architecture Decision:**
- **No httpOnly cookies** for cross-domain setup (foo.com → bar.com)
- Cookies would require `SameSite=None; Secure`, complicating CORS
- **No CSRF exposure** because tokens are **not automatically attached**
- Client responsible for:
  - Storing access token in memory (React state/context)
  - Storing refresh token in localStorage
  - Automatic token refresh before expiry
  - Sending tokens explicitly in Authorization header

### **2.3 Token Payload Structure**

**Access Token:**
```typescript
{
  sub: string;        // user.id (UUID)
  email: string;      // user.email
  role: 'guest' | 'admin' | 'sysadmin';
  iat: number;        // issued at
  exp: number;        // expires at (15 min from iat)
}
```

**Refresh Token:**
```typescript
{
  sub: string;        // user.id
  sessionId: string;  // refresh_token_sessions.id
  iat: number;
  exp: number;        // 7 days from iat
}
```

### **2.4 Password Storage**

| Type | Purpose | Algorithm |
|------|---------|-----------|
| Primary password hash | **Authentication** | **Argon2id** (time=2, memory=19456, parallelism=1) |
| Reversible password (dev only) | Debugging convenience | AES-256-GCM encrypted, stored in `password_reversible_dev` column |

**Password Policy:**
- Minimum 8 characters
- Must contain at least 3 of: uppercase, lowercase, number, special character
- Blacklist common passwords (top 1000)
- Cannot be same as email

**Reversible Password Rules:**
- Only enabled when:
  ```env
  NODE_ENV=development
  ENABLE_DEV_REVERSIBLE_PASSWORDS=true
  DEV_REVERSIBLE_PASSWORD_KEY=<base64-encoded-32-byte-key>
  ```
- Column is **always NULL in test & prod** (enforced by migration)
- Encryption: AES-256-GCM with random IV per password

### **2.5 Dev-Only Password Retrieval Script**

```bash
./scripts/get-password.ts <email>
```

- Input: user email
- Output: decrypted password (stdout)
- Exits with error if not in development mode or missing encryption key
- Logs access to audit log

---

## **3. Data Models**

### **3.1 Users Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | |
| email | VARCHAR(255) | UNIQUE, NOT NULL | Lowercase, trimmed |
| full_name | VARCHAR(255) | NOT NULL | Display name |
| password_hash_primary | TEXT | NOT NULL | Argon2id hash |
| password_reversible_dev | TEXT | NULLABLE | AES-GCM encrypted, dev only |
| role | ENUM | NOT NULL, DEFAULT 'guest' | 'guest', 'admin', 'sysadmin' |
| email_verified_at | TIMESTAMPTZ | NULLABLE | NULL = unverified |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Auto-updated by trigger |

**Indexes:**
- UNIQUE INDEX on `email`
- INDEX on `role` (for admin queries)

### **3.2 Refresh Token Sessions Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | |
| user_id | UUID | FOREIGN KEY → users.id, NOT NULL | ON DELETE CASCADE |
| refresh_token_hash | TEXT | NOT NULL | SHA-256 hash of refresh token |
| user_agent | TEXT | NULLABLE | For session display |
| ip_address | INET | NULLABLE | For audit |
| expires_at | TIMESTAMPTZ | NOT NULL | Token expiry time |
| revoked_at | TIMESTAMPTZ | NULLABLE | Manual revocation |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |

**Indexes:**
- INDEX on `user_id` (for user session queries)
- INDEX on `refresh_token_hash` (for validation lookup)
- INDEX on `expires_at` (for cleanup job)

**Automatic Cleanup:**
- Daily cron job deletes sessions where `expires_at < NOW() - INTERVAL '30 days'`

**Session Limits:**
- Maximum 5 concurrent sessions per user
- Oldest session auto-revoked when limit exceeded

### **3.3 Password Reset Tokens Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | |
| user_id | UUID | FOREIGN KEY → users.id, NOT NULL | ON DELETE CASCADE |
| token_hash | TEXT | NOT NULL | SHA-256 hash of token |
| expires_at | TIMESTAMPTZ | NOT NULL | 1 hour from creation |
| used_at | TIMESTAMPTZ | NULLABLE | Single use only |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |

**Indexes:**
- INDEX on `token_hash`
- INDEX on `expires_at`

**Token Format:**
- 32-byte random token (base64url encoded)
- 1-hour expiry
- Single use (marked as used after consumption)

### **3.4 Email Verification Tokens Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | |
| user_id | UUID | FOREIGN KEY → users.id, NOT NULL | ON DELETE CASCADE |
| token_hash | TEXT | NOT NULL | SHA-256 hash of token |
| expires_at | TIMESTAMPTZ | NOT NULL | 24 hours from creation |
| verified_at | TIMESTAMPTZ | NULLABLE | Single use only |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |

**Indexes:**
- INDEX on `token_hash`
- INDEX on `expires_at`

### **3.5 Todos Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | |
| owner_id | UUID | FOREIGN KEY → users.id, NOT NULL | ON DELETE CASCADE |
| description | TEXT | NOT NULL | Required |
| due_date | TIMESTAMPTZ | NULLABLE | Optional deadline |
| priority | ENUM | NOT NULL, DEFAULT 'medium' | 'low', 'medium', 'high' |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |
| updated_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | Auto-updated by trigger |

**Indexes:**
- INDEX on `owner_id` (for user todos query)
- INDEX on `due_date` (for filtering/sorting)
- INDEX on `priority` (for filtering)

**Virtual Field (API only):**
- `ownerEmail`: Derived from JOIN with users table, not stored

### **3.6 Audit Logs Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | |
| user_id | UUID | FOREIGN KEY → users.id, NULLABLE | ON DELETE SET NULL |
| action | VARCHAR(100) | NOT NULL | e.g., 'LOGIN_SUCCESS', 'PASSWORD_RESET' |
| entity_type | VARCHAR(50) | NULLABLE | e.g., 'user', 'todo' |
| entity_id | UUID | NULLABLE | Related entity |
| metadata | JSONB | NULLABLE | Additional context |
| ip_address | INET | NULLABLE | Request IP |
| user_agent | TEXT | NULLABLE | Request user agent |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |

**Indexes:**
- INDEX on `user_id`
- INDEX on `action`
- INDEX on `created_at` (for time-range queries)
- GIN INDEX on `metadata` (for JSON queries)

**Logged Events:**
- `LOGIN_SUCCESS`, `LOGIN_FAILURE`
- `REGISTER`
- `PASSWORD_RESET_REQUEST`, `PASSWORD_RESET_COMPLETE`
- `EMAIL_VERIFICATION_SENT`, `EMAIL_VERIFIED`
- `REFRESH_TOKEN_USED`, `REFRESH_TOKEN_ROTATED`
- `TODO_CREATED`, `TODO_UPDATED`, `TODO_DELETED`
- `ADMIN_TODO_VIEWED`, `ADMIN_TODO_DELETED`
- `SESSION_REVOKED`

### **3.7 Schema Migrations Table**

| Field | Type | Constraints | Notes |
|-------|------|-------------|-------|
| id | SERIAL | PRIMARY KEY | |
| version | VARCHAR(50) | UNIQUE, NOT NULL | Migration version |
| description | TEXT | NOT NULL | Migration description |
| applied_at | TIMESTAMPTZ | NOT NULL, DEFAULT NOW() | |

**Migration Strategy:**
- Sequential versioning: `0001_initial.sql`, `0002_add_todos.sql`, etc.
- Each migration tracked in this table
- Rollback scripts: `0001_initial.down.sql` (stored but not auto-applied)

---

## **4. Authorization Rules (RBAC + Ownership)**

### **4.1 Role Hierarchy**

| Role | Level | Description |
|------|-------|-------------|
| `guest` | 1 | Regular user |
| `admin` | 2 | Can view all todos, manage own |
| `sysadmin` | 3 | Full system access |

### **4.2 ToDo Permissions Matrix**

| Action | guest | admin | sysadmin |
|--------|-------|-------|----------|
| Read own todos | ✅ | ✅ | ✅ |
| Read all todos | ❌ | ✅ | ✅ |
| Create todo | ✅ | ✅ | ✅ |
| Update own todo | ✅ | ✅ | ✅ |
| Update any todo | ❌ | ❌ | ✅ |
| Delete own todo | ✅ | ✅ | ✅ |
| Delete any todo | ❌ | ❌ | ✅ |

### **4.3 User Management Permissions**

| Action | guest | admin | sysadmin |
|--------|-------|-------|----------|
| View own profile | ✅ | ✅ | ✅ |
| Update own profile | ✅ | ✅ | ✅ |
| View all users | ❌ | ✅ | ✅ |
| Update any user | ❌ | ❌ | ✅ |
| Delete any user | ❌ | ❌ | ✅ |
| Assign roles | ❌ | ❌ | ✅ |

### **4.4 Session Management Permissions**

| Action | guest | admin | sysadmin |
|--------|-------|-------|----------|
| View own sessions | ✅ | ✅ | ✅ |
| Revoke own session | ✅ | ✅ | ✅ |
| View all sessions | ❌ | ❌ | ✅ |
| Revoke any session | ❌ | ❌ | ✅ |

---

## **5. API Endpoints**

### **5.1 REST Endpoints**

#### Authentication
```
POST   /auth/register
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
POST   /auth/request-password-reset
POST   /auth/reset-password
POST   /auth/verify-email
POST   /auth/resend-verification
```

#### User Profile
```
GET    /me
PATCH  /me
GET    /me/sessions
DELETE /me/sessions/:sessionId
```

#### Todos
```
POST   /todos
GET    /todos
GET    /todos/:id
PATCH  /todos/:id
DELETE /todos/:id
```

#### Admin
```
GET    /admin/todos              (admin + sysadmin)
GET    /admin/todos/:id          (admin + sysadmin)
DELETE /admin/todos/:id          (sysadmin only)
GET    /admin/users              (admin + sysadmin)
GET    /admin/users/:id          (admin + sysadmin)
PATCH  /admin/users/:id          (sysadmin only)
DELETE /admin/users/:id          (sysadmin only)
GET    /admin/audit-logs         (sysadmin only)
GET    /admin/sessions           (sysadmin only)
DELETE /admin/sessions/:id       (sysadmin only)
```

#### Health & Monitoring
```
GET    /health                   (public, returns 200 OK)
GET    /readiness                (public, checks DB connection)
GET    /metrics                  (Prometheus format, optionally protected)
```

### **5.2 GraphQL Schema**

#### Queries
```graphql
type Query {
  me: User!
  myTodos(
    limit: Int = 20
    offset: Int = 0
    priority: Priority
    dueBefore: DateTime
  ): TodoConnection!
  
  todo(id: ID!): Todo
  
  # Admin only
  adminTodos(
    limit: Int = 20
    offset: Int = 0
    userId: ID
  ): TodoConnection!
  
  adminUsers(
    limit: Int = 20
    offset: Int = 0
  ): UserConnection!
  
  # Sysadmin only
  auditLogs(
    limit: Int = 50
    offset: Int = 0
    action: String
    userId: ID
    after: DateTime
  ): AuditLogConnection!
}
```

#### Mutations
```graphql
type Mutation {
  # Auth
  register(input: RegisterInput!): AuthPayload!
  login(input: LoginInput!): AuthPayload!
  refresh(refreshToken: String!): AuthPayload!
  logout(refreshToken: String!): Boolean!
  requestPasswordReset(email: String!): Boolean!
  resetPassword(token: String!, newPassword: String!): Boolean!
  verifyEmail(token: String!): Boolean!
  resendVerification: Boolean!
  
  # Profile
  updateProfile(input: UpdateProfileInput!): User!
  revokeSession(sessionId: ID!): Boolean!
  
  # Todos
  createTodo(input: CreateTodoInput!): Todo!
  updateTodo(id: ID!, input: UpdateTodoInput!): Todo!
  deleteTodo(id: ID!): Boolean!
  
  # Admin (sysadmin only)
  adminDeleteTodo(id: ID!): Boolean!
  adminUpdateUser(id: ID!, input: AdminUpdateUserInput!): User!
  adminDeleteUser(id: ID!): Boolean!
  adminRevokeSession(sessionId: ID!): Boolean!
}
```

#### Types
```graphql
type User {
  id: ID!
  email: String!
  fullName: String!
  role: Role!
  emailVerified: Boolean!
  createdAt: DateTime!
}

type Todo {
  id: ID!
  ownerId: ID!
  ownerEmail: String!
  description: String!
  dueDate: DateTime
  priority: Priority!
  createdAt: DateTime!
  updatedAt: DateTime!
}

type AuthPayload {
  accessToken: String!
  refreshToken: String!
  user: User!
}

enum Role {
  GUEST
  ADMIN
  SYSADMIN
}

enum Priority {
  LOW
  MEDIUM
  HIGH
}
```

---

## **6. Email Requirements**

### **6.1 Email Providers**

| Provider | Configuration | Notes |
|----------|---------------|-------|
| **SendGrid** | `SENDGRID_API_KEY` | Preferred for production |
| **SMTP** | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | Fallback option |

**Selection Logic:**
```
If SENDGRID_API_KEY is set → use SendGrid
Else if SMTP_HOST is set → use SMTP
Else → throw configuration error
```

### **6.2 Required Email Templates**

| Template | Trigger | Variables | Notes |
|----------|---------|-----------|-------|
| `verification-email` | User registration | `fullName`, `verificationLink`, `expiresIn` | 24-hour link expiry |
| `password-reset` | Password reset request | `fullName`, `resetLink`, `expiresIn` | 1-hour link expiry |
| `password-changed` | Password reset completed | `fullName`, `changedAt` | Notification only, no action |
| `welcome` | Email verified | `fullName` | Optional welcome message |

**Template Engine:**
- Handlebars (`.hbs` files)
- Stored in `/src/modules/email/templates/`
- Support for HTML + plain text fallback

**Email Configuration:**
```env
EMAIL_FROM=noreply@example.com
EMAIL_FROM_NAME=MyApp
EMAIL_REPLY_TO=support@example.com
```

### **6.3 Rate Limiting for Email**

| Action | Limit | Notes |
|--------|-------|-------|
| Password reset request | 3 per hour per email | Prevents spam |
| Email verification resend | 5 per hour per email | Prevents spam |

---

## **7. Security Requirements**

### **7.1 Password Security**

✅ **Argon2id** for password hashing
✅ Strong password policy (min 8 chars, 3 character classes)
✅ Common password blacklist (top 1000)
✅ Cannot reuse last 3 passwords (stored in `password_history` table)

### **7.2 Token Security**

✅ **Refresh token rotation** on every use
✅ Refresh token stored as SHA-256 hash in database
✅ Automatic session invalidation on suspicious activity:
  - Token reuse detection (token used after rotation)
  - Session revoked, user notified via email
✅ Access token cannot be refreshed after expiry (must re-login)

### **7.3 Rate Limiting**

| Endpoint | Limit | Window | Notes |
|----------|-------|--------|-------|
| `POST /auth/login` | 5 attempts | 15 min | Per IP |
| `POST /auth/register` | 3 attempts | 1 hour | Per IP |
| `POST /auth/refresh` | 10 attempts | 15 min | Per refresh token |
| `POST /auth/request-password-reset` | 3 attempts | 1 hour | Per email |
| All other endpoints | 100 requests | 15 min | Per access token |

**Implementation:**
- Use `@nestjs/throttler` with Redis store (production) or memory (dev)
- Custom throttler guards for different endpoint categories

### **7.4 Content Security Policy (CSP)**

**Recommended Client-Side CSP** (Next.js should set this):
```
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'nonce-<generated>';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://bar.com;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
```

**API Response Headers** (via Helmet):
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### **7.5 Audit Logging**

**Required Events:**
- ✅ All authentication events (success/failure)
- ✅ Password resets (request + completion)
- ✅ Email verification
- ✅ Token refresh and rotation
- ✅ Admin/sysadmin actions (view all, delete, update)
- ✅ Session revocations
- ✅ Failed authorization attempts

**Log Storage:**
- Database table (`audit_logs`) for queryability
- Retention: 90 days in database, then archive to cold storage

---

## **8. CORS Configuration**

### **8.1 Environment-Specific CORS**

| Environment | Allowed Origins | Credentials |
|-------------|----------------|-------------|
| `development` | `*` | `false` |
| `test` | `http://localhost:3000` | `false` |
| `production` | Configurable via `CORS_ALLOWED_ORIGINS` env | `false` |

**Example Production Config:**
```env
CORS_ALLOWED_ORIGINS=https://app.example.com,https://www.example.com
```

### **8.2 CORS Headers**

```
Access-Control-Allow-Origin: <allowed-origin>
Access-Control-Allow-Methods: GET, POST, PATCH, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

**Important:**
- `credentials: 'omit'` on client fetch calls (no cookies)
- No `Access-Control-Allow-Credentials` header needed

---

## **9. Error Handling**

### **9.1 Standardized Error Response Format**

**REST & GraphQL:**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ],
    "timestamp": "2025-01-15T10:30:00Z",
    "path": "/auth/register",
    "requestId": "req_abc123"
  }
}
```

### **9.2 Error Codes**

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Input validation failed |
| `UNAUTHORIZED` | 401 | Invalid or missing authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Duplicate resource (e.g., email exists) |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Unexpected server error |
| `SERVICE_UNAVAILABLE` | 503 | Database or external service down |

### **9.3 GraphQL Error Extensions**

```json
{
  "errors": [
    {
      "message": "Unauthorized",
      "extensions": {
        "code": "UNAUTHORIZED",
        "timestamp": "2025-01-15T10:30:00Z",
        "requestId": "req_abc123"
      }
    }
  ]
}
```

---

## **10. Monitoring & Observability**

### **10.1 Health Checks**

**`GET /health`:**
```json
{
  "status": "ok",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

**`GET /readiness`:**
```json
{
  "status": "ok",
  "checks": {
    "database": "ok",
    "email": "ok"
  },
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### **10.2 Metrics Endpoint**

**`GET /metrics`** (Prometheus format):
```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",route="/todos",status="200"} 1523

# HELP http_request_duration_seconds HTTP request latency
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",route="/todos",le="0.1"} 1200
```

**Tracked Metrics:**
- Request count by endpoint, method, status
- Request duration histogram
- Active connections
- Database connection pool utilization
- Token refresh rate
- Authentication success/failure rate

### **10.3 Structured Logging**

**Format:** JSON
**Library:** `winston` or `pino`

**Log Levels:**
- `error`: Errors requiring attention
- `warn`: Potential issues
- `info`: General information (auth events, etc.)
- `debug`: Detailed debugging (dev only)

**Log Fields:**
```json
{
  "level": "info",
  "message": "User logged in successfully",
  "timestamp": "2025-01-15T10:30:00Z",
  "requestId": "req_abc123",
  "userId": "user_xyz",
  "ip": "192.168.1.1",
  "userAgent": "Mozilla/5.0...",
  "context": "AuthService"
}
```

**Log Destinations:**
- `development`: Console (pretty-printed)
- `test`: File (`logs/test.log`)
- `production`: stdout (captured by orchestration platform)

---

## **11. Testing Strategy**

### **11.1 Unit Tests**

**Coverage Target:** 80%+

**Focus Areas:**
- Service business logic (auth, todos)
- Validators and guards
- Utility functions (password hashing, token generation)

**Tools:**
- Jest
- Mock external dependencies (database, email)

### **11.2 Integration Tests**

**Coverage:**
- API endpoint behavior
- Database operations (use test database)
- Email sending (mock provider)
- RBAC enforcement

**Setup:**
- Test database (Docker PostgreSQL)
- Database reset between test suites
- Seed data fixtures

### **11.3 E2E Tests**

**Critical Flows:**
1. User registration → email verification → login
2. Password reset flow
3. Token refresh rotation
4. RBAC scenarios (guest vs admin vs sysadmin)
5. Todo CRUD with authorization checks

**Tools:**
- Supertest for HTTP requests
- Test database with cleanup

### **11.4 Security Tests**

- SQL injection attempts
- XSS payload injection
- Rate limiting validation
- Token reuse detection
- CORS policy enforcement

---

## **12. Deployment & CI/CD**

### **12.1 Environments**

| Environment | Purpose | Database | Deployment |
|-------------|---------|----------|------------|
| `development` | Local dev | `dev_db` | Auto (on commit to `main`) |
| `test` | Integration testing | `test_db` | Manual approval |
| `production` | Live system | `prod_db` | Manual approval |

### **12.2 Migration Strategy**

**Development:**
```bash
npm run migration:generate -- --name <name>
npm run migration:run
```
- Auto-deploy migrations on commit

**Test/Production:**
1. Generate migration in dev
2. Commit migration file
3. **Manual review** of migration SQL
4. **Manual approval** in CI/CD pipeline
5. Migration runs before app deployment
6. Rollback procedure available

**Rollback:**
```bash
npm run migration:revert
```
- Requires manual execution
- Down migration files must be tested

### **12.3 CI/CD Pipeline (GitHub Actions Example)**

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]

jobs:
  test:
    - Lint (ESLint)
    - Type check (tsc)
    - Unit tests
    - Integration tests
    - E2E tests
    - Security scan (npm audit)
  
  deploy-dev:
    if: github.ref == 'refs/heads/main'
    needs: test
    - Run migrations
    - Deploy to dev environment
  
  deploy-test:
    if: github.ref == 'refs/heads/main'
    needs: test
    - Manual approval required
    - Run migrations
    - Deploy to test environment
  
  deploy-prod:
    if: github.ref == 'refs/heads/release'
    needs: test
    - Manual approval required
    - Run migrations (with backup)
    - Deploy to production
    - Smoke tests
```

---

## **13. Environment Variables**

### **13.1 Required Variables (All Environments)**

```env
# App
NODE_ENV=development|test|production
PORT=3000
API_URL=http://localhost:3000

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/dbname
DATABASE_POOL_MIN=2
DATABASE_POOL_MAX=10

# JWT
JWT_ACCESS_SECRET=<random-256-bit-key>
JWT_REFRESH_SECRET=<random-256-bit-key>
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Email (choose one provider)
# Option 1: SendGrid
SENDGRID_API_KEY=<key>

# Option 2: SMTP
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=<user>
SMTP_PASS=<pass>
SMTP_SECURE=true

# Email Settings
EMAIL_FROM=noreply@example.com
EMAIL_FROM_NAME=MyApp
EMAIL_REPLY_TO=support@example.com

# CORS
CORS_ALLOWED_ORIGINS=https://app.example.com,https://www.example.com

# Rate Limiting (production only)
REDIS_URL=redis://localhost:6379
```

### **13.2 Optional Variables**

```env
# Dev Only
ENABLE_DEV_REVERSIBLE_PASSWORDS=true
DEV_REVERSIBLE_PASSWORD_KEY=<base64-encoded-32-byte-key>

# Monitoring
ENABLE_METRICS=true
METRICS_AUTH_TOKEN=<optional-bearer-token>

# Logging
LOG_LEVEL=info|debug|warn|error
```

---

## **14. Future Extensibility**

### **14.1 Planned Identity Providers**

**OAuth 2.0 / OIDC:**
- Google (`@nestjs/passport` + `passport-google-oauth20`)
- Microsoft (`passport-azure-ad`)
- GitHub

**SAML:**
- Corporate SSO via `passport-saml`

**Strategy:**
- Each provider maps user by email to existing user record
- If no user exists, create new user with `role=guest`
- Store provider info in `user_identities` table:
  ```sql
  CREATE TABLE user_identities (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'google', 'microsoft', etc.
    provider_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
  );
  ```

### **14.2 Module Extension Pattern**

To add new feature modules:
1. Create module in `/src/modules/<feature>`
2. Define Drizzle schema in `/src/database/schema/<feature>.ts`
3. Generate migration
4. Add RBAC rules in `/src/common/guards/roles.guard.ts`
5. Expose REST endpoints in `<feature>.controller.ts`
6. Expose GraphQL resolvers in `<feature>.resolver.ts`

---

## **Summary of Key Decisions**

✅ **localStorage for refresh tokens** (simpler than cookies for cross-domain)  
✅ **Argon2id** for password hashing  
✅ **Refresh token rotation** for security  
✅ **Drizzle ORM** with versioned migrations  
✅ **Dual API exposure** (REST + GraphQL)  
✅ **RBAC with ownership checks**  
✅ **Comprehensive audit logging**  
✅ **Rate limiting** on critical endpoints  
✅ **Email verification required** before login  
✅ **Dev-only reversible passwords** for debugging  
✅ **Prometheus metrics** for monitoring  
✅ **Structured JSON logging**  
✅ **Manual approval for test/prod deployments**  
