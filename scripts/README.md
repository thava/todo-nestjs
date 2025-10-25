# Development Utilities

This directory contains utilities for interacting with the Todo NestJS API during development, testing, and automation.

## Available Tools

### 1. Bash Utilities (`dev-utils.sh`)

A collection of bash functions for shell scripting and automation.

#### Installation

No installation required. Just source the file:

```bash
source scripts/dev-utils.sh
```

#### Requirements

- `curl` (required)
- `jq` (optional but recommended for better JSON handling)

Install jq:
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Alpine
apk add jq
```

#### Usage

```bash
# Source the utilities
source scripts/dev-utils.sh

# Show help
show_help

# Register a new user
register_user "test@example.com" "password123" "Test User"

# Login
login_user "test@example.com" "password123"

# Create a todo
create_todo "Buy groceries" "high" "2025-12-31"

# List all todos
list_todos

# Update a todo
update_todo <todo_id> "Updated description" "low"

# Delete a todo
delete_todo <todo_id>

# Logout
logout_user
```

#### Configuration

Set environment variables to customize behavior:

```bash
export API_URL="http://localhost:3000"
export TOKEN_FILE=".dev-tokens.json"
```

### 2. TypeScript CLI (`utils.ts`)

A TypeScript-based CLI tool with better type safety and error handling.

#### Installation

Install tsx as a dev dependency:

```bash
pnpm add -D tsx
```

#### Usage

```bash
# Show help
npx tsx scripts/utils.ts help

# Register a new user
npx tsx scripts/utils.ts register test@example.com password123 "Test User"

# Login
npx tsx scripts/utils.ts login test@example.com password123

# Create a todo with options
npx tsx scripts/utils.ts todos:create "Buy groceries" --priority=high --due=2025-12-31

# List all todos
npx tsx scripts/utils.ts todos:list

# Get a specific todo
npx tsx scripts/utils.ts todos:get <todo_id>

# Update a todo
npx tsx scripts/utils.ts todos:update <todo_id> --description="Updated" --priority=low

# Delete a todo
npx tsx scripts/utils.ts todos:delete <todo_id>

# Check API health
npx tsx scripts/utils.ts health

# Logout
npx tsx scripts/utils.ts logout

# Clear saved tokens
npx tsx scripts/utils.ts tokens:clear
```

#### Configuration

Set environment variables:

```bash
export API_URL="http://localhost:3000"
```

The TypeScript CLI always saves tokens to `.dev-tokens.json` in the current directory.

## Token Storage

Both utilities store authentication tokens in a JSON file (`.dev-tokens.json` by default) in the current directory.

**Important**: Add `.dev-tokens.json` to your `.gitignore` to avoid committing sensitive tokens!

Example token file:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "timestamp": "2025-10-25T10:30:00Z"
}
```

## Examples

### Bash Script Automation

Create a test script:

```bash
#!/bin/bash

source scripts/dev-utils.sh

# Setup
TEST_EMAIL="test-$(date +%s)@example.com"
TEST_PASSWORD="Test123!@#"

# Register and login
register_user "$TEST_EMAIL" "$TEST_PASSWORD" "Test User"

# Create multiple todos
create_todo "Task 1" "high"
create_todo "Task 2" "medium"
create_todo "Task 3" "low"

# List all todos
list_todos

# Cleanup
logout_user
```

### TypeScript Integration

```typescript
import { execSync } from 'child_process';

// Execute CLI commands from TypeScript code
const result = execSync('npx tsx scripts/utils.ts todos:list', {
  encoding: 'utf-8',
});

console.log(result);
```

### CI/CD Pipeline

Use in GitHub Actions or other CI/CD:

```yaml
- name: Test API endpoints
  run: |
    source scripts/dev-utils.sh

    # Health check
    health_check

    # Register test user
    register_user "ci-test@example.com" "TestPass123!" "CI Test User"

    # Run CRUD tests
    create_todo "CI Test Todo" "high"
    list_todos

    # Cleanup
    logout_user
```

## Available Commands

### Authentication

| Bash | TypeScript | Description |
|------|-----------|-------------|
| `register_user <email> <password> <name>` | `register <email> <password> <name>` | Register new user |
| `login_user <email> <password>` | `login <email> <password>` | Login and save tokens |
| `refresh_token` | `refresh` | Refresh access token |
| `logout_user` | `logout` | Logout and clear tokens |
| `get_profile` | `profile` | Get current user profile |

### Todo Operations

| Bash | TypeScript | Description |
|------|-----------|-------------|
| `create_todo <desc> [priority] [due]` | `todos:create <desc> [--priority=X] [--due=Y]` | Create todo |
| `list_todos` | `todos:list` | List all todos |
| `get_todo <id>` | `todos:get <id>` | Get specific todo |
| `update_todo <id> [desc] [priority] [due]` | `todos:update <id> [--description=X] [--priority=Y]` | Update todo |
| `delete_todo <id>` | `todos:delete <id>` | Delete todo |

### Health Checks

| Bash | TypeScript | Description |
|------|-----------|-------------|
| `health_check` | `health` | Check API health |
| `readiness_check` | `readiness` | Check API readiness |

### Token Management

| Bash | TypeScript | Description |
|------|-----------|-------------|
| `load_tokens` | (automatic) | Load tokens from file |
| `clear_tokens` | `tokens:clear` | Delete token file |

## Tips

1. **Use jq for better JSON handling** in bash scripts:
   ```bash
   list_todos | jq '.[] | select(.priority == "high")'
   ```

2. **Chain commands** with bash:
   ```bash
   login_user "test@example.com" "password" && create_todo "Task" "high" && list_todos
   ```

3. **Set custom API URL** for different environments:
   ```bash
   API_URL=https://api.staging.example.com source scripts/dev-utils.sh
   ```

4. **Make bash script executable**:
   ```bash
   chmod +x scripts/dev-utils.sh
   ```

5. **Create aliases** for frequently used commands:
   ```bash
   alias todo-login='npx tsx scripts/utils.ts login'
   alias todo-list='npx tsx scripts/utils.ts todos:list'
   ```

## Troubleshooting

### "Token file not found"

You need to login first:
```bash
login_user "your@email.com" "password"
# or
npx tsx scripts/utils.ts login your@email.com password
```

### "Invalid or expired token"

Refresh your token or login again:
```bash
refresh_token
# or
npx tsx scripts/utils.ts refresh
```

### "Command not found: jq"

The bash utilities work without jq, but install it for better output:
```bash
brew install jq  # macOS
```

### API connection refused

Make sure the API is running:
```bash
pnpm run start:dev
```

Check the API URL:
```bash
echo $API_URL  # Should be http://localhost:3000
```

## Security Notes

⚠️ **Important Security Considerations**:

1. **Never commit `.dev-tokens.json`** to version control
2. **Don't use these utilities in production** - they're for development only
3. **Tokens are stored in plain text** - keep them secure
4. **Don't share token files** - they provide full API access
5. **Clear tokens when done**: `clear_tokens` or `tokens:clear`

## Contributing

When adding new utilities:

1. Update both bash and TypeScript versions for consistency
2. Add examples to this README
3. Include error handling
4. Add color-coded output for better UX
5. Update the help messages
