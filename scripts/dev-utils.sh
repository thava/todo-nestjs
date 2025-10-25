#!/bin/bash

# Dev Utilities for Todo NestJS API
# Usage: source scripts/dev-utils.sh
# Then call functions like: register_user "test@example.com" "password123" "Test User"

# Configuration
API_URL="${API_URL:-http://localhost:3000}"
TOKEN_FILE="${TOKEN_FILE:-.dev-tokens.json}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper function to print colored output
print_success() {
  echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
  echo -e "${RED}✗ $1${NC}"
}

print_info() {
  echo -e "${BLUE}ℹ $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}⚠ $1${NC}"
}

# Helper function to pretty print JSON
print_json() {
  if command -v jq &> /dev/null; then
    echo "$1" | jq '.'
  else
    echo "$1"
  fi
}

# Save tokens to file
save_tokens() {
  local access_token="$1"
  local refresh_token="$2"
  cat > "$TOKEN_FILE" <<EOF
{
  "accessToken": "$access_token",
  "refreshToken": "$refresh_token",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
  print_success "Tokens saved to $TOKEN_FILE"
}

# Load tokens from file
load_tokens() {
  if [ ! -f "$TOKEN_FILE" ]; then
    print_error "Token file not found: $TOKEN_FILE"
    return 1
  fi

  if command -v jq &> /dev/null; then
    ACCESS_TOKEN=$(jq -r '.accessToken' "$TOKEN_FILE")
    REFRESH_TOKEN=$(jq -r '.refreshToken' "$TOKEN_FILE")
  else
    print_warning "jq not installed, using grep (less reliable)"
    ACCESS_TOKEN=$(grep -o '"accessToken": *"[^"]*"' "$TOKEN_FILE" | sed 's/"accessToken": *"\(.*\)"/\1/')
    REFRESH_TOKEN=$(grep -o '"refreshToken": *"[^"]*"' "$TOKEN_FILE" | sed 's/"refreshToken": *"\(.*\)"/\1/')
  fi

  if [ -z "$ACCESS_TOKEN" ] || [ -z "$REFRESH_TOKEN" ]; then
    print_error "Failed to load tokens from $TOKEN_FILE"
    return 1
  fi

  print_success "Tokens loaded from $TOKEN_FILE"
  return 0
}

# Delete token file
clear_tokens() {
  if [ -f "$TOKEN_FILE" ]; then
    rm "$TOKEN_FILE"
    print_success "Token file deleted: $TOKEN_FILE"
  else
    print_info "No token file to delete"
  fi
}

# Register a new user
# Usage: register_user "email@example.com" "password123" "Full Name"
register_user() {
  local email="$1"
  local password="$2"
  local full_name="$3"

  if [ -z "$email" ] || [ -z "$password" ] || [ -z "$full_name" ]; then
    print_error "Usage: register_user <email> <password> <full_name>"
    return 1
  fi

  print_info "Registering user: $email"

  local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"$password\",\"fullName\":\"$full_name\"}")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 201 ]; then
    print_success "User registered successfully"
    print_json "$body"

    # Extract and save tokens
    if command -v jq &> /dev/null; then
      local access_token=$(echo "$body" | jq -r '.accessToken')
      local refresh_token=$(echo "$body" | jq -r '.refreshToken')
      save_tokens "$access_token" "$refresh_token"
    else
      print_warning "jq not installed, tokens not saved automatically"
      echo "$body"
    fi
  else
    print_error "Registration failed (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Login
# Usage: login_user "email@example.com" "password123"
login_user() {
  local email="$1"
  local password="$2"

  if [ -z "$email" ] || [ -z "$password" ]; then
    print_error "Usage: login_user <email> <password>"
    return 1
  fi

  print_info "Logging in: $email"

  local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"$password\"}")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "Login successful"
    print_json "$body"

    # Extract and save tokens
    if command -v jq &> /dev/null; then
      local access_token=$(echo "$body" | jq -r '.accessToken')
      local refresh_token=$(echo "$body" | jq -r '.refreshToken')
      save_tokens "$access_token" "$refresh_token"
    else
      print_warning "jq not installed, tokens not saved automatically"
      echo "$body"
    fi
  else
    print_error "Login failed (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Refresh access token
# Usage: refresh_token
refresh_token() {
  if ! load_tokens; then
    return 1
  fi

  print_info "Refreshing access token"

  local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "Token refreshed successfully"
    print_json "$body"

    # Extract and save new tokens
    if command -v jq &> /dev/null; then
      local access_token=$(echo "$body" | jq -r '.accessToken')
      local refresh_token=$(echo "$body" | jq -r '.refreshToken')
      save_tokens "$access_token" "$refresh_token"
    fi
  else
    print_error "Token refresh failed (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Logout
# Usage: logout_user
logout_user() {
  if ! load_tokens; then
    return 1
  fi

  print_info "Logging out"

  local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/logout" \
    -H "Content-Type: application/json" \
    -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")

  local http_code=$(echo "$response" | tail -n1)

  if [ "$http_code" -eq 204 ]; then
    print_success "Logout successful"
    clear_tokens
  else
    print_error "Logout failed (HTTP $http_code)"
    return 1
  fi
}

# Get current user profile
# Usage: get_profile
get_profile() {
  if ! load_tokens; then
    return 1
  fi

  print_info "Fetching user profile"

  local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/me" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "Profile retrieved"
    print_json "$body"
  else
    print_error "Failed to get profile (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Create a todo
# Usage: create_todo "Buy groceries" "high" "2025-12-31"
create_todo() {
  local description="$1"
  local priority="${2:-medium}"
  local due_date="$3"

  if [ -z "$description" ]; then
    print_error "Usage: create_todo <description> [priority] [due_date]"
    return 1
  fi

  if ! load_tokens; then
    return 1
  fi

  print_info "Creating todo: $description"

  local json_data="{\"description\":\"$description\",\"priority\":\"$priority\""
  if [ -n "$due_date" ]; then
    json_data="$json_data,\"dueDate\":\"$due_date\""
  fi
  json_data="$json_data}"

  local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/todos" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d "$json_data")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 201 ]; then
    print_success "Todo created"
    print_json "$body"
  else
    print_error "Failed to create todo (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# List all todos
# Usage: list_todos
list_todos() {
  if ! load_tokens; then
    return 1
  fi

  print_info "Fetching todos"

  local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/todos" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "Todos retrieved"
    print_json "$body"
  else
    print_error "Failed to get todos (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Get a specific todo
# Usage: get_todo <todo_id>
get_todo() {
  local todo_id="$1"

  if [ -z "$todo_id" ]; then
    print_error "Usage: get_todo <todo_id>"
    return 1
  fi

  if ! load_tokens; then
    return 1
  fi

  print_info "Fetching todo: $todo_id"

  local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/todos/$todo_id" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "Todo retrieved"
    print_json "$body"
  else
    print_error "Failed to get todo (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Update a todo
# Usage: update_todo <todo_id> "New description" "low" "2025-12-31"
update_todo() {
  local todo_id="$1"
  local description="$2"
  local priority="$3"
  local due_date="$4"

  if [ -z "$todo_id" ]; then
    print_error "Usage: update_todo <todo_id> [description] [priority] [due_date]"
    return 1
  fi

  if ! load_tokens; then
    return 1
  fi

  print_info "Updating todo: $todo_id"

  local json_data="{"
  local has_field=false

  if [ -n "$description" ]; then
    json_data="$json_data\"description\":\"$description\""
    has_field=true
  fi

  if [ -n "$priority" ]; then
    [ "$has_field" = true ] && json_data="$json_data,"
    json_data="$json_data\"priority\":\"$priority\""
    has_field=true
  fi

  if [ -n "$due_date" ]; then
    [ "$has_field" = true ] && json_data="$json_data,"
    json_data="$json_data\"dueDate\":\"$due_date\""
  fi

  json_data="$json_data}"

  local response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/todos/$todo_id" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d "$json_data")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "Todo updated"
    print_json "$body"
  else
    print_error "Failed to update todo (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Delete a todo
# Usage: delete_todo <todo_id>
delete_todo() {
  local todo_id="$1"

  if [ -z "$todo_id" ]; then
    print_error "Usage: delete_todo <todo_id>"
    return 1
  fi

  if ! load_tokens; then
    return 1
  fi

  print_info "Deleting todo: $todo_id"

  local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/todos/$todo_id" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

  local http_code=$(echo "$response" | tail -n1)

  if [ "$http_code" -eq 204 ]; then
    print_success "Todo deleted"
  else
    local body=$(echo "$response" | sed '$d')
    print_error "Failed to delete todo (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Health check
# Usage: health_check
health_check() {
  print_info "Checking API health"

  local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/health")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "API is healthy"
    print_json "$body"
  else
    print_error "API health check failed (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Readiness check
# Usage: readiness_check
readiness_check() {
  print_info "Checking API readiness"

  local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/readiness")

  local http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | sed '$d')

  if [ "$http_code" -eq 200 ]; then
    print_success "API is ready"
    print_json "$body"
  else
    print_error "API readiness check failed (HTTP $http_code)"
    print_json "$body"
    return 1
  fi
}

# Show help
show_help() {
  cat <<EOF
${BLUE}Todo NestJS API - Dev Utilities${NC}

${GREEN}Configuration:${NC}
  API_URL=${API_URL}
  TOKEN_FILE=${TOKEN_FILE}

${GREEN}Authentication:${NC}
  register_user <email> <password> <full_name>  - Register a new user
  login_user <email> <password>                  - Login and save tokens
  refresh_token                                  - Refresh access token
  logout_user                                    - Logout and clear tokens
  get_profile                                    - Get current user profile

${GREEN}Todo Operations:${NC}
  create_todo <description> [priority] [due_date] - Create a new todo
  list_todos                                      - List all todos
  get_todo <todo_id>                              - Get a specific todo
  update_todo <todo_id> [desc] [priority] [date]  - Update a todo
  delete_todo <todo_id>                           - Delete a todo

${GREEN}Health:${NC}
  health_check                                    - Check API health
  readiness_check                                 - Check API readiness

${GREEN}Token Management:${NC}
  load_tokens                                     - Load tokens from file
  clear_tokens                                    - Delete token file

${GREEN}Examples:${NC}
  source scripts/dev-utils.sh
  register_user "test@example.com" "password123" "Test User"
  login_user "test@example.com" "password123"
  create_todo "Buy groceries" "high" "2025-12-31"
  list_todos
  delete_todo <todo_id>

${YELLOW}Note: jq is recommended for better JSON parsing${NC}
EOF
}

# Print help if sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  echo "This script should be sourced, not executed directly."
  echo "Usage: source scripts/dev-utils.sh"
  echo "Then run: show_help"
else
  print_success "Dev utilities loaded. Run 'show_help' for available commands."
fi
