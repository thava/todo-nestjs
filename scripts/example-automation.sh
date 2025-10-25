#!/bin/bash

# Example automation script demonstrating dev-utils.sh usage
# This script creates a test user, performs CRUD operations, and cleans up

set -e  # Exit on error

# Source the utilities
source "$(dirname "$0")/dev-utils.sh"

echo ""
echo "======================================"
echo "  Todo API - Example Automation"
echo "======================================"
echo ""

# Generate unique test email
TEST_EMAIL="test-$(date +%s)@example.com"
TEST_PASSWORD="Test123!@#"
TEST_NAME="Automation Test User"

# Step 1: Health Check
echo "Step 1: Health Check"
health_check
echo ""

# Step 2: Register User
echo "Step 2: Registering test user"
register_user "$TEST_EMAIL" "$TEST_PASSWORD" "$TEST_NAME"
echo ""

# Step 3: Get Profile
echo "Step 3: Getting user profile"
get_profile
echo ""

# Step 4: Create Multiple Todos
echo "Step 4: Creating todos"
create_todo "Write unit tests" "high" "2025-11-01"
sleep 0.5
create_todo "Code review" "medium" "2025-11-02"
sleep 0.5
create_todo "Update documentation" "low" "2025-11-05"
echo ""

# Step 5: List All Todos
echo "Step 5: Listing all todos"
TODOS_JSON=$(curl -s -X GET "$API_URL/todos" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

if command -v jq &> /dev/null; then
  echo "Found $(echo "$TODOS_JSON" | jq 'length') todos"

  # Get first todo ID for update/delete demo
  FIRST_TODO_ID=$(echo "$TODOS_JSON" | jq -r '.[0].id')

  echo ""
  echo "Step 6: Updating first todo"
  update_todo "$FIRST_TODO_ID" "Write unit tests (Updated)" "medium"

  echo ""
  echo "Step 7: Deleting first todo"
  delete_todo "$FIRST_TODO_ID"

  echo ""
  echo "Step 8: Final todo list"
  list_todos
else
  echo "$TODOS_JSON"
  print_warning "Install jq for better automation capabilities"
fi

echo ""
echo "Step 9: Refresh token demo"
sleep 1
refresh_token

echo ""
echo "Step 10: Logout and cleanup"
logout_user

echo ""
echo "======================================"
echo "  Automation completed successfully!"
echo "======================================"
echo ""
