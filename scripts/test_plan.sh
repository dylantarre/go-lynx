#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
LOCAL_URL="http://localhost:8080"
PROD_URL="https://go.lynx.fm"
TEST_TOKEN="your_test_token_here"  # Replace with a valid test token

# Helper function for testing endpoints
test_endpoint() {
    local env=$1
    local name=$2
    local url=$3
    local method=${4:-GET}
    local expected_status=${5:-200}
    local auth_header=${6:-""}
    
    echo -e "${YELLOW}Testing $env: $name${NC}"
    
    local headers=""
    if [ ! -z "$auth_header" ]; then
        headers="-H 'Authorization: Bearer $auth_header'"
    fi
    
    local response=$(curl -s -w "\n%{http_code}" $headers -X $method $url)
    local status=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed \$d)
    
    if [ "$status" -eq "$expected_status" ]; then
        echo -e "${GREEN}✓ Status $status - Pass${NC}"
        echo "Response: $body"
    else
        echo -e "${RED}✗ Status $status - Fail (Expected: $expected_status)${NC}"
        echo "Response: $body"
        if [ "$env" = "Production" ]; then
            echo -e "${RED}⚠️  Production test failed! Please investigate immediately!${NC}"
        fi
    fi
    echo "----------------------------------------"
}

run_environment_tests() {
    local env=$1
    local base_url=$2
    
    echo -e "\n${YELLOW}Running $env Tests${NC}"
    echo "========================================="
    
    # Health Check
    test_endpoint "$env" "Health Check" "$base_url/health"
    
    # Unauthenticated /me endpoint
    test_endpoint "$env" "Unauthenticated /me" "$base_url/me" "GET" 401
    
    # Authenticated /me endpoint
    test_endpoint "$env" "Authenticated /me" "$base_url/me" "GET" 200 "$TEST_TOKEN"
    
    # List tracks (authenticated)
    test_endpoint "$env" "List Tracks" "$base_url/tracks" "GET" 200 "$TEST_TOKEN"
    
    # Invalid token test
    test_endpoint "$env" "Invalid Token" "$base_url/me" "GET" 401 "invalid.token.here"
}

# Pre-deployment checks
echo -e "${YELLOW}Running Pre-deployment Checks${NC}"
echo "========================================="

# Check if required environment variables are set
if [ -z "$SUPABASE_JWT_SECRET" ]; then
    echo -e "${RED}Error: SUPABASE_JWT_SECRET is not set${NC}"
    exit 1
fi

if [ -z "$MUSIC_DIR" ]; then
    echo -e "${RED}Error: MUSIC_DIR is not set${NC}"
    exit 1
fi

# Build the application
echo "Building application..."
if ! go build -o lynx ./cmd/server; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
echo -e "${GREEN}Build successful${NC}"

# Run local tests if specified
if [ "$1" != "--prod-only" ]; then
    # Start the server in background
    ./lynx &
    SERVER_PID=$!
    
    # Wait for server to start
    echo "Waiting for server to start..."
    sleep 3
    
    # Run local tests
    run_environment_tests "Local" "$LOCAL_URL"
    
    # Kill the server
    kill $SERVER_PID
fi

# Run production tests if specified
if [ "$1" != "--local-only" ]; then
    run_environment_tests "Production" "$PROD_URL"
fi

echo -e "\n${GREEN}Test plan completed!${NC}" 