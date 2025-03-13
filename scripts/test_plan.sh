#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
LOCAL_URL="http://localhost:3500"
PROD_URL="https://go.lynx.fm"

# Helper function for testing endpoints
test_endpoint() {
    local env=$1
    local name=$2
    local url=$3
    local method=${4:-GET}
    local expected_status=${5:-200}
    local auth_header=${6:-""}
    
    echo -e "${YELLOW}Testing $env: $name${NC}"
    
    local curl_cmd="curl -s -w '%{http_code}' -o /tmp/response.txt"
    if [ ! -z "$auth_header" ]; then
        curl_cmd="$curl_cmd -H \"Authorization: Bearer $auth_header\""
    fi
    curl_cmd="$curl_cmd -X $method \"$url\""
    
    echo "Running: $curl_cmd"
    local status=$(eval $curl_cmd)
    local body=$(cat /tmp/response.txt)
    rm -f /tmp/response.txt
    
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
    
    if [ -z "$TEST_TOKEN" ]; then
        echo -e "${RED}Error: TEST_TOKEN environment variable is not set${NC}"
        echo "Please set a valid JWT token for testing:"
        echo "export TEST_TOKEN='your.jwt.token'"
        exit 1
    fi
    
    echo -e "\n${YELLOW}Running $env Tests${NC}"
    echo "========================================="
    
    # Health Check
    test_endpoint "$env" "Health Check" "$base_url/health"
    
    # Unauthenticated /me endpoint
    test_endpoint "$env" "Unauthenticated /me" "$base_url/me" "GET" 401
    
    # Authenticated /me endpoint
    test_endpoint "$env" "Authenticated /me" "$base_url/me" "GET" 200 "$TEST_TOKEN"
    
    # Random track endpoint
    test_endpoint "$env" "Random Track" "$base_url/random" "GET" 200
    
    # Invalid token test
    test_endpoint "$env" "Invalid Token" "$base_url/me" "GET" 401 "invalid.token.here"
}

# Pre-deployment checks
echo -e "${YELLOW}Running Pre-deployment Checks${NC}"
echo "========================================="

# Check if required environment variables are set
if [ -z "$SUPABASE_JWT_SECRET" ]; then
    echo -e "${RED}Error: SUPABASE_JWT_SECRET is not set${NC}"
    echo "Please set your Supabase JWT secret:"
    echo "export SUPABASE_JWT_SECRET='your_secret'"
    exit 1
fi

if [ -z "$MUSIC_DIR" ]; then
    echo -e "${RED}Error: MUSIC_DIR is not set${NC}"
    echo "Please set your music directory:"
    echo "export MUSIC_DIR='./music'"
    exit 1
fi

# Kill any existing server on port 3500
echo "Checking for existing server..."
lsof -ti:3500 | xargs kill -9 2>/dev/null || true

# Build the application
echo "Building application..."
if ! go build -o lynx ./cmd/server; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
echo -e "${GREEN}Build successful${NC}"

# Run local tests if specified
if [ "$1" != "--prod-only" ]; then
    # Set the port for the local server
    export PORT=3500
    
    # Start the server in background
    ./lynx &
    SERVER_PID=$!
    
    # Wait for server to start
    echo "Waiting for server to start..."
    sleep 3
    
    # Run local tests
    run_environment_tests "Local" "$LOCAL_URL"
    
    # Kill the server
    kill $SERVER_PID 2>/dev/null || true
fi

# Run production tests if specified
if [ "$1" != "--local-only" ]; then
    run_environment_tests "Production" "$PROD_URL"
fi

echo -e "\n${GREEN}Test plan completed!${NC}" 