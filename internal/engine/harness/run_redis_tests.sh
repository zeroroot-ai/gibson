#!/bin/bash
#
# run_redis_tests.sh - Helper script to run Redis integration tests
#
# Usage:
#   ./run_redis_tests.sh              # Run all Redis integration tests
#   ./run_redis_tests.sh ToolRegistration  # Run specific test
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Redis is running
check_redis() {
    REDIS_URL="${REDIS_URL:-redis://localhost:6379}"

    echo -e "${YELLOW}Checking Redis connectivity at ${REDIS_URL}...${NC}"

    # Try to connect using Go
    if timeout 2 redis-cli -u "$REDIS_URL" ping > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Redis is available${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Redis is not available${NC}"
        echo -e "${YELLOW}Tests will be skipped unless Redis is running${NC}"
        echo ""
        echo -e "To start Redis using Docker:"
        echo -e "  ${GREEN}docker run -d --name redis-test -p 6379:6379 redis:7${NC}"
        echo ""
        return 1
    fi
}

# Run tests
run_tests() {
    local test_pattern="${1:-TestRedisIntegration}"

    echo -e "${YELLOW}Running tests: ${test_pattern}${NC}"
    echo ""

    # Run with verbose output
    go test -v -tags=integration -run "$test_pattern" ./

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo ""
        echo -e "${GREEN}✓ Tests passed${NC}"
    else
        echo ""
        echo -e "${RED}✗ Tests failed (exit code: $exit_code)${NC}"
    fi

    return $exit_code
}

# Main
main() {
    echo "=========================================="
    echo "  Gibson Redis Integration Tests"
    echo "=========================================="
    echo ""

    check_redis || true

    echo ""

    if [ -n "$1" ]; then
        run_tests "TestRedisIntegration_$1"
    else
        run_tests "TestRedisIntegration"
    fi
}

main "$@"
