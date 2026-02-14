#!/bin/bash

###############################################################################
# Open Agent Auth - E2E Test Runner Script
#
# This script orchestrates the complete E2E testing flow:
# 1. Restart all sample services
# 2. Wait for services to be ready
# 3. Run E2E tests
# 4. Display test results
#
# Usage: ./scripts/run-e2e-tests.sh [--debug] [--skip-build] [--test-class <class>]
#   --debug:       Start services in debug mode
#   --skip-build:  Skip Maven build step
#   --test-class:  Run specific test class (e.g., FullAuthorizationFlowE2ETest)
#
# Author: Open Agent Auth Team
###############################################################################

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_ROOT should point to the integration-tests module directory
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# PROJECT_ROOT_DIR should point to the project root directory
PROJECT_ROOT_DIR="$(cd "$PROJECT_ROOT/.." && pwd)"
# SAMPLES_SCRIPTS_DIR should point to open-agent-auth-samples/scripts
SAMPLES_SCRIPTS_DIR="$PROJECT_ROOT_DIR/open-agent-auth-samples/scripts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
DEBUG_MODE=false
SKIP_BUILD=false
TEST_CLASS="FullAuthorizationFlowE2ETest"
for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --test-class)
            TEST_CLASS="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}║     Open Agent Auth - E2E Test Runner                          ║${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Build arguments for restart script
# Note: sample-stop.sh only accepts --force, sample-start.sh accepts --debug, --skip-build, and --profile
RESTART_ARGS=()
if [ "$DEBUG_MODE" = true ]; then
    RESTART_ARGS+=("--debug")
fi
if [ "$SKIP_BUILD" = false ]; then
    # Only pass --skip-build if we want to skip the build step in sample-start.sh
    RESTART_ARGS+=("--skip-build")
fi
# Add mock-llm profile to enable Mock LLM for sample-agent during E2E tests
RESTART_ARGS+=("--profile")
RESTART_ARGS+=("mock-llm")

# Step 1: Build the entire project
echo -e "${BLUE}[Step 1/4] Building the entire project...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

cd "$PROJECT_ROOT/.."

# Set JAVA_HOME to JDK 17 if available
JAVA_HOME_17=$(/usr/libexec/java_home -v 17 2>/dev/null)
if [ -n "$JAVA_HOME_17" ] && [ -d "$JAVA_HOME_17" ]; then
    export JAVA_HOME="$JAVA_HOME_17"
    echo -e "${YELLOW}Using JDK 17: $JAVA_HOME${NC}"
fi

if [ "$SKIP_BUILD" = false ]; then
    if ! mvn clean install -DskipTests; then
        echo -e "${RED}[ERROR] Failed to build project${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}[SKIP] Build step skipped${NC}"
fi

echo ""
echo -e "${GREEN}✓ Project built successfully${NC}"
echo ""

# Step 2: Restart all services
echo -e "${BLUE}[Step 2/4] Restarting all sample services...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

if ! "$SAMPLES_SCRIPTS_DIR/sample-restart.sh" "${RESTART_ARGS[@]}"; then
    echo -e "${RED}[ERROR] Failed to restart services${NC}"
    echo -e "${YELLOW}Check logs above for detailed error information${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ All services restarted successfully${NC}"
echo ""

# Step 3: Verify all services are healthy
echo -e "${BLUE}[Step 3/4] Verifying service health...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

REQUIRED_SERVICES=(
    "8083:Agent User IDP"
    "8084:AS User IDP"
    "8085:Authorization Server"
    "8086:Resource Server"
)

ALL_HEALTHY=true
for service_info in "${REQUIRED_SERVICES[@]}"; do
    port=$(echo "$service_info" | cut -d: -f1)
    name=$(echo "$service_info" | cut -d: -f2)
    
    echo -ne "${YELLOW}  Checking $name (port $port)...${NC} "
    
    # Try to access JWKS endpoint
    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port/.well-known/jwks.json" 2>/dev/null | grep -q "200"; then
        echo -e "${GREEN}✓ Healthy${NC}"
    else
        echo -e "${RED}✗ Unhealthy${NC}"
        ALL_HEALTHY=false
    fi
done

echo ""

if [ "$ALL_HEALTHY" = false ]; then
    echo -e "${RED}[ERROR] Not all services are healthy${NC}"
    echo -e "${YELLOW}Check logs with: $SAMPLES_SCRIPTS_DIR/sample-logs.sh <service-name>${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All services are healthy${NC}"
echo ""

# Step 4: Run E2E tests
echo -e "${BLUE}[Step 4/4] Running E2E tests...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

# Display current service status
echo -e "${CYAN}Current Service Status:${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
"$SAMPLES_SCRIPTS_DIR/sample-status.sh" | grep -E "(Port|Status|PID)" || echo "  Unable to retrieve service status"
echo ""

cd "$PROJECT_ROOT"

# Set JAVA_HOME to JDK 17 if available
JAVA_HOME_17=$(/usr/libexec/java_home -v 17 2>/dev/null)
if [ -n "$JAVA_HOME_17" ] && [ -d "$JAVA_HOME_17" ]; then
    export JAVA_HOME="$JAVA_HOME_17"
    echo -e "${YELLOW}Using JDK 17: $JAVA_HOME${NC}"
    echo ""
fi

# Run the tests
TEST_START_TIME=$(date +%s)

echo -e "${YELLOW}Running: mvn test -Dtest=\"$TEST_CLASS\" -Dspring.profiles.active=e2e-test -DENABLE_INTEGRATION_TESTS=true${NC}"
echo ""

# Run tests and capture both stdout and stderr for summary
# Also tee to show real-time output
# Skip JaCoCo to avoid JDK 17 compatibility issues
# Enable integration tests by setting ENABLE_INTEGRATION_TESTS=true
TEST_RESULTS=$(mvn test -Dtest="$TEST_CLASS" -Dspring.profiles.active=e2e-test -DENABLE_INTEGRATION_TESTS=true -Djacoco.skip=true 2>&1 | tee /dev/stderr)
TEST_EXIT_CODE=$?

TEST_END_TIME=$(date +%s)
TEST_DURATION=$((TEST_END_TIME - TEST_START_TIME))

echo ""
echo ""

# Display test results
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Test Results Summary${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All E2E tests PASSED${NC}"
else
    echo -e "${RED}✗ E2E tests FAILED${NC}"
fi

echo ""
echo -e "${CYAN}Test Duration: ${TEST_DURATION}s${NC}"
echo ""

# Parse and display test statistics
echo -e "${CYAN}Test Statistics:${NC}"
echo "$TEST_RESULTS" | grep -E "(Tests run:|Failures:|Errors:|Skipped:)" | sed 's/^/  /' || echo "  Test statistics not available"

echo ""
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo ""

# Detailed test results
echo -e "${BLUE}Detailed Test Output:${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

# Print test results with proper formatting
if [ -n "$TEST_RESULTS" ]; then
    echo "$TEST_RESULTS"
else
    echo -e "${RED}No test output available${NC}"
fi

echo ""

# Final status
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}║     E2E Tests Completed Successfully! ✓                        ║${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  - Review test output above"
    echo -e "  - Check service logs: $SAMPLES_SCRIPTS_DIR/sample-logs.sh <service-name>"
    echo -e "  - Stop services when done: $SAMPLES_SCRIPTS_DIR/sample-stop.sh"
    echo ""
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                                                                ║${NC}"
    echo -e "${RED}║     E2E Tests Failed! ✗                                        ║${NC}"
    echo -e "${RED}║                                                                ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Troubleshooting:${NC}"
    echo -e "  - Review test output above for error details"
    echo -e "  - Check service logs: $SAMPLES_SCRIPTS_DIR/sample-logs.sh <service-name>"
    echo -e "  - Check service status: $SAMPLES_SCRIPTS_DIR/sample-status.sh"
    echo -e "  - Restart services: $SAMPLES_SCRIPTS_DIR/sample-restart.sh"
    echo ""
fi

exit $TEST_EXIT_CODE