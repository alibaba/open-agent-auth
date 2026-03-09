#!/bin/bash

###############################################################################
# Open Agent Auth - Protocol Conformance Test Runner Script
#
# This script orchestrates the protocol conformance testing flow:
# 1. Build the project (optional)
# 2. Restart all sample services
# 3. Wait for services to be ready
# 4. Run protocol conformance tests
# 5. Display test results
#
# Usage: ./scripts/run-conformance-tests.sh [--debug] [--skip-build] [--skip-services] [--test-class <class>]
#   --debug:          Start services in debug mode
#   --skip-build:     Skip Maven build step
#   --skip-services:  Skip service restart (use when services are already running)
#   --test-class:     Run specific conformance test class
#
# Author: Open Agent Auth Team
###############################################################################

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT_DIR="$(cd "$PROJECT_ROOT/.." && pwd)"
SAMPLES_SCRIPTS_DIR="$PROJECT_ROOT_DIR/open-agent-auth-samples/scripts"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default conformance test classes
DEFAULT_TEST_CLASSES="OidcDiscoveryConformanceTest,OAuth2TokenEndpointConformanceTest,OAuth2ParConformanceTest,OAuth2DcrConformanceTest,JwksEndpointConformanceTest,OidcIdTokenConformanceTest,WimseWorkloadCredsConformanceTest,OAuth2TokenExchangeConformanceTest,ProtocolInteroperabilityConformanceTest"

# Parse arguments
DEBUG_MODE=false
SKIP_BUILD=false
SKIP_SERVICES=false
TEST_CLASS="$DEFAULT_TEST_CLASSES"
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --skip-services)
            SKIP_SERVICES=true
            shift
            ;;
        --test-class)
            TEST_CLASS="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo ""
            echo "Usage: $0 [--debug] [--skip-build] [--skip-services] [--test-class <class>]"
            exit 1
            ;;
    esac
done

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}║     Open Agent Auth - Protocol Conformance Test Runner          ║${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${MAGENTA}Protocols under test:${NC}"
echo -e "  • OAuth 2.0 Token Endpoint (RFC 6749 §5)"
echo -e "  • OAuth 2.0 Token Exchange (RFC 8693)"
echo -e "  • OAuth 2.0 DCR (RFC 7591)"
echo -e "  • OAuth 2.0 PAR (RFC 9126)"
echo -e "  • OIDC Discovery (OpenID Connect Discovery 1.0)"
echo -e "  • OIDC ID Token (OpenID Connect Core 1.0 §2)"
echo -e "  • JWKS Endpoint (RFC 7517)"
echo -e "  • WIMSE WIT/WPT (draft-ietf-wimse-workload-creds)"
echo -e "  • Cross-Protocol Interoperability (DCR→PAR→Token, OIDC→JWKS, WIT→TokenExchange)"
echo ""

# Build arguments for restart script
RESTART_ARGS=()
if [ "$DEBUG_MODE" = true ]; then
    RESTART_ARGS+=("--debug")
fi
if [ "$SKIP_BUILD" = true ]; then
    RESTART_ARGS+=("--skip-build")
fi
RESTART_ARGS+=("--profile")
RESTART_ARGS+=("mock-llm")

# Determine total steps based on whether services are skipped
if [ "$SKIP_SERVICES" = true ]; then
    TOTAL_STEPS=3
    STEP_OFFSET=0
else
    TOTAL_STEPS=5
    STEP_OFFSET=0
fi

CURRENT_STEP=0

next_step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
}

# Step 1: Build the entire project
next_step
echo -e "${BLUE}[Step ${CURRENT_STEP}/${TOTAL_STEPS}] Building the entire project...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

cd "$PROJECT_ROOT_DIR"

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

if [ "$SKIP_SERVICES" = false ]; then
    # Step 2: Restart all services
    next_step
    echo -e "${BLUE}[Step ${CURRENT_STEP}/${TOTAL_STEPS}] Restarting all sample services...${NC}"
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
    next_step
    echo -e "${BLUE}[Step ${CURRENT_STEP}/${TOTAL_STEPS}] Verifying service health...${NC}"
    echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
    echo ""

    REQUIRED_SERVICES=(
        "8082:Agent IDP"
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
        echo -e "${YELLOW}Run diagnostic: $SCRIPT_DIR/diagnose-conformance-env.sh${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓ All services are healthy${NC}"
    echo ""
fi

# Step: Display protocol endpoints
next_step
echo -e "${BLUE}[Step ${CURRENT_STEP}/${TOTAL_STEPS}] Protocol endpoints under test...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${CYAN}Authorization Server (8085):${NC}"
echo -e "    • Discovery:  http://localhost:8085/.well-known/openid-configuration"
echo -e "    • JWKS:       http://localhost:8085/.well-known/jwks.json"
echo -e "    • Token:      http://localhost:8085/oauth2/token"
echo -e "    • PAR:        http://localhost:8085/par"
echo -e "    • DCR:        http://localhost:8085/oauth2/register"
echo ""
echo -e "  ${CYAN}Identity Providers:${NC}"
echo -e "    • Agent IDP (8082):      http://localhost:8082/.well-known/jwks.json"
echo -e "    • Agent User IDP (8083): http://localhost:8083/.well-known/jwks.json"
echo -e "    • AS User IDP (8084):    http://localhost:8084/.well-known/jwks.json"
echo ""

# Step: Run conformance tests
next_step
echo -e "${BLUE}[Step ${CURRENT_STEP}/${TOTAL_STEPS}] Running protocol conformance tests...${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"
echo ""

cd "$PROJECT_ROOT"

TEST_START_TIME=$(date +%s)

echo -e "${YELLOW}Running: mvn test -P protocol-conformance -Dtest=\"$TEST_CLASS\" -DENABLE_INTEGRATION_TESTS=true${NC}"
echo ""

TEST_RESULTS=$(mvn test -P protocol-conformance -Dtest="$TEST_CLASS" -DENABLE_INTEGRATION_TESTS=true -Djacoco.skip=true 2>&1 | tee /dev/stderr)
TEST_EXIT_CODE=$?

TEST_END_TIME=$(date +%s)
TEST_DURATION=$((TEST_END_TIME - TEST_START_TIME))

echo ""
echo ""

# Display test results
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Protocol Conformance Test Results${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All protocol conformance tests PASSED${NC}"
else
    echo -e "${RED}✗ Protocol conformance tests FAILED${NC}"
fi

echo ""
echo -e "${CYAN}Test Duration: ${TEST_DURATION}s${NC}"
echo ""

# Parse and display test statistics
echo -e "${CYAN}Test Statistics:${NC}"
echo "$TEST_RESULTS" | grep -E "(Tests run:|Failures:|Errors:|Skipped:)" | sed 's/^/  /' || echo "  Test statistics not available"

echo ""
echo -e "${CYAN}Protocols Validated:${NC}"
echo -e "  • OAuth 2.0 Token Endpoint  (RFC 6749 §5)"
echo -e "  • OAuth 2.0 Token Exchange  (RFC 8693)"
echo -e "  • OAuth 2.0 DCR             (RFC 7591)"
echo -e "  • OAuth 2.0 PAR             (RFC 9126)"
echo -e "  • OIDC Discovery            (OpenID Connect Discovery 1.0)"
echo -e "  • OIDC ID Token             (OpenID Connect Core 1.0 §2)"
echo -e "  • JWKS Endpoint             (RFC 7517)"
echo -e "  • WIMSE WIT/WPT             (draft-ietf-wimse-workload-creds)"
echo -e "  • Cross-Protocol Interop    (DCR→PAR→Token, OIDC→JWKS, WIT→TokenExchange)"
echo ""

echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo ""

# Final status
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}║     Protocol Conformance Tests Completed Successfully! ✓       ║${NC}"
    echo -e "${GREEN}║                                                                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  - Review test output above for protocol compliance details"
    echo -e "  - Run E2E tests: $SCRIPT_DIR/run-e2e-tests.sh"
    echo -e "  - Stop services when done: $SAMPLES_SCRIPTS_DIR/sample-stop.sh"
    echo ""
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                                                                ║${NC}"
    echo -e "${RED}║     Protocol Conformance Tests Failed! ✗                       ║${NC}"
    echo -e "${RED}║                                                                ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Troubleshooting:${NC}"
    echo -e "  - Review test output above for specific protocol violations"
    echo -e "  - Run diagnostics: $SCRIPT_DIR/diagnose-conformance-env.sh"
    echo -e "  - Check service logs: $SAMPLES_SCRIPTS_DIR/sample-logs.sh <service-name>"
    echo -e "  - Restart services: $SAMPLES_SCRIPTS_DIR/sample-restart.sh"
    echo ""
fi

exit $TEST_EXIT_CODE
