#!/bin/bash

###############################################################################
# Open Agent Auth - E2E Environment Diagnostic Script
#
# This script checks if the environment is ready for E2E testing
#
# Usage: ./scripts/diagnose-e2e-env.sh
#
# Author: Open Agent Auth Team
###############################################################################

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}║     E2E Environment Diagnostic Tool                            ║${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check 1: Java version
echo -e "${BLUE}[Check 1/6] Java Version${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
echo -e "  Java version: ${JAVA_VERSION}"

if [[ "$JAVA_VERSION" == "17"* ]] || [[ "$JAVA_VERSION" == "1.8"* ]]; then
    echo -e "  ${GREEN}✓ Java version is compatible${NC}"
else
    echo -e "  ${YELLOW}⚠ Java version may not be compatible (recommended: 17 or 8)${NC}"
fi
echo ""

# Check 2: Maven
echo -e "${BLUE}[Check 2/6] Maven Installation${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

if command -v mvn &> /dev/null; then
    MVN_VERSION=$(mvn -version | head -n 1)
    echo -e "  ${GREEN}✓ Maven is installed${NC}"
    echo -e "  $MVN_VERSION"
else
    echo -e "  ${RED}✗ Maven is not installed${NC}"
fi
echo ""

# Check 3: Required services
echo -e "${BLUE}[Check 3/6] Required Services${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

REQUIRED_SERVICES=(
    "8081:Agent"
    "8082:Agent IDP"
    "8083:Agent User IDP"
    "8084:AS User IDP"
    "8085:Authorization Server"
    "8086:Resource Server"
)

ALL_SERVICES_RUNNING=true
for service_info in "${REQUIRED_SERVICES[@]}"; do
    port=$(echo "$service_info" | cut -d: -f1)
    name=$(echo "$service_info" | cut -d: -f2)
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ $name (port $port) - Running${NC}"
    else
        echo -e "  ${RED}✗ $name (port $port) - Not running${NC}"
        ALL_SERVICES_RUNNING=false
    fi
done

if [ "$ALL_SERVICES_RUNNING" = true ]; then
    echo ""
    echo -e "  ${GREEN}✓ All services are running${NC}"
else
    echo ""
    echo -e "  ${RED}✗ Some services are not running${NC}"
    echo -e "  ${YELLOW}  Run: ./scripts/sample-start.sh${NC}"
fi
echo ""

# Check 4: Service health endpoints
echo -e "${BLUE}[Check 4/6] Service Health Endpoints${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

E2E_SERVICES=(
    "8083:Agent User IDP"
    "8084:AS User IDP"
    "8085:Authorization Server"
    "8086:Resource Server"
)

ALL_SERVICES_HEALTHY=true
for service_info in "${E2E_SERVICES[@]}"; do
    port=$(echo "$service_info" | cut -d: -f1)
    name=$(echo "$service_info" | cut -d: -f2)
    
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port/.well-known/jwks.json" 2>/dev/null || echo "000")
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "  ${GREEN}✓ $name JWKS endpoint is accessible${NC}"
    else
        echo -e "  ${RED}✗ $name JWKS endpoint returned HTTP $HTTP_CODE${NC}"
        ALL_SERVICES_HEALTHY=false
    fi
done

if [ "$ALL_SERVICES_HEALTHY" = true ]; then
    echo ""
    echo -e "  ${GREEN}✓ All service health endpoints are accessible${NC}"
else
    echo ""
    echo -e "  ${RED}✗ Some service health endpoints are not accessible${NC}"
fi
echo ""

# Check 5: Test files
echo -e "${BLUE}[Check 5/6] Test Files${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

TEST_CLASS="$PROJECT_ROOT/src/test/java/com/alibaba/openagentauth/integration/e2e/FullAuthorizationFlowE2ETest.java"
TEST_CONFIG="$PROJECT_ROOT/src/test/resources/application-e2e-test.yml"

if [ -f "$TEST_CLASS" ]; then
    echo -e "  ${GREEN}✓ E2E test class exists${NC}"
else
    echo -e "  ${RED}✗ E2E test class not found${NC}"
fi

if [ -f "$TEST_CONFIG" ]; then
    echo -e "  ${GREEN}✓ E2E test configuration exists${NC}"
else
    echo -e "  ${RED}✗ E2E test configuration not found${NC}"
fi
echo ""

# Check 6: Chrome browser (for Selenium tests)
echo -e "${BLUE}[Check 6/6] Chrome Browser${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

if command -v google-chrome &> /dev/null; then
    CHROME_VERSION=$(google-chrome --version)
    echo -e "  ${GREEN}✓ Chrome browser is installed${NC}"
    echo -e "  $CHROME_VERSION"
elif command -v chromium &> /dev/null; then
    CHROME_VERSION=$(chromium --version)
    echo -e "  ${GREEN}✓ Chromium browser is installed${NC}"
    echo -e "  $CHROME_VERSION"
elif [ -d "/Applications/Google Chrome.app" ]; then
    echo -e "  ${GREEN}✓ Chrome browser is installed (macOS)${NC}"
else
    echo -e "  ${YELLOW}⚠ Chrome browser not found (required for Selenium tests)${NC}"
fi
echo ""

# Summary
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Diagnostic Summary${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$ALL_SERVICES_RUNNING" = true ] && [ "$ALL_SERVICES_HEALTHY" = true ]; then
    echo -e "${GREEN}✓ Environment is ready for E2E testing${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  Run E2E tests: ./scripts/run-e2e-tests.sh"
else
    echo -e "${RED}✗ Environment is not ready for E2E testing${NC}"
    echo ""
    echo -e "${CYAN}Recommended Actions:${NC}"
    
    if [ "$ALL_SERVICES_RUNNING" = false ]; then
        echo -e "  1. Start all services: ./scripts/sample-start.sh"
    fi
    
    if [ "$ALL_SERVICES_HEALTHY" = false ]; then
        echo -e "  2. Check service logs: ./scripts/sample-logs.sh <service-name>"
        echo -e "  3. Restart services: ./scripts/sample-restart.sh"
    fi
    
    echo -e "  4. Run diagnostics again: ./scripts/diagnose-e2e-env.sh"
fi

echo ""