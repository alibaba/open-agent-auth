#!/bin/bash

###############################################################################
# Open Agent Auth - Protocol Conformance Environment Diagnostic Script
#
# This script checks if the environment is ready for protocol conformance testing.
# It validates all required services and protocol endpoints are accessible.
#
# Usage: ./scripts/diagnose-conformance-env.sh
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
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}║     Protocol Conformance Environment Diagnostic Tool           ║${NC}"
echo -e "${CYAN}║                                                                ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL_CHECKS=7
ALL_PASSED=true

# Check 1: Java version
echo -e "${BLUE}[Check 1/${TOTAL_CHECKS}] Java Version${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
echo -e "  Java version: ${JAVA_VERSION}"

if [[ "$JAVA_VERSION" == "17"* ]] || [[ "$JAVA_VERSION" == "21"* ]]; then
    echo -e "  ${GREEN}✓ Java version is compatible${NC}"
else
    echo -e "  ${YELLOW}⚠ Java version may not be compatible (recommended: 17 or 21)${NC}"
fi
echo ""

# Check 2: Maven
echo -e "${BLUE}[Check 2/${TOTAL_CHECKS}] Maven Installation${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

if command -v mvn &> /dev/null; then
    MVN_VERSION=$(mvn -version 2>&1 | head -n 1)
    echo -e "  ${GREEN}✓ Maven is installed${NC}"
    echo -e "  $MVN_VERSION"
else
    echo -e "  ${RED}✗ Maven is not installed${NC}"
    ALL_PASSED=false
fi
echo ""

# Check 3: Required services (port listening)
echo -e "${BLUE}[Check 3/${TOTAL_CHECKS}] Required Services (Port Listening)${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

REQUIRED_SERVICES=(
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
        ALL_PASSED=false
    fi
done

if [ "$ALL_SERVICES_RUNNING" = true ]; then
    echo -e "  ${GREEN}✓ All services are running${NC}"
else
    echo -e "  ${RED}✗ Some services are not running${NC}"
fi
echo ""

# Check 4: JWKS endpoints (health check)
echo -e "${BLUE}[Check 4/${TOTAL_CHECKS}] JWKS Endpoints (Health Check)${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

JWKS_SERVICES=(
    "8082:Agent IDP"
    "8083:Agent User IDP"
    "8084:AS User IDP"
    "8085:Authorization Server"
)

ALL_JWKS_HEALTHY=true
for service_info in "${JWKS_SERVICES[@]}"; do
    port=$(echo "$service_info" | cut -d: -f1)
    name=$(echo "$service_info" | cut -d: -f2)

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port/.well-known/jwks.json" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "  ${GREEN}✓ $name JWKS endpoint (HTTP $HTTP_CODE)${NC}"
    else
        echo -e "  ${RED}✗ $name JWKS endpoint (HTTP $HTTP_CODE)${NC}"
        ALL_JWKS_HEALTHY=false
        ALL_PASSED=false
    fi
done

if [ "$ALL_JWKS_HEALTHY" = true ]; then
    echo -e "  ${GREEN}✓ All JWKS endpoints are accessible${NC}"
fi
echo ""

# Check 5: OAuth 2.0 protocol endpoints
echo -e "${BLUE}[Check 5/${TOTAL_CHECKS}] OAuth 2.0 Protocol Endpoints${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

OAUTH_ENDPOINTS=(
    "http://localhost:8085/.well-known/openid-configuration:OIDC Discovery"
    "http://localhost:8085/.well-known/jwks.json:JWKS"
)

ALL_OAUTH_HEALTHY=true
for endpoint_info in "${OAUTH_ENDPOINTS[@]}"; do
    url=$(echo "$endpoint_info" | cut -d: -f1-3)
    name=$(echo "$endpoint_info" | cut -d: -f4)

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "  ${GREEN}✓ $name ($url) - HTTP $HTTP_CODE${NC}"
    else
        echo -e "  ${RED}✗ $name ($url) - HTTP $HTTP_CODE${NC}"
        ALL_OAUTH_HEALTHY=false
        ALL_PASSED=false
    fi
done

# Token endpoint requires POST, so we check with a simple POST
TOKEN_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:8085/oauth2/token" 2>/dev/null || echo "000")
if [ "$TOKEN_CODE" = "400" ] || [ "$TOKEN_CODE" = "401" ]; then
    echo -e "  ${GREEN}✓ Token Endpoint (http://localhost:8085/oauth2/token) - HTTP $TOKEN_CODE (expected error for empty request)${NC}"
elif [ "$TOKEN_CODE" = "000" ]; then
    echo -e "  ${RED}✗ Token Endpoint (http://localhost:8085/oauth2/token) - Not reachable${NC}"
    ALL_OAUTH_HEALTHY=false
    ALL_PASSED=false
else
    echo -e "  ${YELLOW}⚠ Token Endpoint (http://localhost:8085/oauth2/token) - HTTP $TOKEN_CODE${NC}"
fi

# PAR endpoint requires POST
PAR_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:8085/par" 2>/dev/null || echo "000")
if [ "$PAR_CODE" = "400" ] || [ "$PAR_CODE" = "401" ]; then
    echo -e "  ${GREEN}✓ PAR Endpoint (http://localhost:8085/par) - HTTP $PAR_CODE (expected error for empty request)${NC}"
elif [ "$PAR_CODE" = "000" ]; then
    echo -e "  ${RED}✗ PAR Endpoint (http://localhost:8085/par) - Not reachable${NC}"
    ALL_OAUTH_HEALTHY=false
    ALL_PASSED=false
else
    echo -e "  ${YELLOW}⚠ PAR Endpoint (http://localhost:8085/par) - HTTP $PAR_CODE${NC}"
fi

if [ "$ALL_OAUTH_HEALTHY" = true ]; then
    echo -e "  ${GREEN}✓ All OAuth 2.0 protocol endpoints are accessible${NC}"
fi
echo ""

# Check 6: Conformance test files
echo -e "${BLUE}[Check 6/${TOTAL_CHECKS}] Conformance Test Files${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

CONFORMANCE_DIR="$PROJECT_ROOT/src/test/java/com/alibaba/openagentauth/integration/conformance"

EXPECTED_FILES=(
    "ProtocolConformanceTest.java"
    "ProtocolConformanceTestCondition.java"
    "OidcDiscoveryConformanceTest.java"
    "OAuth2TokenEndpointConformanceTest.java"
    "OAuth2ParConformanceTest.java"
    "OAuth2DcrConformanceTest.java"
    "JwksEndpointConformanceTest.java"
    "OidcIdTokenConformanceTest.java"
    "WimseWorkloadCredsConformanceTest.java"
)

ALL_FILES_EXIST=true
for file in "${EXPECTED_FILES[@]}"; do
    if [ -f "$CONFORMANCE_DIR/$file" ]; then
        echo -e "  ${GREEN}✓ $file${NC}"
    else
        echo -e "  ${RED}✗ $file - Missing${NC}"
        ALL_FILES_EXIST=false
        ALL_PASSED=false
    fi
done

if [ "$ALL_FILES_EXIST" = true ]; then
    echo -e "  ${GREEN}✓ All conformance test files exist${NC}"
fi
echo ""

# Check 7: Maven profile
echo -e "${BLUE}[Check 7/${TOTAL_CHECKS}] Maven Profile Configuration${NC}"
echo -e "${YELLOW}─────────────────────────────────────────────────────────────${NC}"

POM_FILE="$PROJECT_ROOT/pom.xml"
if grep -q "protocol-conformance" "$POM_FILE" 2>/dev/null; then
    echo -e "  ${GREEN}✓ protocol-conformance profile is configured in pom.xml${NC}"
else
    echo -e "  ${RED}✗ protocol-conformance profile is missing from pom.xml${NC}"
    ALL_PASSED=false
fi

if grep -q "ConformanceTest" "$POM_FILE" 2>/dev/null; then
    echo -e "  ${GREEN}✓ ConformanceTest pattern is included in surefire configuration${NC}"
else
    echo -e "  ${RED}✗ ConformanceTest pattern is missing from surefire configuration${NC}"
    ALL_PASSED=false
fi
echo ""

# Summary
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Diagnostic Summary${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$ALL_PASSED" = true ]; then
    echo -e "${GREEN}✓ Environment is ready for protocol conformance testing${NC}"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo -e "  Run conformance tests: ./scripts/run-conformance-tests.sh"
    echo -e "  Run with skip-services: ./scripts/run-conformance-tests.sh --skip-services --skip-build"
else
    echo -e "${RED}✗ Environment is not ready for protocol conformance testing${NC}"
    echo ""
    echo -e "${CYAN}Recommended Actions:${NC}"

    if [ "$ALL_SERVICES_RUNNING" = false ]; then
        echo -e "  1. Start all services: ../open-agent-auth-samples/scripts/sample-start.sh"
    fi

    if [ "$ALL_JWKS_HEALTHY" = false ] || [ "$ALL_OAUTH_HEALTHY" = false ]; then
        echo -e "  2. Check service logs: ../open-agent-auth-samples/scripts/sample-logs.sh <service-name>"
        echo -e "  3. Restart services: ../open-agent-auth-samples/scripts/sample-restart.sh"
    fi

    if [ "$ALL_FILES_EXIST" = false ]; then
        echo -e "  4. Ensure all conformance test files are present"
    fi

    echo -e "  5. Run diagnostics again: ./scripts/diagnose-conformance-env.sh"
fi

echo ""
