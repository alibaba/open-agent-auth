#!/bin/bash

###############################################################################
# Open Agent Auth - Sample Services Startup Script
#
# This script starts all sample services in the correct order based on their
# dependencies. It includes health checks and proper error handling.
#
# Usage: ./start-all.sh [--debug] [--skip-build]
#   --debug:       Start services in debug mode (with debug port 5005X)
#   --skip-build:  Skip Maven build step
#
# Author: Open Agent Auth Team
###############################################################################

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
PID_DIR="$PROJECT_ROOT/pids"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
DEBUG_MODE=false
SKIP_BUILD=false
SPRING_PROFILES=""
skip_next=false
for arg in "$@"; do
    if [ "$skip_next" = true ]; then
        SPRING_PROFILES="$arg"
        skip_next=false
        continue
    fi
    case $arg in
        --debug)
            DEBUG_MODE=true
            ;;
        --skip-build)
            SKIP_BUILD=true
            ;;
        --profile)
            skip_next=true
            ;;
        *)
            if [ "$skip_next" = false ]; then
                echo -e "${RED}Unknown option: $arg${NC}"
                exit 1
            fi
            ;;
    esac
done

# Service definitions with dependencies
# Format: "port:display_name:dependencies(comma-separated)"
get_service_info() {
    local service=$1
    local field=$2  # port, display_name, or dependencies
    case $service in
        sample-agent-user-idp)
            case $field in
                port) echo "8083" ;;
                display_name) echo "Agent User IDP" ;;
                dependencies) echo "" ;;
            esac
            ;;
        sample-agent-idp)
            case $field in
                port) echo "8082" ;;
                display_name) echo "Agent IDP" ;;
                dependencies) echo "sample-agent-user-idp" ;;
            esac
            ;;
        sample-as-user-idp)
            case $field in
                port) echo "8084" ;;
                display_name) echo "AS User IDP" ;;
                dependencies) echo "" ;;
            esac
            ;;
        sample-authorization-server)
            case $field in
                port) echo "8085" ;;
                display_name) echo "Authorization Server" ;;
                dependencies) echo "sample-agent-idp,sample-agent-user-idp,sample-as-user-idp" ;;
            esac
            ;;
        sample-resource-server)
            case $field in
                port) echo "8086" ;;
                display_name) echo "Resource Server" ;;
                dependencies) echo "sample-agent-idp,sample-authorization-server" ;;
            esac
            ;;
        sample-agent)
            case $field in
                port) echo "8081" ;;
                display_name) echo "Agent" ;;
                dependencies) echo "sample-agent-idp,sample-agent-user-idp,sample-authorization-server,sample-resource-server" ;;
            esac
            ;;
    esac
}

# Startup order (topological sort)
STARTUP_ORDER=(
    "sample-agent-user-idp"
    "sample-agent-idp"
    "sample-as-user-idp"
    "sample-authorization-server"
    "sample-resource-server"
    "sample-agent"
)

# Create necessary directories
mkdir -p "$LOG_DIR"
mkdir -p "$PID_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Open Agent Auth - Starting Services${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Build project if not skipped
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${YELLOW}[1/7] Building project...${NC}"
    # Build from parent directory and install to local repository
    cd "$PROJECT_ROOT/.."
    # Use JAVA_HOME with JDK 17 if available (cross-platform)
    if command -v /usr/libexec/java_home &>/dev/null; then
        # macOS
        JAVA_HOME_17=$(/usr/libexec/java_home -v 17 2>/dev/null || true)
        if [ -n "$JAVA_HOME_17" ] && [ -d "$JAVA_HOME_17" ]; then
            export JAVA_HOME="$JAVA_HOME_17"
            echo -e "${YELLOW}Using JDK 17: $JAVA_HOME${NC}"
        fi
    fi
    # Build with spring-boot:repackage to create executable JARs
    mvn clean package -DskipTests
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed!${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Build completed${NC}"
    echo ""
fi

# Function to check if port is in use
is_port_in_use() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Function to wait for service health
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=60
    local attempt=0
    
    echo -e "${YELLOW}  Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -lt $max_attempts ]; do
        if is_port_in_use $port; then
            # Port is in use, try to access HTTP endpoint to confirm service is ready
            if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port/" 2>/dev/null | grep -qE "^(200|404|302|301)$"; then
                echo -e "${GREEN}  ✓ $service_name is ready${NC}"
                return 0
            fi
        fi
        
        attempt=$((attempt + 1))
        echo -ne "${YELLOW}  ⏳ Attempt $attempt/$max_attempts...${NC}\r"
        sleep 2
    done
    
    echo -e "${RED}  ✗ $service_name failed to start within ${max_attempts}s${NC}"
    return 1
}

# Function to start a service
start_service() {
    local service=$1
    local port=$(get_service_info "$service" "port")
    local display_name=$(get_service_info "$service" "display_name")
    local dependencies=$(get_service_info "$service" "dependencies")
    
    local module_dir="$PROJECT_ROOT/$service"
    local log_file="$LOG_DIR/${service}.log"
    local pid_file="$PID_DIR/${service}.pid"
    
    # Check if service is already running
    if [ -f "$pid_file" ]; then
        local old_pid=$(cat "$pid_file")
        if ps -p $old_pid > /dev/null 2>&1; then
            echo -e "${YELLOW}[SKIP] $display_name is already running (PID: $old_pid)${NC}"
            return 0
        else
            rm -f "$pid_file"
        fi
    fi
    
    # Check if port is already in use
    if is_port_in_use $port; then
        echo -e "${RED}[ERROR] Port $port is already in use for $display_name${NC}"
        return 1
    fi
    
    echo -e "${BLUE}[START] $display_name (Port: $port)${NC}"
    
    # Build Java command
    local java_cmd="java"
    local java_opts="-Xmx512m -Xms256m"
    
    if [ "$DEBUG_MODE" = true ]; then
        local debug_port="${port:0:3}5"  # e.g., 8081 -> 505
        java_opts="$java_opts -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:$debug_port"
        echo -e "${YELLOW}  Debug mode enabled on port $debug_port${NC}"
    fi
    
    # Start the service
    cd "$module_dir"
    
    # Add Spring profile if specified
    local profile_args=""
    if [ -n "$SPRING_PROFILES" ]; then
        profile_args="--spring.profiles.active=$SPRING_PROFILES"
        echo -e "${YELLOW}  Using Spring profile: $SPRING_PROFILES${NC}"
    fi
    
    nohup $java_cmd $java_opts \
        -jar "target/${service}-0.1.0-beta.1-SNAPSHOT.jar" \
        $profile_args \
        > "$log_file" 2>&1 &
    
    local pid=$!
    echo $pid > "$pid_file"
    
    echo -e "${GREEN}  ✓ Started with PID: $pid${NC}"
    
    # Wait for service to be ready
    if ! wait_for_service "$display_name" "$port"; then
        echo -e "${RED}[ERROR] $display_name failed to start${NC}"
        echo -e "${RED}  Check logs: $log_file${NC}"
        return 1
    fi
    
    echo ""
    return 0
}

# Start services in order
STEP=2
for service in "${STARTUP_ORDER[@]}"; do
    display_name=$(get_service_info "$service" "display_name")
    
    echo -e "${BLUE}[$STEP/7] Starting $display_name...${NC}"
    STEP=$((STEP + 1))
    
    if ! start_service "$service"; then
        echo -e "${RED}Failed to start $display_name. Aborting...${NC}"
        exit 1
    fi
done

# Summary
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All services started successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Service URLs:${NC}"
echo -e "  - Agent:              http://localhost:8081"
echo -e "  - Agent IDP:          http://localhost:8082"
echo -e "  - Agent User IDP:     http://localhost:8083"
echo -e "  - AS User IDP:        http://localhost:8084"
echo -e "  - Authorization Server: http://localhost:8085"
echo -e "  - Resource Server:    http://localhost:8086"
echo ""
echo -e "${BLUE}Logs directory: $LOG_DIR${NC}"
echo -e "${BLUE}PIDs directory: $PID_DIR${NC}"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo -e "  - Stop all services:  ./scripts/sample-stop.sh"
echo -e "  - Check status:       ./scripts/sample-status.sh"
echo -e "  - View logs:          ./scripts/sample-logs.sh <service-name>"
echo ""
