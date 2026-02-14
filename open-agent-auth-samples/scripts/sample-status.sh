#!/bin/bash

###############################################################################
# Open Agent Auth - Sample Services Status Check Script
#
# This script checks the status of all sample services including:
# - Process status (running/stopped)
# - Port availability
# - Health check endpoint response
#
# Usage: ./status.sh [--verbose]
#   --verbose: Show detailed information including PID and memory usage
#
# Author: Open Agent Auth Team
###############################################################################

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PID_DIR="$PROJECT_ROOT/pids"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
VERBOSE=false
for arg in "$@"; do
    case $arg in
        --verbose)
            VERBOSE=true
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $arg${NC}"
            exit 1
            ;;
    esac
done

# Service definitions
# Function to get service info by name
get_service_info() {
    local service=$1
    case $service in
        sample-agent-user-idp) echo "Agent User IDP:8083" ;;
        sample-agent-idp) echo "Agent IDP:8082" ;;
        sample-as-user-idp) echo "AS User IDP:8084" ;;
        sample-authorization-server) echo "Authorization Server:8085" ;;
        sample-resource-server) echo "Resource Server:8086" ;;
        sample-agent) echo "Agent:8081" ;;
    esac
}

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Open Agent Auth - Service Status${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to check service status
check_service() {
    local service=$1
    local service_info=$(get_service_info "$service")
    local display_name=$(echo "$service_info" | cut -d: -f1)
    local port=$(echo "$service_info" | cut -d: -f2)
    
    local pid_file="$PID_DIR/${service}.pid"
    local status="UNKNOWN"
    local status_color="${YELLOW}"
    local pid="N/A"
    local memory="N/A"
    local uptime="N/A"
    local health="UNKNOWN"
    
    # Check PID file
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        
        # Check if process is running
        if ps -p $pid > /dev/null 2>&1; then
            status="RUNNING"
            status_color="${GREEN}"
            
            # Get memory usage
            if [ "$VERBOSE" = true ]; then
                memory=$(ps -o rss= -p $pid | awk '{print $1/1024 " MB"}' 2>/dev/null || echo "N/A")
                uptime=$(ps -o etime= -p $pid | xargs 2>/dev/null || echo "N/A")
            fi
        else
            status="STOPPED (stale PID)"
            status_color="${RED}"
            pid="N/A"
        fi
    else
        # Check if port is in use (maybe started manually)
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            local running_pid=$(lsof -ti :$port -sTCP:LISTEN 2>/dev/null)
            status="RUNNING (external)"
            status_color="${YELLOW}"
            pid=$running_pid
        else
            status="STOPPED"
            status_color="${RED}"
        fi
    fi
    
    # Health check
    if [ "$status" = "RUNNING" ] || [ "$status" = "RUNNING (external)" ]; then
        if curl -s --max-time 3 "http://localhost:$port/actuator/health" >/dev/null 2>&1; then
            health="HEALTHY"
        elif curl -s --max-time 3 "http://localhost:$port/.well-known/jwks.json" >/dev/null 2>&1; then
            health="HEALTHY"
        elif curl -s --max-time 3 "http://localhost:$port/" >/dev/null 2>&1; then
            health="HEALTHY"
        else
            health="UNHEALTHY"
        fi
    fi
    
    # Print status
    printf "${status_color}%-20s${NC} " "$status"
    printf "%-25s " "$display_name"
    printf "Port: %-5s " "$port"
    
    if [ "$VERBOSE" = true ]; then
        printf "PID: %-8s " "$pid"
        printf "Mem: %-10s " "$memory"
        printf "Uptime: %-10s " "$uptime"
    fi
    
    if [ "$health" = "HEALTHY" ]; then
        printf "${GREEN}✓ $health${NC}"
    elif [ "$health" = "UNHEALTHY" ]; then
        printf "${RED}✗ $health${NC}"
    fi
    
    printf "\n"
}

# Print header
if [ "$VERBOSE" = true ]; then
    printf "%-20s %-25s %-12s %-10s %-12s %-12s %-12s\n" \
        "STATUS" "SERVICE" "PORT" "PID" "MEMORY" "UPTIME" "HEALTH"
    printf "%s\n" "$(printf '%.0s-' {1..100})"
else
    printf "%-20s %-25s %-12s %s\n" "STATUS" "SERVICE" "PORT" "HEALTH"
    printf "%s\n" "$(printf '%.0s-' {1..70})"
fi

# Check all services
for service in sample-agent-user-idp sample-agent-idp sample-as-user-idp sample-authorization-server sample-resource-server sample-agent; do
    check_service "$service"
done

echo ""
echo -e "${BLUE}========================================${NC}"

# Summary
running=0
stopped=0

for service in sample-agent-user-idp sample-agent-idp sample-as-user-idp sample-authorization-server sample-resource-server sample-agent; do
    pid_file="$PID_DIR/${service}.pid"
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        if ps -p $pid > /dev/null 2>&1; then
            running=$((running + 1))
        else
            stopped=$((stopped + 1))
        fi
    else
        stopped=$((stopped + 1))
    fi
done

echo -e "Total: $((running + stopped)) services | ${GREEN}Running: $running${NC} | ${RED}Stopped: $stopped${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
