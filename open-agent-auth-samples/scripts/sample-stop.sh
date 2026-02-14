#!/bin/bash

###############################################################################
# Open Agent Auth - Sample Services Stop Script
#
# This script stops all sample services gracefully in reverse order
# to minimize disruption.
#
# Usage: ./stop-all.sh [--force]
#   --force: Force kill services if graceful shutdown fails
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
FORCE_MODE=false
for arg in "$@"; do
    case $arg in
        --force)
            FORCE_MODE=true
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

# Shutdown order (reverse of startup order)
SHUTDOWN_ORDER=(
    "sample-agent"
    "sample-resource-server"
    "sample-authorization-server"
    "sample-as-user-idp"
    "sample-agent-idp"
    "sample-agent-user-idp"
)

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Open Agent Auth - Stopping Services${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to stop a service
stop_service() {
    local service=$1
    local service_info=$(get_service_info "$service")
    local display_name=$(echo "$service_info" | cut -d: -f1)
    local port=$(echo "$service_info" | cut -d: -f2)
    
    local pid_file="$PID_DIR/${service}.pid"
    local pid=""
    local pid_from_file=false
    
    # Try to get PID from file first
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        pid_from_file=true
    fi
    
    # Check if process from PID file is running
    if [ -n "$pid" ] && ps -p $pid > /dev/null 2>&1; then
        echo -e "${BLUE}[STOP] $display_name (PID: $pid, Port: $port)${NC}"
        
        # Try graceful shutdown first
        if [ "$FORCE_MODE" = false ]; then
            echo -e "${YELLOW}  Attempting graceful shutdown...${NC}"
            kill $pid 2>/dev/null || true
            
            # Wait for process to terminate
            local max_wait=30
            local wait_time=0
            while [ $wait_time -lt $max_wait ]; do
                if ! ps -p $pid > /dev/null 2>&1; then
                    echo -e "${GREEN}  ✓ $display_name stopped gracefully${NC}"
                    rm -f "$pid_file"
                    return 0
                fi
                sleep 1
                wait_time=$((wait_time + 1))
                echo -ne "${YELLOW}  ⏳ Waiting... ${wait_time}s/${max_wait}s${NC}\r"
            done
            echo ""
        fi
        
        # Force kill if graceful shutdown failed or force mode is enabled
        echo -e "${YELLOW}  Force killing process...${NC}"
        kill -9 $pid 2>/dev/null || true
        sleep 1
        
        # Verify process is dead
        if ps -p $pid > /dev/null 2>&1; then
            echo -e "${RED}  ✗ Failed to kill $display_name (PID: $pid)${NC}"
            return 1
        else
            echo -e "${GREEN}  ✓ $display_name stopped forcefully${NC}"
            rm -f "$pid_file"
            return 0
        fi
    else
        # PID file not found or process not running, try to find by port
        local port_pid=$(lsof -ti :$port -sTCP:LISTEN 2>/dev/null || true)
        
        if [ -n "$port_pid" ]; then
            echo -e "${YELLOW}[RECOVER] $display_name - PID file ${pid_from_file:+not found/}stale, found process on port $port (PID: $port_pid)${NC}"
            echo -e "${BLUE}[STOP] $display_name (PID: $port_pid, Port: $port)${NC}"
            
            # Force kill the process found by port
            echo -e "${YELLOW}  Force killing process...${NC}"
            kill -9 $port_pid 2>/dev/null || true
            sleep 1
            
            # Verify process is dead
            if ps -p $port_pid > /dev/null 2>&1; then
                echo -e "${RED}  ✗ Failed to kill $display_name (PID: $port_pid)${NC}"
                return 1
            else
                echo -e "${GREEN}  ✓ $display_name stopped forcefully${NC}"
                rm -f "$pid_file"
                return 0
            fi
        else
            # No process found on port either
            if [ "$pid_from_file" = true ]; then
                echo -e "${YELLOW}[CLEAN] $display_name - Process not running (stale PID file)${NC}"
                rm -f "$pid_file"
            else
                echo -e "${YELLOW}[SKIP] $display_name - No PID file and no process on port $port${NC}"
            fi
            return 0
        fi
    fi
}

# Stop services in reverse order
for service in "${SHUTDOWN_ORDER[@]}"; do
    if ! stop_service "$service"; then
        echo -e "${RED}Failed to stop $service${NC}"
    fi
    echo ""
done

# Additional cleanup: kill any remaining processes on our ports
echo -e "${YELLOW}[CLEANUP] Checking for orphaned processes...${NC}"
for port in 8081 8082 8083 8084 8085 8086; do
    pids=$(lsof -ti :$port 2>/dev/null || true)
    if [ -n "$pids" ]; then
        echo -e "${YELLOW}  Found orphaned process(es) on port $port: $pids${NC}"
        if [ "$FORCE_MODE" = true ]; then
            kill -9 $pids 2>/dev/null || true
            echo -e "${GREEN}  ✓ Killed orphaned processes on port $port${NC}"
        else
            echo -e "${YELLOW}  Use --force to kill orphaned processes${NC}"
        fi
    fi
done

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  All services stopped${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
