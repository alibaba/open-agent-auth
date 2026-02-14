#!/bin/bash

###############################################################################
# Open Agent Auth - Sample Services Log Viewer Script
#
# This script provides convenient access to service logs with various options.
#
# Usage: ./logs.sh <service-name> [options]
#   service-name:  sample-agent | sample-agent-idp | sample-agent-user-idp |
#                  sample-as-user-idp | sample-authorization-server |
#                  sample-resource-server | all
#
# Options:
#   --follow:      Follow log output (tail -f)
#   --lines N:     Show last N lines (default: 100)
#   --errors:      Show only errors
#   --grep PATTERN: Filter logs by pattern
#
# Examples:
#   ./logs.sh sample-agent --follow
#   ./logs.sh all --lines 50
#   ./logs.sh sample-authorization-server --errors
#
# Author: Open Agent Auth Team
###############################################################################

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if service name is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: Service name is required${NC}"
    echo ""
    echo "Usage: $0 <service-name> [options]"
    echo ""
    echo "Available services:"
    echo "  - sample-agent"
    echo "  - sample-agent-idp"
    echo "  - sample-agent-user-idp"
    echo "  - sample-as-user-idp"
    echo "  - sample-authorization-server"
    echo "  - sample-resource-server"
    echo "  - all"
    echo ""
    echo "Options:"
    echo "  --follow:      Follow log output (tail -f)"
    echo "  --lines N:     Show last N lines (default: 100)"
    echo "  --errors:      Show only errors"
    echo "  --grep PATTERN: Filter logs by pattern"
    echo ""
    exit 1
fi

SERVICE_NAME=$1
shift

# Parse options
FOLLOW=false
LINES=100
ERRORS_ONLY=false
GREP_PATTERN=""

while [ $# -gt 0 ]; do
    case $1 in
        --follow)
            FOLLOW=true
            shift
            ;;
        --lines)
            LINES=$2
            shift 2
            ;;
        --errors)
            ERRORS_ONLY=true
            shift
            ;;
        --grep)
            GREP_PATTERN=$2
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Service names
get_service_display_name() {
    local service=$1
    case $service in
        all) echo "All Services" ;;
        sample-agent) echo "Agent" ;;
        sample-agent-idp) echo "Agent IDP" ;;
        sample-agent-user-idp) echo "Agent User IDP" ;;
        sample-as-user-idp) echo "AS User IDP" ;;
        sample-authorization-server) echo "Authorization Server" ;;
        sample-resource-server) echo "Resource Server" ;;
    esac
}

# Validate service name
if [ -z "$(get_service_display_name "$SERVICE_NAME")" ]; then
    echo -e "${RED}Error: Unknown service '$SERVICE_NAME'${NC}"
    echo ""
    echo "Available services: all, sample-agent, sample-agent-idp, sample-agent-user-idp, sample-as-user-idp, sample-authorization-server, sample-resource-server"
    exit 1
fi

# Function to view log for a single service
view_log() {
    local service=$1
    local log_file="$LOG_DIR/${service}.log"
    
    if [ ! -f "$log_file" ]; then
        echo -e "${YELLOW}[SKIP] $service - Log file not found${NC}"
        return
    fi
    
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  $(get_service_display_name "$service")${NC}"
    echo -e "${CYAN}  Log: $log_file${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    # Build tail command
    local cmd="tail -n $LINES"
    
    if [ "$ERRORS_ONLY" = true ]; then
        cmd="$cmd | grep -i --color=always 'error\|exception\|failed'"
    fi
    
    if [ -n "$GREP_PATTERN" ]; then
        cmd="$cmd | grep --color=always -i '$GREP_PATTERN'"
    fi
    
    if [ "$FOLLOW" = true ]; then
        local follow_cmd="tail -f"
        if [ "$ERRORS_ONLY" = true ]; then
            follow_cmd="tail -f | grep --line-buffered -i --color=always 'error\|exception\|failed'"
        fi
        if [ -n "$GREP_PATTERN" ]; then
            follow_cmd="tail -f | grep --line-buffered --color=always -i '$GREP_PATTERN'"
        fi
        echo -e "${YELLOW}Following logs (Ctrl+C to exit)...${NC}"
        eval "$follow_cmd \"$log_file\""
    else
        eval "$cmd \"$log_file\""
    fi
    
    echo ""
}

# View logs
if [ "$SERVICE_NAME" = "all" ]; then
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Viewing logs for all services${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    
    for service in sample-agent-user-idp sample-agent-idp sample-as-user-idp sample-authorization-server sample-resource-server sample-agent; do
        view_log "$service"
    done
else
    view_log "$SERVICE_NAME"
fi
