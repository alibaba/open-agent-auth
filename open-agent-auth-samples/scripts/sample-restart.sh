#!/bin/bash

###############################################################################
# Open Agent Auth - Sample Services Restart Script
#
# This script restarts all sample services by stopping and starting them
# in the correct order.
#
# Usage: ./restart-all.sh [--debug] [--force] [--skip-build]
#   --debug:       Start services in debug mode
#   --force:       Force kill services during stop
#   --skip-build:  Skip Maven build step
#
# Author: Open Agent Auth Team
###############################################################################

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Open Agent Auth - Restarting Services${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Stop all services
echo -e "${YELLOW}[1/2] Stopping all services...${NC}"
echo ""

# Filter out --skip-build and --profile for stop script (stop doesn't need these)
STOP_ARGS=()
skip_next=false
for arg in "$@"; do
    if [ "$skip_next" = true ]; then
        skip_next=false
        continue
    fi
    if [ "$arg" = "--skip-build" ]; then
        continue
    fi
    if [ "$arg" = "--profile" ]; then
        skip_next=true
        continue
    fi
    STOP_ARGS+=("$arg")
done

"$SCRIPT_DIR/sample-stop.sh" "${STOP_ARGS[@]}"

echo ""
echo -e "${YELLOW}[2/2] Starting all services...${NC}"
echo ""

# Filter out --force for start script (start doesn't need force)
# Note: --profile is kept for start script to enable Mock LLM
START_ARGS=()
for arg in "$@"; do
    if [ "$arg" != "--force" ]; then
        START_ARGS+=("$arg")
    fi
done

# Start all services
"$SCRIPT_DIR/sample-start.sh" "${START_ARGS[@]}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Restart completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
