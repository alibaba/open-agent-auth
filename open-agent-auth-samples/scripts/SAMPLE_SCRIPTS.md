# Open Agent Auth - Operations Scripts Guide

This document provides usage instructions for the Open Agent Auth sample project operations scripts.

## 📋 Table of Contents

- [Scripts Overview](#scripts-overview)
- [Quick Start](#quick-start)
- [Detailed Instructions](#detailed-instructions)
- [Service Dependencies](#service-dependencies)
- [FAQ](#faq)

---

## 🚀 Scripts Overview

| Script | Function | Purpose |
|--------|----------|---------|
| `sample-start.sh` | Start all services | Start all 6 sample services in dependency order |
| `sample-stop.sh` | Stop all services | Gracefully stop all services |
| `sample-restart.sh` | Restart all services | Stop and restart all services |
| `sample-status.sh` | Check service status | View running status and health checks of all services |
| `sample-logs.sh` | View service logs | View and filter service logs |

---

## ⚡ Quick Start

### 1. First Time Start

```bash
# Grant script execution permissions
chmod +x scripts/*.sh

# Start all services (includes build)
./scripts/sample-start.sh
```

### 2. Check Status

```bash
# Check all service status
./scripts/sample-status.sh

# Check detailed status (includes PID, memory, runtime)
./scripts/sample-status.sh --verbose
```

### 3. View Logs

```bash
# View last 100 lines of all services
./scripts/sample-logs.sh all

# Real-time follow logs for a specific service
./scripts/sample-logs.sh sample-agent --follow

# View error logs
./scripts/sample-logs.sh sample-authorization-server --errors
```

### 4. Stop Services

```bash
# Gracefully stop all services
./scripts/sample-stop.sh

# Force stop (if graceful stop fails)
./scripts/sample-stop.sh --force
```

---

## 📖 Detailed Instructions

### sample-start.sh - Start All Services

Start all services in the correct dependency order with health checks.

**Usage:**
```bash
./scripts/sample-start.sh [options]
```

**Options:**
- `--debug` - Start services in debug mode (enables debug port)
- `--skip-build` - Skip Maven build step

**Examples:**
```bash
# Normal start
./scripts/sample-start.sh

# Start in debug mode
./scripts/sample-start.sh --debug

# Skip build (for already built projects)
./scripts/sample-start.sh --skip-build

# Debug mode + skip build
./scripts/sample-start.sh --debug --skip-build
```

**Debug Port Mapping:**
| Service | App Port | Debug Port |
|---------|----------|------------|
| sample-agent | 8081 | 505 |
| sample-agent-idp | 8082 | 505 |
| sample-agent-user-idp | 8083 | 505 |
| sample-as-user-idp | 8084 | 505 |
| sample-authorization-server | 8085 | 505 |
| sample-resource-server | 8086 | 505 |

### sample-stop.sh - Stop All Services

Gracefully stop all services in reverse order.

**Usage:**
```bash
./scripts/sample-stop.sh [options]
```

**Options:**
- `--force` - Force kill processes (if graceful stop fails)

**Examples:**
```bash
# Graceful stop
./scripts/sample-stop.sh

# Force stop
./scripts/sample-stop.sh --force
```

### sample-restart.sh - Restart All Services

Stop and restart all services.

**Usage:**
```bash
./scripts/sample-restart.sh [options]
```

**Options:**
- `--debug` - Start in debug mode
- `--force` - Force stop
- `--skip-build` - Skip build

**Examples:**
```bash
# Normal restart
./scripts/sample-restart.sh

# Debug mode restart
./scripts/sample-restart.sh --debug
```

### sample-status.sh - Check Service Status

Display running status, port usage, and health check results for all services.

**Usage:**
```bash
./scripts/sample-status.sh [options]
```

**Options:**
- `--verbose` - Show detailed information (PID, memory usage, runtime)

**Examples:**
```bash
# Concise status
./scripts/sample-status.sh

# Detailed status
./scripts/sample-status.sh --verbose
```

**Output Example:**
```
STATUS               SERVICE                    PORT         HEALTH
----------------------------------------------------------------------
RUNNING              Agent User IDP             Port: 8083   ✓ HEALTHY
RUNNING              Agent IDP                  Port: 8082   ✓ HEALTHY
RUNNING              AS User IDP                Port: 8084   ✓ HEALTHY
RUNNING              Authorization Server       Port: 8085   ✓ HEALTHY
RUNNING              Resource Server            Port: 8086   ✓ HEALTHY
RUNNING              Agent                      Port: 8081   ✓ HEALTHY

========================================
Total: 6 services | Running: 6 | Stopped: 0
========================================
```

### sample-logs.sh - View Service Logs

View and filter service logs.

**Usage:**
```bash
./scripts/sample-logs.sh <service-name> [options]
```

**Service Names:**
- `sample-agent`
- `sample-agent-idp`
- `sample-agent-user-idp`
- `sample-as-user-idp`
- `sample-authorization-server`
- `sample-resource-server`
- `all` (view all services)

**Options:**
- `--follow` - Real-time follow logs (similar to tail -f)
- `--lines N` - Show last N lines (default: 100)
- `--errors` - Show only error logs
- `--grep PATTERN` - Filter logs containing specific pattern

**Examples:**
```bash
# View last 100 lines of all services
./scripts/sample-logs.sh all

# Real-time follow Agent service logs
./scripts/sample-logs.sh sample-agent --follow

# View last 50 lines
./scripts/sample-logs.sh sample-agent-idp --lines 50

# View only error logs
./scripts/sample-logs.sh sample-authorization-server --errors

# Filter logs containing "token"
./scripts/sample-logs.sh sample-resource-server --grep token

# Combined usage: real-time follow error logs
./scripts/sample-logs.sh sample-agent --follow --errors
```

---

## 🔗 Service Dependencies

Service startup order (topological sort):

```
1. sample-agent-user-idp (8083)
   ↓
2. sample-agent-idp (8082) ────────────┐
   ↓                                   │
3. sample-as-user-idp (8084)           │
   ↓                                   │
4. sample-authorization-server (8085)  │
   ↓                                   │
5. sample-resource-server (8086) ──────┘
   ↓
6. sample-agent (8081)
```

**Dependency Description:**
- `sample-agent-user-idp` - No dependencies, starts independently
- `sample-agent-idp` - Depends on `sample-agent-user-idp` (for ID Token validation)
- `sample-as-user-idp` - No dependencies, starts independently
- `sample-authorization-server` - Depends on all IDP services
- `sample-resource-server` - Depends on `sample-agent-idp` and `sample-authorization-server`
- `sample-agent` - Depends on all other services

---

## 📁 Directory Structure

```
open-agent-auth/
└── open-agent-auth-samples/  # Sample services
    ├── scripts/              # Operations scripts directory
    │   ├── sample-start.sh   # Start script
    │   ├── sample-stop.sh    # Stop script
    │   ├── sample-restart.sh # Restart script
    │   ├── sample-status.sh  # Status check script
    │   ├── sample-logs.sh    # Log viewing script
    │   └── SAMPLE_SCRIPTS.md # This document
    ├── sample-agent/         # Agent service
    ├── sample-agent-idp/     # Agent IDP service
    ├── sample-agent-user-idp/ # Agent User IDP service
    ├── sample-as-user-idp/   # AS User IDP service
    ├── sample-authorization-server/ # Authorization Server service
    ├── sample-resource-server/      # Resource Server service
    ├── logs/                 # Logs directory (auto-created)
    │   ├── sample-agent.log
    │   ├── sample-agent-idp.log
    │   └── ...
    └── pids/                 # PID files directory (auto-created)
        ├── sample-agent.pid
        ├── sample-agent-idp.pid
        └── ...
```

---

## ❓ FAQ

### Q1: Port already in use during startup?

**A:** Check if other processes are using the ports or if previous processes didn't stop properly:

```bash
# Check port usage
lsof -i :8081
lsof -i :8082
# ...

# Stop all services
./sample-stop.sh --force
```

### Q2: What to do if service startup fails?

**A:** Check service logs for detailed error information:

```bash
# View specific service logs
./sample-logs.sh <service-name> --errors

# View error logs for all services
./sample-logs.sh all --errors
```

### Q3: How to debug services in IDEA?

**A:** Start services with `--debug` option, then configure remote debugging in IDEA:

1. Start services:
   ```bash
   ./scripts/sample-start.sh --debug
   ```

2. Configure Remote JVM Debug in IDEA:
   - Host: `localhost`
   - Port: Corresponding service debug port (see table above)

### Q4: How to start only some services?

**A:** Current scripts are designed to start all services. To start a single service manually:

```bash
cd open-agent-auth-samples/<service-name>
java -jar target/<service-name>-0.1.0-beta.1-SNAPSHOT.jar
```

### Q5: Where are the log files?

**A:** Log files are located in the `open-agent-auth-samples/logs/` folder:

```bash
ls -lh logs/
```

### Q6: How to clean up logs and PID files?

**A:** After stopping all services, you can manually clean up:

```bash
# Stop services
./scripts/sample-stop.sh

# Clean logs
rm -rf logs/*

# Clean PID files
rm -rf pids/*
```

---

## 🔧 Advanced Usage

### Custom JVM Parameters

Edit the `sample-start.sh` script and modify the `java_opts` variable:

```bash
# Find and modify in sample-start.sh
local java_opts="-Xmx512m -Xms256m"
# Change to
local java_opts="-Xmx1024m -Xms512m -XX:+UseG1GC"
```

### Modify Health Check Timeout

Edit the `max_attempts` variable in `sample-start.sh`:

```bash
local max_attempts=60  # Default: 60 attempts, 2 seconds each, total 120 seconds
```

### Add Custom Startup Parameters

If you need to add startup parameters for specific services, modify the `java_cmd` section in `sample-start.sh`.

---

## 📝 Notes

1. **First Time Use**: First startup will execute Maven build, which may take a few minutes
2. **Java Version**: Ensure Java 17 or higher is used
3. **Port Conflicts**: Ensure ports 8081-8086 are not occupied by other applications
4. **Debug Port**: Ensure port 505 is not occupied when using `--debug` mode
5. **Log Management**: Regularly clean up log files to avoid disk space issues
6. **Process Cleanup**: Use `--force` option to clean up residual processes after abnormal exits

---

## 🆘 Getting Help

If you encounter issues:

1. View service logs: `./scripts/sample-logs.sh <service-name>`
2. Check service status: `./scripts/sample-status.sh --verbose`
3. View project documentation: `README.md`
4. Submit Issue: [Project GitHub Issues Page]

---

**Happy coding!** 🎉
