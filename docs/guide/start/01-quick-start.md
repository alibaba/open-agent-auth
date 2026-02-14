# Open Agent Auth Quick Start Guide

This guide will help you experience the core features of Open Agent Auth in **5 minutes**.

## Goal

After completing this guide, you will:
- ✅ Understand the basic agent authorization flow
- ✅ Experience complete identity authentication and authorization mechanisms
- ✅ View audit trail records

---

## Prerequisites

### Required

- **Java 17+**
- **Maven 3.6+**
- **QwenCode** (optional, for deeper experience with real AI conversations)

### Check Your Environment

```bash
# Check Java version
java -version

# Check Maven version
mvn -version
```

If Maven is not installed, install it using one of the following methods:

**macOS (using Homebrew)**:
```bash
# Install Maven
brew install maven

# Verify installation
mvn -version
```

**Linux (using apt)**:
```bash
# Install Maven (Ubuntu/Debian)
sudo apt update
sudo apt install maven

# Verify installation
mvn -version
```

**Linux (using yum)**:
```bash
# Install Maven (CentOS/RHEL)
sudo yum install maven

# Verify installation
mvn -version
```

**Manual Installation (Any OS)**:
```bash
# Download Maven from https://maven.apache.org/download.cgi
# Extract to /opt/maven (or your preferred location)
tar -xzf apache-maven-3.9.9-bin.tar.gz
sudo mv apache-maven-3.9.9 /opt/maven

# Set environment variables (add to ~/.bashrc or ~/.zshrc)
export M2_HOME=/opt/maven
export PATH=$M2_HOME/bin:$PATH

# Reload configuration
source ~/.bashrc  # or source ~/.zshrc

# Verify installation
mvn -version
```

---

## 5-Minute Quick Experience

### Step 1: Clone and Build the Project (2 minutes)

```bash
# Clone the project
git clone https://github.com/alibaba/open-agent-auth.git
cd open-agent-auth

# Build the project (skip tests to speed up)
mvn clean package -DskipTests

# Enter the samples directory
cd open-agent-auth-samples
```

### Step 2: Start All Services (2 minutes)

The sample project provides two startup options:

#### Option 1: Using Mock LLM (Quick Start)

```bash
# Start all services with mock LLM
./scripts/sample-start.sh --profile mock-llm
```

#### Option 2: Using QwenCode (Deep Experience)

The sample project integrates [qwencode-sdk](https://github.com/QwenLM/qwen-code/blob/main/packages/sdk-java/qwencode/README.md), enabling direct integration with QwenCode for a deeper experience with real AI conversations.

### Install QwenCode

Follow the installation guide at: [QwenCode Documentation](https://qwenlm.github.io/qwen-code-docs/zh/users/overview)

### Restart with QwenCode

After installing QwenCode, restart the services:

```bash
# Stop all services
./scripts/sample-stop.sh

# Start all services with QwenCode integration
./scripts/sample-start.sh
```

Now, the Agent will use the real Qwen model for conversations, providing a deeper experience.

**Note:** Make sure QwenCode is properly installed and configured. If you encounter any issues, you can always fall back to Option 1 (Mock LLM) by using:

```bash
./scripts/sample-start.sh --profile mock-llm
```

Wait for all services to start (about 1-2 minutes). You should see output similar to:
```
# ✓ Agent User IDP is ready
# ✓ Agent IDP is ready
# ✓ AS User IDP is ready
# ✓ Authorization Server is ready
# ✓ Resource Server is ready
# ✓ Agent is ready
```

**Service Ports**:
- Agent: `http://localhost:8081`
- Agent IDP: `http://localhost:8082`
- Agent User IDP: `http://localhost:8083`
- AS User IDP: `http://localhost:8084`
- Authorization Server: `http://localhost:8085`
- Resource Server: `http://localhost:8086`

### Step 3: Access the Agent Interface (30 seconds)

Open your browser and navigate to:
```
http://localhost:8081
```

You will see the main Agent interface.

### Step 4: Experience the Agent Authorization Flow (1 minute)

#### 4.1 User Login

1. Click the "Login" button on the page
2. Log in with the default credentials:
    - **Username**: `alice`
    - **Password**: `password123`
3. After successful login, you will enter the Agent conversation interface

#### 4.2 Initiate a Request

Type in the dialog box:
```
I want to buy a smartphone
```

> **Tip**: The Mock LLM uses keyword-based matching. For available products and matching rules, see [Mock LLM Guide](./mock-llm-guide.md).

#### 4.3 Observe the Authorization Flow

The agent will automatically perform the following steps:

1. **Identity Authentication**
    - The agent verifies your identity
    - Creates a virtual workload
    - Obtains a workload token (WIT)

2. **Tool Call Preparation**
    - The agent analyzes the request and determines it needs to call the shopping tool
    - Displays Operation Policy:
      ```rego
      package agent
      allow {
        input.operationType == "search_products"
        input.resourceId == "shopping"
        # Additional context constraints
        input.context.keywords == "iPhone 15"
      }
      ```

3. **Authorization Confirmation**
    - The agent asks if you confirm executing this operation
    - Click the "Approve" button to confirm

4. **Execute Tool Call**
    - The agent uses the authorization token to call the shopping tool
    - The tool server performs five-layer verification:
        - ✓ Workload authentication
        - ✓ Request integrity verification
        - ✓ User authentication
        - ✓ Identity consistency verification
        - ✓ Policy evaluation

5. **Return Result**
    - The agent displays the purchase result
    - Generates an audit trail record

---

## Optional: Configure Qwen Code CLI

If you want to use real AI conversation functionality, you need to configure Qwen Code CLI.

### Install Qwen Code CLI

```bash
# Install using pip
pip install qwencode-cli

# Verify installation
qwencode --version
```

### Configure API Key

```bash
# Get API Key
# Visit https://tongyi.aliyun.com/ to register and get an API Key

# Set environment variable
export QWEN_API_KEY="your-api-key-here"

# Test configuration
qwencode chat "Hello, Qwen!"
```

### Restart Agent Service

```bash
# Stop all services
./scripts/sample-stop.sh

# Restart
./scripts/sample-start.sh
```

Now, the Agent will use the real Qwen model for conversations.

---

## Core Concepts

### What is Agent Authorization?

When AI agents perform operations on behalf of users, it needs to ensure:
1. **Operation Legitimacy**: The operation is indeed initiated by the user
2. **Identity Authenticity**: Both the agent and user identities are authentic
3. **Permission Reasonableness**: The agent has permission to perform the operation
4. **Traceability**: All operations can be audited and traced

### Five-Layer Verification Mechanism

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Layer 1:        │ →  │  Layer 2:        │ →  │  Layer 3:        │ →  │  Layer 4:        │ →  │  Layer 5:        │
│  Workload Auth   │    │  Request Integ   │    │  User Auth       │    │  Identity Cons   │    │  Policy Eval     │
│  Verify WIT sig  │    │  Verify WPT sig  │    │  Verify OA Token │    │  Verify binding  │    │  (OPA) Fine-grain│
└──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘    └──────────────────┘
```

---

## Common Commands

### Service Management

```bash
# Start all services
./scripts/sample-start.sh

# Stop all services
./scripts/sample-stop.sh

# Check service status
./scripts/sample-status.sh

# View service logs
./scripts/sample-logs.sh sample-agent
./scripts/sample-logs.sh all
```

### Skip Build

```bash
# If already built, skip the build step
./scripts/sample-start.sh --skip-build
```

---

## FAQ

### Q: What if service startup fails?

```bash
# Check if ports are occupied
lsof -i :8081
lsof -i :8082
# ... check other ports

# View service logs
./scripts/sample-logs.sh sample-agent

# Rebuild
cd ..
mvn clean package -DskipTests
cd open-agent-auth-samples
```

### Q: How to reset all services?

```bash
# Stop all services
./scripts/sample-stop.sh

# Clean up logs and process files
rm -rf logs/* pids/*

# Restart
./scripts/sample-start.sh
```

### Q: How to view test coverage?

```bash
# Run tests and generate coverage report
cd ..
mvn clean test jacoco:report

# View report
open open-agent-auth-core/target/site/jacoco/index.html
```

---

## Next Steps

- 📖 [Complete User Guide](00-user-guide.md) - Learn about all features in depth
- 🏗️ [Architecture Documents](../architecture/) - Understand system architecture design
- 💻 [Integration Guide](02-integration-guide.md) - Learn how to integrate into your own project
- 🔗 [API Documentation](../api/) - View API reference documentation

---

## Get Help

- **GitHub Issues**: [Report Issues](https://github.com/alibaba/open-agent-auth/issues)
- **GitHub Discussions**: [Technical Discussions](https://github.com/alibaba/open-agent-auth/discussions)
- **Email**: open-agent-auth@alibaba-inc.com

---

**Document Version**: 1.0.0  
**Last Updated**: 2026-02-03  
**Maintainer**: Open Agent Auth Team