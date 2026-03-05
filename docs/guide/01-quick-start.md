# Open Agent Auth User Guide & Quick Start

## 📖 Table of Contents

- [1. Overview](#1-overview)
- [2. Prerequisites](#2-prerequisites)
    - [2.1 System Requirements](#21-system-requirements)
    - [2.2 Installing Qwen Code CLI](#22-installing-qwen-code-cli)
    - [2.3 Configuring Qwen Code CLI](#23-configuring-qwen-code-cli)
- [3. Quick Start (5 Minutes)](#3-quick-start-5-minutes)
- [4. Service Endpoints](#4-service-endpoints)
- [5. Core Features](#5-core-features)
    - [5.1 Agent Authentication](#51-agent-authentication)
    - [5.2 Workload Management](#52-workload-management)
    - [5.3 Tool Call Authorization](#53-tool-call-authorization)
    - [5.4 Audit Trail](#54-audit-trail)
- [6. Core Concepts](#6-core-concepts)
- [7. Configuration](#7-configuration)
    - [7.1 Agent Configuration](#71-agent-configuration)
    - [7.2 Qwen Configuration](#72-qwen-configuration)
    - [7.3 JWKS Configuration](#73-jwks-configuration)
- [8. Common Commands](#8-common-commands)
- [9. Troubleshooting](#9-troubleshooting)
- [10. Next Steps](#10-next-steps)

---

## 1. Overview

Open Agent Auth is an enterprise-grade AI Agent operation authorization framework built on industry-standard protocols (OAuth 2.0, OpenID Connect, WIMSE, MCP). It provides comprehensive security guarantees for AI Agents executing operations on behalf of users.

### Key Features

- **Virtual Workload Mode**: Request-level isolation mechanism where each user request operates in an independent workload environment
- **Cryptographic Identity Binding**: Three-layer cryptographic binding (User-Workload-Token) ensuring end-to-end identity consistency
- **Semantic Audit Trail**: W3C VC-based verifiable credentials recording complete operation context
- **Dynamic Policy Registration**: Runtime policy updates without service restart
- **Standard Protocol Support**: OAuth 2.0, OIDC, WIMSE, MCP and other international standards

### Use Cases

- AI Agents need to execute sensitive operations on behalf of users (e.g., payments, data queries)
- Complete operation auditing and compliance tracking is required
- Fine-grained access control and permission management is needed
- Prevention of Agent abuse and identity impersonation is necessary

---

## 2. Prerequisites

### 2.1 System Requirements

#### Required Software

- **Java**: JDK 17 or higher
  ```bash
  # Check Java version
  java -version
  ```

- **Maven**: 3.6.0 or higher
  ```bash
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

- **Git**: For cloning the project code
  ```bash
  # Check Git version
  git --version
  ```

#### Recommended Tools

- **IDE**: IntelliJ IDEA (recommended) or Eclipse
- **HTTP Client**: Postman or curl
- **Browser**: Chrome, Firefox, Safari

### 2.2 Installing Qwen Code CLI

Qwen Code CLI is a command-line tool for interacting with the Qwen large language model. This project uses it as the backend model for the AI Agent.

#### macOS/Linux Installation

```bash
# Method 1: Install using pip (recommended)
pip install qwencode-cli

# Method 2: Install using brew (macOS)
brew install qwencode-cli

# Method 3: Install from source
git clone https://github.com/QwenLM/qwen-code.git
cd qwen-code
pip install -e .
```

#### Windows Installation

```powershell
# Install using pip
pip install qwencode-cli

# Or use Chocolatey
choco install qwencode-cli
```

#### Verifying Installation

```bash
# Verify Qwen Code CLI installation
qwencode --version

# Test connection
qwencode test
```

### 2.3 Configuring Qwen Code CLI

#### Obtaining API Key

1. Visit [Qwen Official Website](https://tongyi.aliyun.com/)
2. Register/Login to your account
3. Navigate to API Key Management page
4. Create a new API Key
5. Save the API Key (format: `sk-xxxxx`)

#### Configuring Environment Variables

```bash
# macOS/Linux
export QWEN_API_KEY="your-api-key-here"
export QWEN_API_BASE="https://dashscope.aliyuncs.com/compatible-mode/v1"

# Windows PowerShell
$env:QWEN_API_KEY="your-api-key-here"
$env:QWEN_API_BASE="https://dashscope.aliyuncs.com/compatible-mode/v1"

# Permanent configuration (add to ~/.bashrc or ~/.zshrc)
echo 'export QWEN_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

#### Configuration File Method

Create `~/.qwencode/config.yaml`:

```yaml
api_key: your-api-key-here
api_base: https://dashscope.aliyuncs.com/compatible-mode/v1
model: qwen3-coder-plus
timeout: 120
```

#### Testing Configuration

```bash
# Test Qwen Code CLI configuration
qwencode chat "Hello, Qwen!"

# Test tool calling functionality
qwencode chat --tool "calculator" "Calculate 2 + 2"
```

---

## 3. Quick Start (5 Minutes)

This guide will help you experience the core features of Open Agent Auth in **5 minutes**.

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

After installing QwenCode (see Section 2.2), restart the services:

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

> **Tip**: The Mock LLM uses keyword-based matching. For available products and matching rules, see [Mock LLM Guide](02-mock-llm-guide.md).

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

## 4. Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Agent | http://localhost:8081 | AI Agent main interface |
| Agent IDP | http://localhost:8082 | Agent identity provider |
| Agent User IDP | http://localhost:8083 | User identity provider |
| AS User IDP | http://localhost:8084 | Authorization server user identity provider |
| Authorization Server | http://localhost:8085 | Authorization server |
| Resource Server | http://localhost:8086 | Resource server (MCP Server) |

---

## 5. Core Features

### 5.1 Agent Authentication

#### OAuth 2.0 Authorization Flow

1. **User Authentication**
    - Agent User IDP verifies user identity
    - Issues ID Token

2. **Agent Authentication**
    - Authorization Server verifies agent identity
    - Issues Agent OA Token

3. **Workload Authentication**
    - Agent IDP creates virtual workload
    - Issues WIT (Workload Identity Token)

#### Identity Binding

- **User Identity**: Bound through ID Token
- **Workload Identity**: Bound through WIT
- **Agent Identity**: Bound through OA Token

The three layers of identity are cryptographically bound to ensure end-to-end identity consistency.

### 5.2 Workload Management

#### Virtual Workload Creation

Each user request creates an independent virtual workload:

```java
// Workload creation example
Workload workload = workloadManager.createWorkload(userId, requestId);
workload.setTemporaryKeyPair(generateKeyPair());
// Set expiration to 1 hour from now
workload.setExpiration(System.currentTimeMillis() + 3600000);
```

#### Workload Features

- **Request-level isolation**: Each request operates in an independent workload environment
- **Temporary key pairs**: Workload-specific keys that expire and are automatically revoked
- **Resource limits**: Restricts resources that the workload can access
- **Audit tracking**: Records all operations of the workload

### 5.3 Tool Call Authorization

#### MCP Protocol Support

The agent calls tools through the MCP (Model Context Protocol) protocol:

```yaml
# MCP server configuration
agent:
  mcp-servers:
    - name: shopping
      url: http://localhost:8086/mcp
      description: "Shopping service MCP Server"
      enabled: true
```

#### Five-Layer Verification Mechanism

1. **Workload Authentication**: Verifies WIT signature and validity period
2. **Request Integrity**: Verifies WPT (Workload Proof Token) signature
3. **User Authentication**: Verifies Agent OA Token signature and claims
4. **Identity Consistency**: Verifies user-workload-token identity binding
5. **Policy Evaluation**: Fine-grained access control based on OPA policies

### 5.4 Audit Trail

#### W3C VC Verifiable Credentials

Each operation generates a verifiable credential:

```json
{
  "jti": "vc-abc123xyz",
  "iss": "http://localhost:8082",
  "sub": "user123",
  "iat": 1738562400,
  "exp": 1738566000,
  "type": "VerifiableCredential",
  "credential_subject": {
    "type": "UserInputEvidence",
    "prompt": "I want to buy an iPhone 15",
    "timestamp": "2026-02-03T10:00:00Z",
    "channel": "web",
    "device_fingerprint": "fp_device_abc123"
  },
  "issuer": "http://localhost:8082",
  "issuance_date": "2026-02-03T10:00:00Z",
  "expiration_date": "2026-02-03T11:00:00Z",
  "proof": {
    "type": "JwtProof2020",
    "created": "2026-02-03T10:00:00Z",
    "verification_method": "http://localhost:8081/#key-01"
  }
}
```

---

## 6. Core Concepts

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

## 7. Configuration

This section covers the essential configuration options for the Open Agent Auth framework. For a complete reference of all configuration properties, default values, and role-specific settings, please refer to the **[Configuration Guide](04-configuration.md)**.

### 7.1 Agent Configuration

#### Basic Configuration

```yaml
open-agent-auth:
  enabled: true
  role: agent
  issuer: http://localhost:8081
  trust-domain: wimse://default.trust.domain
  
  agent:
    enabled: true
    oauth-callbacks-redirect-uri: http://localhost:8081/callback
    authentication:
      enabled: true
      include-paths:
        - /**
      exclude-paths:
        - /oauth/callback
        - /public/**
        - /.well-known/jwks.json
  
  services:
    provider:
      enabled: true
      base-url: ${open-agent-auth.issuer}
    consumers:
      agent-idp:
        base-url: http://localhost:8082
        endpoints:
          workload.issue: /api/v1/workloads/token/issue
          workload.revoke: /api/v1/workloads/revoke
      authorization-server:
        base-url: http://localhost:8085
        endpoints:
          oauth2.authorize: /oauth2/authorize
          oauth2.token: /oauth2/token
```

#### Session Management

```yaml
open-agent-auth:
  agent:
    session-mapping:
      enabled: true
      session-ttl-seconds: 3600
```

### 7.2 Qwen Configuration

#### Basic Configuration

```yaml
qwen:
  model: qwen3-coder-plus
  timeout: 120
```

#### Supported Models

| Model | Description | Use Cases |
|-------|-------------|-----------|
| qwen3-coder-plus | Enhanced code model | Code generation, debugging |
| qwen3-coder-flash | Fast code model | Quick response, lightweight tasks |
| qwen-max | Maximum capability model | Complex reasoning, long text |
| qwen-plus | Enhanced model | General conversation, tool calling |

#### Advanced Configuration

```yaml
qwen:
  model: qwen3-coder-plus
  timeout: 120
  temperature: 0.7
  max-tokens: 2000
  top-p: 0.9
```

### 7.3 JWKS Configuration

For comprehensive information about infrastructure configuration, including trust domain, key management, JWKS, and service discovery, please refer to the **[Infrastructure Configuration Guide](04-configuration.md)**.

#### Provider Configuration (Expose Public Keys)

```yaml
open-agent-auth:
  jwks:
    enabled: true
    provider:
      enabled: true
      path: /.well-known/jwks.json
      cache-duration-seconds: 300
      cache-headers-enabled: true
```

#### Consumer Configuration (Verify External Tokens)

```yaml
open-agent-auth:
  jwks:
    consumers:
      agent-user-idp:
        enabled: true
        jwks-endpoint: http://localhost:8083/.well-known/jwks.json
        issuer: http://localhost:8083
      
      agent-idp:
        enabled: true
        jwks-endpoint: http://localhost:8082/.well-known/jwks.json
        issuer: http://localhost:8082
      
      authorization-server:
        enabled: true
        jwks-endpoint: http://localhost:8085/.well-known/jwks.json
        issuer: http://localhost:8085
```

---

## 8. Common Commands

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

## 9. Troubleshooting

### Q1: What if Qwen Code CLI installation fails?

**Problem**: `pip install qwencode-cli` reports an error

**Solution**:
```bash
# Upgrade pip
python -m pip install --upgrade pip

# Use domestic mirror source
pip install qwencode-cli -i https://pypi.tuna.tsinghua.edu.cn/simple

# Or use conda
conda install -c conda-forge qwencode-cli
```

### Q2: What if service startup fails?

**Problem**: `Port 8081 is already in use` or service fails to start

**Solution**:
```bash
# Check if ports are occupied
lsof -i :8081
lsof -i :8082
# ... check other ports

# Find the process occupying the port
lsof -i :8081

# Kill the process
kill -9 <PID>

# View service logs
./scripts/sample-logs.sh sample-agent

# Rebuild
cd ..
mvn clean package -DskipTests
cd open-agent-auth-samples
```

### Q3: Qwen API call failed?

**Problem**: `Failed to call Qwen API`

**Solution**:
```bash
# Check API Key configuration
echo $QWEN_API_KEY

# Test API connection
curl https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions \
  -H "Authorization: Bearer $QWEN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen3-coder-plus","messages":[{"role":"user","content":"test"}]}'

# Check network connection
ping dashscope.aliyuncs.com
```

### Q4: How to view service logs?

**Solution**:
```bash
# Use the provided log script
./scripts/sample-logs.sh sample-agent

# Or view log files directly
tail -f open-agent-auth-samples/logs/sample-agent.log

# View all service logs
./scripts/sample-logs.sh all
```

### Q5: How to reset all services?

**Solution**:
```bash
# Stop all services
./scripts/sample-stop.sh

# Clean up logs and process files
rm -rf logs/* pids/*

# Restart
./scripts/sample-start.sh
```

### Q6: How to view test coverage?

**Solution**:
```bash
# Run tests and generate coverage report
mvn clean test jacoco:report

# View HTML report
open open-agent-auth-core/target/site/jacoco/index.html
open open-agent-auth-framework/target/site/jacoco/index.html

# View aggregated report (if configured)
open target/site/jacoco-aggregate/index.html
```

---

## 10. Next Steps

### Deep Dive

- **Configuration Guides**:
    - [Mock LLM Guide](02-mock-llm-guide.md) - Learn about Mock LLM configuration
    - [Integration Guide](03-integration-guide.md) - Learn how to integrate into your own project
    - [Configuration Guide](04-configuration.md) - Complete configuration reference
- **Architecture Documents**: Read [Architecture Design Documents](../architecture/)
- **API Documentation**: View [API Reference Documentation](../api/00-api-overview.md)
- **Protocol Standards**: Learn about [OAuth 2.0](https://oauth.net/2/), [OIDC](https://openid.net/connect/), [WIMSE](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-identity)

### Contribute

- **Report Issues**: [GitHub Issues](https://github.com/alibaba/open-agent-auth/issues)
- **Submit Code**: [Pull Request](https://github.com/alibaba/open-agent-auth/pulls)
- **Contributing Guide**: [CONTRIBUTING.md](https://github.com/alibaba/open-agent-auth/blob/main/CONTRIBUTING.md)

### Get Help

- **Documentation**: [Complete Documentation](https://github.com/alibaba/open-agent-auth#readme)
- **Examples**: [Sample Project](https://github.com/alibaba/open-agent-auth/tree/main/open-agent-auth-samples)
- **Community**: [GitHub Discussions](https://github.com/alibaba/open-agent-auth/discussions)
- **Email**: open-agent-auth@alibaba-inc.com

---

**Document Version**: 1.0.0  
**Last Updated**: 2026-02-03  
**Maintainer**: Open Agent Auth Team
