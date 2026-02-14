# Open Agent Auth User Guide

## 📖 Table of Contents

- [1. Overview](#1-overview)
- [2. Prerequisites](#2-prerequisites)
    - [2.1 System Requirements](#21-system-requirements)
    - [2.2 Installing Qwen Code CLI](#22-installing-qwen-code-cli)
    - [2.3 Configuring Qwen Code CLI](#23-configuring-qwen-code-cli)
- [3. Quick Start](#3-quick-start)
    - [3.1 Starting Sample Services](#31-starting-sample-services)
    - [3.2 Accessing the Agent Interface](#32-accessing-the-agent-interface)
    - [3.3 Experiencing the Agent Authorization Flow](#33-experiencing-the-agent-authorization-flow)
- [4. Core Features](#4-core-features)
    - [4.1 Agent Authentication](#41-agent-authentication)
    - [4.2 Workload Management](#42-workload-management)
    - [4.3 Tool Call Authorization](#43-tool-call-authorization)
    - [4.4 Audit Trail](#44-audit-trail)
- [5. Configuration](#5-configuration)
    - [5.1 Agent Configuration](#51-agent-configuration)
    - [5.2 Qwen Configuration](#52-qwen-configuration)
    - [5.3 JWKS Configuration](#53-jwks-configuration)
- [6. Troubleshooting](#6-troubleshooting)
- [7. Next Steps](#7-next-steps)

---

## 1. Overview

Open Agent Auth is an enterprise-grade AI Agent operation authorization framework built on industry-standard protocols (OAuth 2.0, OpenID Connect, WIMSE, MCP). It provides comprehensive security guarantees for AI Agents executing operations on behalf of users.

### Getting Started

- 🚀 **Quick Start**: If you want to get started in 5 minutes, see the [Quick Start Guide](01-quick-start.md)
- 📖 **Complete Configuration**: For detailed configuration options, see the [Configuration Guide](../configuration/)
- 🔧 **Infrastructure Configuration**: For infrastructure configuration, see the [Infrastructure Configuration Guide](../configuration/01-infrastructure-configuration.md)
- 🔐 **Infrastructure Configuration**: For infrastructure configuration, see the [Infrastructure Configuration Guide](../configuration/01-infrastructure-configuration.md)

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

## 3. Quick Start

### 3.1 Starting Sample Services

This project includes a complete sample project with all necessary service components.

#### Clone the Project

```bash
# Clone the project
git clone https://github.com/alibaba/open-agent-auth.git
cd open-agent-auth
```

#### Build the Project

```bash
# Build using JDK 17
export JAVA_HOME=$(/usr/libexec/java_home -v 17)

# Build all modules
mvn clean package -DskipTests

# Or use the provided startup script (will build automatically)
cd open-agent-auth-samples/scripts
./sample-start.sh
```

#### Start Services

```bash
# Enter the samples directory
cd open-agent-auth-samples

# Start all services (using the startup script)
./scripts/sample-start.sh
```

#### Verify Services Are Running

```bash
# Check service ports
lsof -i :8081 # Agent
lsof -i :8082 # Agent IDP
lsof -i :8083 # Agent User IDP
lsof -i :8084 # AS User IDP
lsof -i :8085 # Authorization Server
lsof -i :8086 # Resource Server

# Or use the provided status check script
./scripts/sample-status.sh
```

### 3.2 Accessing the Agent Interface

After services start successfully, you can access the Agent interface through your browser:

#### Main Interface

```
http://localhost:8081
```

#### Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Agent | http://localhost:8081 | AI Agent main interface |
| Agent IDP | http://localhost:8082 | Agent identity provider |
| Agent User IDP | http://localhost:8083 | User identity provider |
| AS User IDP | http://localhost:8084 | Authorization server user identity provider |
| Authorization Server | http://localhost:8085 | Authorization server |
| Resource Server | http://localhost:8086 | Resource server (MCP Server) |

### 3.3 Experiencing the Agent Authorization Flow

#### Scenario: Shopping Assistant

1. **Access the Agent Interface**
   ```
   http://localhost:8081
   ```

2. **User Login**
    - Click the "Login" button
    - Enter username and password (Sample default: `user/password`)
    - Complete identity authentication

3. **Initiate a Request**
    - In the dialog box, type: "I want to buy an iPhone 15"
    - The agent will analyze the request and prepare to call the shopping tool

4. **Authorization Confirmation**
    - The agent will display tool call details
    - User confirms authorization: "Yes, please help me buy it"
    - The agent executes the tool call

5. **View Results**
    - The agent returns the purchase result
    - You can view the complete operation record in the audit log

#### Complete Authorization Flow

```
User → Agent → Authentication → Create Workload → Request Authorization
  ↓
User confirms authorization → Get authorization token → Call tool → Five-layer verification → Return result
```

---

## 4. Core Features

### 4.1 Agent Authentication

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

### 4.2 Workload Management

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

### 4.3 Tool Call Authorization

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

### 4.4 Audit Trail

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

## 5. Configuration

This section covers the essential configuration options for the Open Agent Auth framework. For a complete reference of all configuration properties, default values, and role-specific settings, please refer to the **[Configuration Guide](../configuration/)**.

### 5.1 Agent Configuration

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

### 5.2 Qwen Configuration

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

### 5.3 JWKS Configuration

For comprehensive information about infrastructure configuration, including trust domain, key management, JWKS, and service discovery, please refer to the **[Infrastructure Configuration Guide](../configuration/01-infrastructure-configuration.md)**.

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

## 6. Troubleshooting

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

### Q2: Service startup failed, port is already in use?

**Problem**: `Port 8081 is already in use`

**Solution**:
```bash
# Find the process occupying the port
lsof -i :8081

# Kill the process
kill -9 <PID>

# Or modify port configuration
# Modify server.port in application.yml
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

### Q5: How to stop all services?

**Solution**:
```bash
# Use the provided stop script
./scripts/sample-stop.sh
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

## 7. Next Steps

### Deep Dive

- **Configuration Guides**:
    - [Quick Start Guide](01-quick-start.md) - Get started in 5 minutes
    - [Configuration Guide](../configuration/) - Complete configuration reference
    - [Infrastructure Configuration Guide](../configuration/01-infrastructure-configuration.md) - Infrastructure configuration
    - [Infrastructure Configuration Guide](../configuration/01-infrastructure-configuration.md) - Infrastructure configuration
- **Architecture Documents**: Read [Architecture Design Documents](../architecture/)
- **Developer Guide**: Learn how to integrate into your own project
- **API Documentation**: View [API Reference Documentation](../api/)
- **Protocol Standards**: Learn about [OAuth 2.0](https://oauth.net/2/), [OIDC](https://openid.net/connect/), [WIMSE](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-identity)

### Contribute

- **Report Issues**: [GitHub Issues](https://github.com/alibaba/open-agent-auth/issues)
- **Submit Code**: [Pull Request](https://github.com/alibaba/open-agent-auth/pulls)
- **Contributing Guide**: [CONTRIBUTING.md](../../CONTRIBUTING.md)

### Get Help

- **Documentation**: [Complete Documentation](../../../README.md)
- **Examples**: [Sample Project](../../open-agent-auth-samples/)
- **Community**: [GitHub Discussions](https://github.com/alibaba/open-agent-auth/discussions)
- **Email**: open-agent-auth@alibaba-inc.com

---

**Document Version**: 1.0.0  
**Last Updated**: 2026-02-03  
**Maintainer**: Open Agent Auth Team