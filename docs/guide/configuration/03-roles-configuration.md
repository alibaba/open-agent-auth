# Roles Configuration Guide

## Introduction

Roles represent specific functional instances in the Open Agent Auth framework. Each role composes one or more capabilities to create a complete, working application. This guide explains how to configure roles and how they interact with capabilities.

## Configuration Overview

Roles are configured under `open-agent-auth.roles`. The required capabilities for each role are automatically validated by the framework's ConfigurationValidator. You only need to enable the corresponding capabilities under `open-agent-auth.capabilities`.

```yaml
open-agent-auth:
  roles:
    authorization-server:
      enabled: true
      issuer: https://auth.example.com
```

### Available Roles

| Role | Description | Required Capabilities |
|------|-------------|----------------------|
| **agent** | AI Agent that orchestrates tool calls | oauth2-client, operation-authorization |
| **agent-idp** | Workload Identity Provider | workload-identity |
| **agent-user-idp** | Agent User Identity Provider | oauth2-server, user-authentication |
| **authorization-server** | Authorization Server for agent operations | oauth2-server, operation-authorization, workload-identity, audit |
| **resource-server** | Hosts protected resources | workload-identity |
| **as-user-idp** | Authorization Server User Identity Provider | oauth2-server, user-authentication |

---

## Role Properties

### Common Properties

All roles share the following common properties:

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `enabled` | Boolean | Whether this role is enabled | Yes |
| `issuer` | String | Issuer URL for this role instance | Yes |

### Role Configuration Structure

```yaml
roles:
  <role-name>:
    enabled: boolean              # Whether role is enabled
    issuer: string                # Issuer URL
```

---

## Role Configurations

### Agent Role

#### Overview

The Agent role represents an AI Agent that orchestrates tool calls and manages user interactions. It authenticates users, requests operation authorization, and executes tools.

#### Configuration
```yaml
open-agent-auth:
  roles:
    agent:
      enabled: true
      issuer: https://agent.example.com
```

#### Required Capabilities

| Capability | Purpose |
|------------|---------|
| **oauth2-client** | Authenticate with authorization server |
| **operation-authorization** | Request authorization for operations |

#### Use Cases

- **AI Assistant**: Provide intelligent assistance with tool integration
- **Chatbot**: Interactive chatbot with authorization-aware operations
- **Workflow Automation**: Automate workflows with user approval

### Agent IDP Role

#### Overview

The Agent IDP (Agent Identity Provider) role manages workload identities and issues Workload Identity Tokens (WIT) for applications and services.

#### Configuration

```yaml
open-agent-auth:
  roles:
    agent-idp:
      enabled: true
      issuer: https://agent-idp.example.com
```

#### Required Capabilities

| Capability | Purpose |
|------------|---------|
| **workload-identity** | Manage workload identities and issue WITs |

#### Use Cases

- **Service Identity**: Provide identity for microservices
- **Kubernetes Integration**: Provide identity to Kubernetes pods
- **Batch Jobs**: Provide identity to scheduled jobs

### Agent User IDP Role

#### Overview

The Agent User IDP (Agent User Identity Provider) role authenticates AI agents and issues ID Tokens. It provides user authentication for agents.

#### Configuration
```yaml
open-agent-auth:
  roles:
    agent-user-idp:
      enabled: true
      issuer: https://agent-user-idp.example.com
```

#### Required Capabilities

| Capability | Purpose |
|------------|---------|
| **oauth2-server** | Issue OAuth 2.0 tokens |
| **user-authentication** | Authenticate agents |

#### Use Cases

- **Agent Authentication**: Authenticate AI agents
- **Agent Management**: Manage agent identities
- **Agent Registry**: Maintain registry of authorized agents

### Authorization Server Role

#### Overview

The Authorization Server role processes authorization requests and issues Agent Operation Authorization Tokens (AOAT). It manages policies, bindings, and user approvals.

#### Configuration
```yaml
open-agent-auth:
  roles:
    authorization-server:
      enabled: true
      issuer: https://auth-server.example.com
```

#### Required Capabilities

| Capability | Purpose |
|------------|---------|
| **oauth2-server** | Issue OAuth 2.0 tokens |
| **operation-authorization** | Manage policies and bindings |
| **workload-identity** | Verify workload identities |

#### Use Cases

- **Authorization Management**: Centralized authorization for agent operations
- **Policy Enforcement**: Enforce authorization policies
- **User Consent**: Manage user approvals for operations

### Resource Server Role

#### Overview

The Resource Server role hosts protected resources and implements five-layer validation. It validates tokens and enforces access control.

#### Configuration

```yaml
open-agent-auth:
  roles:
    resource-server:
      enabled: true
      issuer: https://resource-server.example.com
```

#### Required Capabilities

| Capability | Purpose |
|------------|---------|
| **workload-identity** | Verify workload identity tokens |

#### Use Cases

- **API Protection**: Protect REST APIs
- **Resource Hosting**: Host protected resources
- **Access Control**: Enforce access control policies

### AS User IDP Role

#### Overview

The AS User IDP (Authorization Server User Identity Provider) role authenticates users for the Authorization Server. It provides user authentication for authorization decisions.

#### Configuration
```yaml
open-agent-auth:
  roles:
    as-user-idp:
      enabled: true
      issuer: https://as-user-idp.example.com
```

#### Required Capabilities

| Capability | Purpose |
|------------|---------|
| **oauth2-server** | Issue OAuth 2.0 tokens |
| **user-authentication** | Authenticate users |

#### Use Cases

- **User Authentication**: Authenticate users for authorization decisions
- **User Management**: Manage user identities
- **User Registry**: Maintain registry of authorized users


---

## Complete Role Configuration Examples

### Example 1: Single Agent Deployment

```yaml
open-agent-auth:
  enabled: true
  
  infrastructures:
    trust-domain: wimse://mycompany.com
  
  capabilities:
    oauth2-client:
      enabled: true
    operation-authorization:
      enabled: true
  
  roles:
    agent:
      enabled: true
      issuer: https://agent.mycompany.com
```

### Example 2: Full Stack Deployment
```yaml
open-agent-auth:
  enabled: true
  
  infrastructures:
    trust-domain: wimse://mycompany.com
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        wit-signing:
          key-id: wit-signing-001
          algorithm: ES256
          provider: local
        aoat-signing:
          key-id: aoat-signing-001
          algorithm: RS256
          provider: local
  
  capabilities:
    oauth2-server:
      enabled: true
    oauth2-client:
      enabled: true
    workload-identity:
      enabled: true
    operation-authorization:
      enabled: true
    user-authentication:
      enabled: true
    audit:
      enabled: true
      provider: logging
  
  roles:
    agent-idp:
      enabled: true
      issuer: https://agent-idp.mycompany.com
    
    agent-user-idp:
      enabled: true
      issuer: https://agent-user-idp.mycompany.com
    
    authorization-server:
      enabled: true
      issuer: https://auth-server.mycompany.com
    
    agent:
      enabled: true
      issuer: https://agent.mycompany.com
```

### Example 3: Development Configuration

```yaml
open-agent-auth:
  enabled: true
  
  infrastructures:
    trust-domain: wimse://dev.mycompany.com
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        dev-signing:
          key-id: dev-signing
          algorithm: ES256
          provider: local
  
  capabilities:
    oauth2-server:
      enabled: true
    workload-identity:
      enabled: true
  
  roles:
    agent-idp:
      enabled: true
      issuer: http://localhost:8082
```

---

## Best Practices

### 1. Use Descriptive Role Names

Use clear, descriptive names for roles:

```yaml
# Good: Descriptive names
roles:
  production-authorization-server:
    enabled: true
  staging-authorization-server:
    enabled: true
```

```yaml
# Bad: Non-descriptive names
roles:
  auth-1:
    enabled: true
  auth-2:
    enabled: true
```

### 2. Use Environment Variables

Use environment variables for sensitive configuration:

```yaml
open-agent-auth:
  capabilities:
    oauth2-client:
      enabled: true
      callback:
        client-id: ${CLIENT_ID}
        client-secret: ${CLIENT_SECRET}
  roles:
    agent:
      enabled: true
      issuer: ${AGENT_ISSUER_URL:https://agent.mycompany.com}
```

### 3. Enable Only Needed Roles

Only enable the roles you need:

```yaml
# Good: Enable only needed roles
roles:
  agent:
    enabled: true
  agent-idp:
    enabled: true
```

```yaml
# Bad: Enable all roles unnecessarily
roles:
  agent:
    enabled: true
  agent-idp:
    enabled: true
  authorization-server:
    enabled: true  # Not needed
  resource-server:
    enabled: true  # Not needed
```

### 4. Document Role Purpose

Add comments explaining the purpose of each role:

```yaml
roles:
  # Primary authorization server for production
  authorization-server-primary:
    enabled: true
    issuer: https://auth.mycompany.com
  
  # Secondary authorization server for high availability
  authorization-server-secondary:
    enabled: true
    issuer: https://auth-backup.mycompany.com
```

### 5. Test Role Configuration

Test your configuration before deploying:

```bash
# Test role endpoints
curl https://agent.mycompany.com/health
curl https://agent-idp.mycompany.com/api/v1/workloads/create
curl https://auth-server.mycompany.com/oauth2/authorize
```

---

## Troubleshooting

### Common Issues

#### 1. Role Not Starting

**Symptoms**: Role is not being initialized

**Solutions**:
- Verify the role is enabled (`roles.<role-name>.enabled: true`)
- Check if required capabilities are enabled under `open-agent-auth.capabilities`
- Ensure the issuer URL is set correctly
- Review logs for initialization errors

#### 2. Capability Not Available

**Symptoms**: Capability features are not available in the role

**Solutions**:
- Verify the capability is enabled in `capabilities.<capability-name>.enabled`
- Ensure required infrastructure (trust domain, keys) is configured

#### 3. Capability Configuration Not Taking Effect

**Symptoms**: Capability configuration is not being applied as expected

**Solutions**:
- Verify the capability is configured under `open-agent-auth.capabilities.<capability-name>`
- Ensure property names match the capability's expected property structure
- Check for YAML indentation issues

### Debug Logging

Enable debug logging for roles:

```yaml
logging:
  level:
    com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties: DEBUG
    com.alibaba.openagentauth.spring.autoconfigure: DEBUG
```

---

## Next Steps

- **[Infrastructure Configuration Guide](01-infrastructure-configuration.md)**: Configure trust domain, keys, and JWKS
- **[Capabilities Configuration Guide](02-capabilities-configuration.md)**: Understand how to configure individual capabilities

---

## Additional Resources

- **[Configuration Overview](00-configuration-overview.md)**: Introduction to configuration architecture
- **[Quick Start Guide](../start/01-quick-start.md)**: Get started quickly
- **[User Guide](../start/00-user-guide.md)**: Comprehensive user documentation
