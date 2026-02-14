# Roles Configuration Guide

## Introduction

Roles represent specific functional instances in the Open Agent Auth framework. Each role composes one or more capabilities to create a complete, working application. This guide explains how to configure roles and how they interact with capabilities.

## Configuration Overview

Roles are configured under `open-agent-auth.roles`:

```yaml
open-agent-auth:
  roles:
    authorization-server:
      enabled: true
      issuer: https://auth.example.com
      capabilities:
        - oauth2-server
        - operation-authorization
        - workload-identity
```

### Available Roles

| Role | Description | Typical Capabilities |
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
| `instance-id` | String | Instance identifier for multi-instance deployments | No |
| `capabilities` | List | List of capabilities used by this role | Yes |
| `config` | Map | Role-specific configuration overrides | No |

### Role Configuration Structure

```yaml
roles:
  &lt;role-name&gt;:
    enabled: boolean              # Whether role is enabled
    issuer: string                # Issuer URL
    instance-id: string           # Optional: Instance identifier
    capabilities:                 # List of capabilities
      - capability-1
      - capability-2
    config:                       # Role-specific overrides
      capability-1:
        property: value
      capability-2:
        property: value
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
      instance-id: agent-001
      capabilities:
        - oauth2-client
        - operation-authorization
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
      instance-id: agent-idp-001
      capabilities:
        - workload-identity
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
      instance-id: agent-user-idp-001
      capabilities:
        - oauth2-server
        - user-authentication
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
      instance-id: auth-server-001
      capabilities:
        - oauth2-server
        - operation-authorization
        - workload-identity
        - audit
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
      instance-id: resource-server-001
      capabilities:
        - workload-identity
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
      instance-id: as-user-idp-001
      capabilities:
        - oauth2-server
        - user-authentication
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

## Multi-Instance Deployment

### Overview

Roles can be deployed as multiple instances using the `instance-id` property. This is useful for high availability and load balancing.

### Configuration

```yaml
open-agent-auth:
  roles:
    authorization-server-primary:
      enabled: true
      issuer: https://auth-primary.example.com
      instance-id: auth-server-001
      capabilities:
        - oauth2-server
        - operation-authorization
    
    authorization-server-secondary:
      enabled: true
      issuer: https://auth-secondary.example.com
      instance-id: auth-server-002
      capabilities:
        - oauth2-server
        - operation-authorization
```

### Use Cases

- **High Availability**: Deploy multiple instances for redundancy
- **Load Balancing**: Distribute load across instances
- **Geographic Distribution**: Deploy instances in different regions

---

## Role-Specific Configuration Overrides

### Overview

Roles can override capability-level configuration using the `config` map. This allows different roles to use different settings for the same capability.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      token:
        access-token-expiry: 3600  # Default: 1 hour
  
  roles:
    agent:
      enabled: true
      capabilities:
        - oauth2-client
      config:
        oauth2-client:  # No override needed
    
    authorization-server:
      enabled: true
      capabilities:
        - oauth2-server
      config:
        oauth2-server:
          token:
            access-token-expiry: 7200  # Override: 2 hours
```

### Override Precedence

Configuration is applied in the following order (later values override earlier ones):

1. **Capability Defaults**: Default values in capability configuration
2. **Capability Configuration**: Values from `capabilities.<capability-name>`
3. **Role Overrides**: Values from `roles.<role-name>.config.<capability-name>`

### Best Practices

1. **Minimize Overrides**: Override only what is necessary
2. **Document Overrides**: Add comments explaining why overrides are needed
3. **Test Overrides**: Verify overrides work as expected
4. **Review Defaults**: Check capability defaults before overriding

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
      capabilities:
        - oauth2-client
        - operation-authorization
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
      capabilities:
        - workload-identity
    
    agent-user-idp:
      enabled: true
      issuer: https://agent-user-idp.mycompany.com
      capabilities:
        - oauth2-server
        - user-authentication
    
    authorization-server:
      enabled: true
      issuer: https://auth-server.mycompany.com
      capabilities:
        - oauth2-server
        - operation-authorization
        - workload-identity
        - audit
    
    agent:
      enabled: true
      issuer: https://agent.mycompany.com
      capabilities:
        - oauth2-client
        - operation-authorization
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
      capabilities:
        - workload-identity
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
roles:
  agent:
    enabled: true
    issuer: ${AGENT_ISSUER_URL:https://agent.mycompany.com}
    config:
      oauth2-client:
        callback:
          client-id: ${CLIENT_ID}
          client-secret: ${CLIENT_SECRET}
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
- Check if required capabilities are listed
- Ensure the issuer URL is set correctly
- Review logs for initialization errors

#### 2. Capability Not Available

**Symptoms**: Capability features are not available in the role

**Solutions**:
- Verify the capability is enabled in `capabilities.<capability-name>.enabled`
- Check if the capability is listed in the role's `capabilities` array
- Ensure required infrastructure (trust domain, keys) is configured

#### 3. Configuration Override Not Working

**Symptoms**: Role-specific configuration is not being applied

**Solutions**:
- Verify the override is in the correct location (`roles.<role-name>.config.<capability-name>`)
- Check if the capability is listed in the role's `capabilities` array
- Ensure override property names match capability property names

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
