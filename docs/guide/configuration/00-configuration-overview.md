# Configuration Overview

## Introduction

The Open Agent Auth framework provides a comprehensive, hierarchical configuration system designed for flexibility, security, and ease of use. This guide introduces the configuration architecture and helps you understand how to configure the framework for your specific needs.

## Configuration Architecture

The framework follows a **layered architecture** that separates concerns into four main levels:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Configuration Architecture                   │
└─────────────────────────────────────────────────────────────────┘

open-agent-auth
├── infrastructures      # Shared infrastructure (trust, keys, JWKS)
├── capabilities         # Composable functional features
├── roles               # Role instances with capability composition
├── security            # Security policies (CSRF, CORS)
├── audit               # Audit logging configuration
└── monitoring          # Metrics and tracing
```

### Configuration Hierarchy

| Level | Purpose | Example Components |
|-------|---------|-------------------|
| **Infrastructure** | Shared foundation for all roles | Trust domain, key management, JWKS, service discovery |
| **Capabilities** | Reusable functional features | OAuth2 server, workload identity, user authentication |
| **Roles** | Specific role instances | Agent, Agent IDP, Authorization Server, Resource Server |
| **Cross-Cutting** | Global policies | Security, audit, monitoring |

### Key Design Principles

- **Composition Over Inheritance**: Roles compose capabilities rather than extend them
- **Separation of Concerns**: Infrastructure, capabilities, and roles are clearly separated
- **Sensible Defaults**: Comprehensive defaults work out-of-the-box
- **Flexible Override**: Override only what you need
- **Type Safety**: Strongly typed configuration with validation

---

## Quick Start

### Minimal Configuration

The simplest configuration enables the framework with default settings:

```yaml
open-agent-auth:
  enabled: true
  roles:
    agent:
      enabled: true
      issuer: http://localhost:8081
```

### Typical Configuration

A typical production configuration:

```yaml
open-agent-auth:
  enabled: true
  
  # Infrastructure - shared across all roles
  infrastructures:
    trust-domain: wimse://mycompany.com
    key-management:
      providers:
        local:
          type: in-memory
    jwks:
      provider:
        enabled: true
        endpoint: /.well-known/jwks.json
  
  # Capabilities - reusable features
  capabilities:
    oauth2-server:
      enabled: true
    workload-identity:
      enabled: true
    operation-authorization:
      enabled: true
  
  # Roles - specific instances
  roles:
    authorization-server:
      enabled: true
      issuer: https://auth.mycompany.com
    resource-server:
      enabled: true
      issuer: https://resource.mycompany.com
  
  # Security policies
  security:
    csrf:
      enabled: false
    cors:
      enabled: true
      allowed-origins: "https://*.mycompany.com"
  
  # Monitoring
  monitoring:
    metrics:
      enabled: true
      export-prometheus: true
    tracing:
      enabled: true
```

---

## Configuration Sections

### 1. Infrastructure Configuration

Infrastructure provides the foundational services shared across all roles:

- **Trust Domain**: Defines the security boundary for workload identities
- **Key Management**: Manages cryptographic keys and key providers
- **JWKS**: Handles public key distribution and consumption
- **Service Discovery**: Enables automatic service discovery within the trust domain

**Configuration Prefix**: `open-agent-auth.infrastructures`

**Detailed Guide**: [Infrastructure Configuration Guide](01-infrastructure-configuration.md)

### 2. Capabilities Configuration

Capabilities represent reusable functional features that can be composed by roles:

| Capability | Description | Typical Use Cases |
|------------|-------------|-------------------|
| **oauth2-server** | OAuth 2.0 authorization server | Authorization Server, Agent User IDP, AS User IDP |
| **oauth2-client** | OAuth 2.0 client functionality | Agent, Resource Server |
| **workload-identity** | Workload identity management | Agent IDP, Agent, Resource Server |
| **operation-authorization** | Fine-grained authorization | Agent, Authorization Server |
| **user-authentication** | User identity and login | Agent User IDP, AS User IDP |
| **audit** | Audit logging for security and compliance | Authorization Server |

**Configuration Prefix**: `open-agent-auth.capabilities`

**Detailed Guide**: [Capabilities Configuration Guide](02-capabilities-configuration.md)

### 3. Roles Configuration

Roles represent specific functional instances that compose capabilities:

| Role | Description | Required Capabilities |
|------|-------------|----------------------|
| **agent** | AI Agent that orchestrates tool calls | oauth2-client, operation-authorization |
| **agent-idp** | Workload Identity Provider | workload-identity |
| **agent-user-idp** | Agent User Identity Provider | oauth2-server, user-authentication |
| **authorization-server** | Authorization Server for agent operations | oauth2-server, operation-authorization, workload-identity, audit |
| **resource-server** | Hosts protected resources | workload-identity |
| **as-user-idp** | Authorization Server User Identity Provider | oauth2-server, user-authentication |

**Configuration Prefix**: `open-agent-auth.roles`

**Detailed Guide**: [Roles Configuration Guide](03-roles-configuration.md)

### 4. Security, Audit, and Monitoring Configuration

Security policies, audit logging, and monitoring settings apply globally to all roles:

- **Security**: CSRF Protection and CORS policies
- **Audit**: Audit logging for compliance and debugging
- **Monitoring**: Metrics and tracing for observability

**Configuration Prefix**: `open-agent-auth.security`, `open-agent-auth.audit`, `open-agent-auth.monitoring`

**Note**: Detailed configuration guides for security, audit, and monitoring will be added in future releases.

---

## Configuration Flow

### How Configuration is Loaded

```
┌─────────────────────────────────────────────────────────────────┐
│                    Configuration Loading Flow                   │
└─────────────────────────────────────────────────────────────────┘

1. Application Startup
   ↓
2. Spring Boot loads application.yml/application.properties
   ↓
3. @ConfigurationProperties binds YAML to OpenAgentAuthProperties
   ↓
4. Infrastructure is initialized (trust domain, keys, JWKS)
   ↓
5. Capabilities are configured (enabled/disabled, parameters)
   ↓
6. Roles are instantiated with capability composition
   ↓
7. AutoConfiguration classes create beans based on role configuration
   ↓
8. Framework components are initialized with configuration
```

### Configuration Precedence

Configuration is applied in the following order (later values override earlier ones):

1. **Default Values**: Hardcoded defaults in Java classes
2. **Application Properties**: Values from `application.yml` or `application.properties`
3. **Environment Variables**: Values from system environment variables
4. **Command Line Arguments**: Values passed as command line arguments

### Environment-Specific Configuration

Use Spring profiles to manage environment-specific configurations:

```yaml
# application.yml
open-agent-auth:
  roles:
    authorization-server:
      enabled: true
      issuer: ${AUTH_SERVER_URL:http://localhost:8085}

---
# application-production.yml
spring:
  profiles: production

open-agent-auth:
  infrastructures:
    trust-domain: wimse://production.mycompany.com
    key-management:
      providers:
        local:
          type: in-memory
  roles:
    authorization-server:
      issuer: https://auth.production.mycompany.com
```

---

## Common Configuration Patterns

### Pattern 1: Single Role Deployment

Deploy a single role with minimal configuration:

```yaml
open-agent-auth:
  roles:
    agent:
      enabled: true
      issuer: http://localhost:8081
```

### Pattern 2: Multi-Role Deployment

Deploy multiple roles in a single application:

```yaml
open-agent-auth:
  roles:
    authorization-server:
      enabled: true
      issuer: http://localhost:8085
    resource-server:
      enabled: true
      issuer: http://localhost:8086
```

### Pattern 3: Capability Configuration

Configure capabilities independently from roles:

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      token:
        lifetime-seconds: 3600
  roles:
    authorization-server:
      enabled: true
      issuer: http://localhost:8085
```

### Pattern 4: Shared Infrastructure

Share infrastructure across multiple roles:

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: wimse://mycompany.com
    key-management:
      providers:
        local:
          type: in-memory
  roles:
    authorization-server:
      enabled: true
      issuer: https://auth.mycompany.com
    resource-server:
      enabled: true
      issuer: https://resource.mycompany.com
```

---

## Best Practices

### 1. Use Environment Variables

Make your configuration environment-agnostic:

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: ${TRUST_DOMAIN:wimse://default.trust.domain}
  roles:
    authorization-server:
      issuer: ${AUTH_SERVER_URL:http://localhost:8085}
```

### 2. Leverage Defaults

Start with defaults and only override when necessary:

```yaml
# Good: Use defaults for most settings
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      # All other settings use sensible defaults
```

```yaml
# Only override what you need
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      token:
        lifetime-seconds: 7200  # Override only this
```

### 3. Group Related Configuration

Use logical grouping for better readability:

```yaml
open-agent-auth:
  # Infrastructure
  infrastructures:
    trust-domain: wimse://mycompany.com
    key-management: {...}
    jwks: {...}
  
  # Capabilities
  capabilities:
    oauth2-server: {...}
    workload-identity: {...}
  
  # Roles
  roles:
    authorization-server: {...}
    resource-server: {...}
```

### 4. Document Custom Values

Add comments when overriding defaults:

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      token:
        # Extended token lifetime for mobile clients
        lifetime-seconds: 7200
```

### 5. Validate Configuration

Test your configuration before deploying:

```bash
# Validate YAML syntax
yamllint application.yml

# Test endpoint connectivity
curl http://localhost:8085/.well-known/jwks.json
```

---

## Migration Guide

### Migrating from Legacy Configuration

If you're migrating from the old configuration structure:

**Before (Legacy)**:
```yaml
open-agent-auth:
  role: authorization-server
  issuer: http://localhost:8085
  authorization-server:
    par:
      enabled: true
      endpoint: /par
```

**After (Current)**:
```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      par:
        enabled: true
        endpoint: /par
  roles:
    authorization-server:
      enabled: true
      issuer: http://localhost:8085
```

### Key Changes

| Aspect | Legacy | Current |
|--------|--------|---------|
| **Role Selection** | `open-agent-auth.role` | `open-agent-auth.roles.<role-name>.enabled` |
| **Configuration Structure** | Flat hierarchy | Layered (Infrastructure → Capabilities → Roles) |
| **Capability Reuse** | Duplicated per role | Defined once under `capabilities`, composed by roles |
| **Capability Configuration** | Embedded in role | Configured independently under `open-agent-auth.capabilities` |

---

## Troubleshooting

### Common Issues

#### 1. Configuration Not Loading

**Symptoms**: Default values are being used instead of your configuration

**Solutions**:
- Verify YAML syntax is correct
- Check indentation (YAML is indentation-sensitive)
- Ensure the `open-agent-auth` prefix is correct
- Check if the profile is active (if using Spring profiles)

#### 2. Role Not Starting

**Symptoms**: Role is not being initialized

**Solutions**:
- Verify the role is enabled (`roles.<role-name>.enabled: true`)
- Check if required capabilities are enabled under `open-agent-auth.capabilities`
- Ensure the issuer URL is set correctly
- Review logs for initialization errors

#### 3. Capability Not Working

**Symptoms**: Capability features are not available

**Solutions**:
- Verify the capability is enabled under `open-agent-auth.capabilities.<capability-name>.enabled`
- Ensure the corresponding role is also enabled under `open-agent-auth.roles.<role-name>.enabled`
- Ensure required infrastructure (trust domain, keys) is configured
- Review capability-specific logs

### Debug Logging

Enable debug logging for configuration:

```yaml
logging:
  level:
    com.alibaba.openagentauth.spring.autoconfigure.properties: DEBUG
```

---

## Next Steps

- **[Infrastructure Configuration Guide](01-infrastructure-configuration.md)**: Learn how to configure trust domain, key management, JWKS, and service discovery
- **[Capabilities Configuration Guide](02-capabilities-configuration.md)**: Understand how to configure individual capabilities
- **[Roles Configuration Guide](03-roles-configuration.md)**: Learn how to compose roles from capabilities

---

## Additional Resources

- **[Quick Start Guide](../start/01-quick-start.md)**: Get started quickly
- **[User Guide](../start/00-user-guide.md)**: Comprehensive user documentation
- **[Architecture Documentation](../architecture/README.md)**: System architecture and design
- **[API Reference](../api/00-api-overview.md)**: API documentation
