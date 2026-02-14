# Infrastructure Configuration Guide

## Introduction

Infrastructure configuration provides the foundational services shared across all roles in the Open Agent Auth framework. This guide explains how to configure trust domains, key management, JWKS (JSON Web Key Sets), and service discovery.

## Configuration Overview

The infrastructure configuration is organized under `open-agent-auth.infrastructures`:

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: wimse://default.trust.domain
    key-management: {...}
    jwks: {...}
    service-discovery: {...}
```

### Infrastructure Components

| Component | Purpose | Key Features |
|-----------|---------|--------------|
| **Trust Domain** | Defines security boundary for workload identities | WIMSE format, trust establishment |
| **Key Management** | Manages cryptographic keys | Multiple providers (in-memory), key rotation |
| **JWKS** | Public key distribution and consumption | Provider/consumer pattern, caching |
| **Service Discovery** | Dynamic service location | Static support |

---

## Trust Domain Configuration

### Overview

The trust domain defines the security boundary within which workloads can verify each other's identities. All workloads within the same trust domain can verify each other's identities without additional configuration.

### Configuration

```yaml
open-agent-auth:
    infrastructures:
      trust-domain: wimse://mycompany.com
```

### Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `trust-domain` | String | Trust domain URI in WIMSE format | `wimse://default.trust.domain` |

### WIMSE Format

The trust domain follows the WIMSE (Workload Identity Management for Service Ecosystems) specification format:

```
wimse://<domain-name>
```

**Examples**:

- `wimse://default.trust.domain` - Default trust domain
- `wimse://mycompany.com` - Organization trust domain
- `wimse://production.mycompany.com` - Environment-specific trust domain

### Best Practices

- **Use Domain-Based Trust**: Match your trust domain to your organization's domain
- **Environment Separation**: Use different trust domains for different environments (dev, staging, production)
- **Consistent Naming**: Follow a consistent naming convention across all services

**Example**:

```yaml
# Production environment
open-agent-auth:
    infrastructures:
      trust-domain: wimse://production.mycompany.com

---
# Development environment
spring:
  profiles: development

open-agent-auth:
    infrastructures:
      trust-domain: wimse://dev.mycompany.com
```

---

## Key Management Configuration

### Overview

Key management configuration defines how cryptographic keys are managed, including key providers and key definitions. This enables the framework to support various key storage mechanisms from simple in-memory storage to enterprise-grade key management systems.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Key Management Architecture                  │
└─────────────────────────────────────────────────────────────────┘

Key Providers (Storage)
└── in-memory      → Keys stored in application memory

Key Definitions (Usage)
├── key-id         → Unique identifier
├── algorithm      → Cryptographic algorithm (RS256, ES256, etc.)
├── provider       → Which provider manages the key
└── jwks-consumer  → For verification keys from remote sources
```

### Configuration

```yaml
open-agent-auth:
    infrastructures:
      key-management:
        providers:
          local:
            type: in-memory
        keys:
          wit-signing-key:
            key-id: wit-signing-key-001
            algorithm: ES256
            provider: local
          aoat-signing-key:
            key-id: aoat-signing-key-001
            algorithm: RS256
            provider: local
          wit-verification:
            key-id: agent-idp-verification-key
            algorithm: ES256
            jwks-consumer: agent-idp
```

### Key Provider Types

#### In-Memory Provider

The in-memory provider stores keys in application memory. This is the simplest and fastest option but keys are lost on application restart.

**Configuration Example**:

```yaml
open-agent-auth:
  infrastructures:
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        signing-key:
          key-id: signing-key-001
          algorithm: RS256
          provider: local
```

**Characteristics**:
- Keys are stored in memory only
- Keys are lost on application restart
- No external dependencies
- Suitable for development and testing

### Key Definitions

#### Key Properties

| Property | Type | Description | Default | Required |
|----------|------|-------------|---------|----------|
| `key-id` | String | Unique key identifier | `null` | Yes |
| `algorithm` | String | Cryptographic algorithm | `null` | Yes |
| `provider` | String | Key provider name | `local` | No |
| `jwks-consumer` | String | JWKS consumer for verification keys | `null` | No |

#### Supported Algorithms

| Algorithm | Type | Key Size | Use Case |
|-----------|------|----------|----------|
| **RS256** | RSA | 2048+ bits | General purpose signing |
| **RS384** | RSA | 3072+ bits | Higher security signing |
| **RS512** | RSA | 4096+ bits | Maximum security signing |
| **ES256** | ECDSA | P-256 | Compact signatures |
| **ES384** | ECDSA | P-384 | Higher security ECDSA |
| **ES512** | ECDSA | P-521 | Maximum security ECDSA |
| **PS256** | RSA-PSS | 2048+ bits | Modern RSA signing |
| **PS384** | RSA-PSS | 3072+ bits | Higher security RSA-PSS |
| **PS512** | RSA-PSS | 4096+ bits | Maximum security RSA-PSS |

#### Key Types

**Signing Keys** (used to sign tokens):

```yaml
keys:
  wit-signing-key:
    key-id: wit-signing-key-001
    algorithm: ES256
    provider: local
```

**Verification Keys** (used to verify tokens from other services):

```yaml
keys:
  wit-verification:
    key-id: wit-signing-key
    algorithm: ES256
    jwks-consumer: agent-idp  # Fetches public key from agent-idp's JWKS consumer
```

### Configuration Examples

#### Example 1: Development Configuration

```yaml
open-agent-auth:
  infrastructures:
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        wit-signing:
          key-id: wit-signing-key
          algorithm: ES256
          provider: local
        aoat-signing:
          key-id: aoat-signing-key
          algorithm: RS256
          provider: local
```

#### Example 2: Production Configuration

```yaml
open-agent-auth:
  infrastructures:
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        # Signing keys (stored locally, contain private keys)
        aoat-signing:
          key-id: aoat-signing-key
          algorithm: RS256
          provider: local
        jwe-decryption:
          key-id: jwe-encryption-key-001
          algorithm: RS256
          provider: local
        
        # Verification keys (public keys fetched from JWKS)
        wit-verification:
          key-id: wit-signing-key
          algorithm: ES256
          jwks-consumer: agent-idp
```

### Best Practices

1. **Use Appropriate Providers**:
   - Development: `in-memory` for simplicity
   - Production: `in-memory` with proper key management practices

2. **Key Rotation**:
   - Implement regular key rotation
   - Support multiple active keys during rotation
   - Use version numbers in key IDs

3. **Algorithm Selection**:
   - Use ES256 for compact signatures (mobile, IoT)
   - Use RS256 for broad compatibility
   - Use RSA-OAEP-256 for encryption

4. **Security**:
   - Never commit private keys to version control
   - Use environment variables for sensitive configuration
   - Set proper file permissions (600 for key files)
   - Store keys in secure, restricted directories

---

## JWKS Configuration

### Overview

JWKS (JSON Web Key Set) configuration manages the distribution and consumption of public keys for JWT signature verification. The framework supports both providing public keys (for token issuance) and consuming public keys from other services (for token verification).

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       JWKS Architecture                         │
└─────────────────────────────────────────────────────────────────┘

Provider (Exposes Public Keys)
├── Endpoint: /.well-known/jwks.json
├── Caching: Cache-Control headers
└── Standards: RFC 7517

Consumers (Fetch Public Keys)
├── Fetch: Periodic refresh from remote endpoints
├── Cache: In-memory caching for performance
└── Verify: JWT signature validation
```

### Configuration

```yaml
open-agent-auth:
  infrastructures:
    jwks:
      provider:
        enabled: true
        path: /.well-known/jwks.json
        cache-duration-seconds: 300
        cache-headers-enabled: true
      consumers:
        agent-idp:
          enabled: true
          jwks-endpoint: http://agent-idp:8082/.well-known/jwks.json
          issuer: http://agent-idp:8082
        authorization-server:
          enabled: true
          jwks-endpoint: http://auth-server:8085/.well-known/jwks.json
          issuer: http://auth-server:8085
```

### JWKS Provider Configuration

The JWKS provider exposes your service's public keys through a standard JWKS endpoint.

#### Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether JWKS provider is enabled | `true` |
| `path` | String | JWKS endpoint path | `/.well-known/jwks.json` |
| `cache-duration-seconds` | Integer | Cache duration in seconds | `300` |
| `cache-headers-enabled` | Boolean | Whether to include cache headers | `true` |

#### Configuration Example

```yaml
open-agent-auth:
  infrastructures:
    jwks:
      provider:
        enabled: true
        path: /.well-known/jwks.json
        cache-duration-seconds: 300
        cache-headers-enabled: true
```

#### Best Practices

- **Use Standard Path**: Keep the default `/.well-known/jwks.json` for compatibility
- **Appropriate Caching**: Balance between performance and key rotation speed
  - 300 seconds (5 minutes) - Recommended for most cases
  - 60 seconds (1 minute) - Fast key rotation
  - 3600 seconds (1 hour) - Slow key rotation, high performance
- **Enable Cache Headers**: Reduces server load and improves performance

### JWKS Consumer Configuration

JWKS consumers fetch public keys from external services for token verification.

#### Properties

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `enabled` | Boolean | Whether this consumer is enabled | No |
| `jwks-endpoint` | String | URL of the JWKS endpoint | No* |
| `issuer` | String | Issuer URL for token validation | No* |

*Note: At least one of `jwks-endpoint` or `issuer` must be configured. If only one is provided, the other will be automatically derived.

#### Configuration Example

```yaml
open-agent-auth:
  infrastructures:
    jwks:
      consumers:
        agent-idp:
          enabled: true
          jwks-endpoint: http://agent-idp:8082/.well-known/jwks.json
          issuer: http://agent-idp:8082
        agent-user-idp:
          enabled: true
          jwks-endpoint: http://agent-user-idp:8083/.well-known/jwks.json
          issuer: http://agent-user-idp:8083
        authorization-server:
          enabled: true
          jwks-endpoint: http://auth-server:8085/.well-known/jwks.json
          issuer: http://auth-server:8085
```

#### Consumer Behavior

1. **Initial Fetch**: Fetches JWKS from the endpoint on startup
2. **Caching**: Caches public keys in memory for performance
3. **Refresh**: Periodically refreshes the JWKS (configurable)
4. **Validation**: Validates JWT signatures using cached keys
5. **Issuer Verification**: Verifies the `iss` claim matches configured issuer

#### Best Practices

- **Unique Consumer Names**: Use descriptive names for each consumer
- **HTTPS in Production**: Always use HTTPS for JWKS endpoints in production
- **Issuer Matching**: Ensure issuer URL matches exactly with token's `iss` claim
- **Error Handling**: Configure appropriate timeout and retry policies

### Complete JWKS Configuration Example

```yaml
open-agent-auth:
  infrastructures:
    jwks:
      # Expose our public keys
      provider:
        enabled: true
        path: /.well-known/jwks.json
        cache-duration-seconds: 300
        cache-headers-enabled: true
      
      # Consume public keys from other services
      consumers:
        # Verify WITs from Agent IDP
        agent-idp:
          enabled: true
          jwks-endpoint: http://agent-idp:8082/.well-known/jwks.json
          issuer: http://agent-idp:8082
        
        # Verify ID Tokens from Agent User IDP
        agent-user-idp:
          enabled: true
          jwks-endpoint: http://agent-user-idp:8083/.well-known/jwks.json
          issuer: http://agent-user-idp:8083
        
        # Verify AOATs from Authorization Server
        authorization-server:
          enabled: true
          jwks-endpoint: http://auth-server:8085/.well-known/jwks.json
          issuer: http://auth-server:8085
```

### Integration with Key Management

JWKS provider automatically publishes keys defined in key management:

```yaml
open-agent-auth:
  infrastructures:
    key-management:
      keys:
        wit-signing:
          key-id: wit-signing-001
          algorithm: ES256
          provider: local
      # ↑ This key will be published in JWKS endpoint
    jwks:
      provider:
        enabled: true
        path: /.well-known/jwks.json
```

### Troubleshooting

#### Issue: JWKS Endpoint Returns 404

**Possible Causes**:
- Provider is disabled
- Path is misconfigured
- Service is not running

**Solutions**:
```yaml
# Check provider configuration
open-agent-auth:
  infrastructures:
    jwks:
      provider:
        enabled: true  # Must be true
        path: /.well-known/jwks.json  # Check path
```

#### Issue: Token Verification Fails

**Possible Causes**:
- JWKS endpoint URL is incorrect
- Issuer URL doesn't match token's `iss` claim
- Key is not yet in JWKS (key rotation in progress)

**Solutions**:
```yaml
# Verify consumer configuration
open-agent-auth:
  infrastructures:
    jwks:
      consumers:
        external-idp:
          enabled: true
          jwks-endpoint: https://external-idp/.well-known/jwks.json  # Verify URL
          issuer: https://external-idp  # Must match token's iss claim
```

---

## Service Discovery Configuration

### Overview

Service discovery enables automatic discovery and connection to services within the trust domain. This is particularly useful in microservice environments where service instances may be dynamically scaled or relocated.

### Configuration

```yaml
open-agent-auth:
  infrastructures:
    service-discovery:
      enabled: true
      type: static
      services:
        authorization-server:
          base-url: http://localhost:8085
          endpoints:
            authorize: /oauth2/authorize
            token: /oauth2/token
            jwks: /.well-known/jwks.json
        agent-idp:
          base-url: http://localhost:8082
          endpoints:
            workload.token-issue: /api/v1/workloads/token/issue
```

### Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether service discovery is enabled | `true` |
| `type` | String | Service discovery type | `static` |
| `services` | Map | Service definitions | Empty map |

### Service Discovery Types

| Type | Description | Use Case |
|------|-------------|----------|
| `static` | Static configuration-based discovery | Simple deployments, development |
| `consul` | Consul-based service discovery | Dynamic microservice environments |
| `eureka` | Netflix Eureka-based service discovery | Spring Cloud ecosystems |

### Static Service Discovery

#### Configuration

```yaml
open-agent-auth:
  infrastructures:
    service-discovery:
      enabled: true
      type: static
      services:
        authorization-server:
          base-url: http://localhost:8085
          endpoints:
            authorize: /oauth2/authorize
            token: /oauth2/token
            policy.registry: /api/v1/policies
        resource-server:
          base-url: http://localhost:8086
          endpoints:
            products: /api/shopping/products
            orders: /api/shopping/orders
```

#### Service Definition Properties

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `base-url` | String | Base URL of the service | Yes |
| `endpoints` | Map | Endpoint paths | No |

### Best Practices

1. **Environment-Specific Configuration**:
   ```yaml
   # Development
   open-agent-auth:
     infrastructures:
       service-discovery:
         services:
           authorization-server:
             base-url: http://localhost:8085
   
   ---
   # Production
   spring:
     profiles: production
   
   open-agent-auth:
     infrastructures:
       service-discovery:
         services:
           authorization-server:
             base-url: https://auth.production.mycompany.com
   ```

2. **Use Environment Variables**:
   ```yaml
   open-agent-auth:
     infrastructures:
       service-discovery:
         services:
           authorization-server:
             base-url: ${AUTH_SERVER_URL:http://localhost:8085}
   ```

3. **Logical Grouping**:
   ```yaml
   services:
     # Identity providers
     agent-idp:
       base-url: http://agent-idp:8082
     agent-user-idp:
       base-url: http://agent-user-idp:8083
     
     # Authorization services
     authorization-server:
       base-url: http://auth-server:8085
     
     # Resource services
     resource-server:
       base-url: http://resource-server:8086
   ```

---

## Complete Infrastructure Configuration Example

### Production Configuration

```yaml
open-agent-auth:
  infrastructures:
    # Trust Domain
    trust-domain: wimse://production.mycompany.com
    
    # Key Management
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        # Signing keys (stored locally, contain private keys)
        aoat-signing:
          key-id: aoat-signing-key
          algorithm: RS256
          provider: local
        jwe-decryption:
          key-id: jwe-encryption-key-001
          algorithm: RS256
          provider: local
        
        # Verification keys (public keys fetched from JWKS)
        wit-verification:
          key-id: wit-signing-key
          algorithm: ES256
          jwks-consumer: agent-idp
    
    # JWKS
    jwks:
      provider:
        enabled: true
        path: /.well-known/jwks.json
        cache-duration-seconds: 300
        cache-headers-enabled: true
      consumers:
        agent-idp:
          enabled: true
          jwks-endpoint: https://agent-idp.production.mycompany.com/.well-known/jwks.json
          issuer: https://agent-idp.production.mycompany.com
        agent-user-idp:
          enabled: true
          jwks-endpoint: https://agent-user-idp.production.mycompany.com/.well-known/jwks.json
          issuer: https://agent-user-idp.production.mycompany.com
    
    # Service Discovery
    service-discovery:
      enabled: true
      type: static
      services:
        authorization-server:
          base-url: https://auth-server.production.mycompany.com
        agent-idp:
          base-url: https://agent-idp.production.mycompany.com
```

### Development Configuration

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: wimse://dev.mycompany.com
    
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        wit-signing:
          key-id: wit-signing-key
          algorithm: ES256
          provider: local
        aoat-signing:
          key-id: aoat-signing-key
          algorithm: RS256
          provider: local
    
    jwks:
      provider:
        enabled: true
        path: /.well-known/jwks.json
        cache-duration-seconds: 60
        cache-headers-enabled: true
      consumers:
        agent-idp:
          enabled: true
          jwks-endpoint: http://localhost:8082/.well-known/jwks.json
          issuer: http://localhost:8082
    
    service-discovery:
      enabled: true
      type: static
      services:
        authorization-server:
          base-url: http://localhost:8085
        agent-idp:
          base-url: http://localhost:8082
        resource-server:
          base-url: http://localhost:8086
```

---

## Security Best Practices

### 1. Trust Domain

- **Use HTTPS**: Always use HTTPS for production trust domains
- **Environment Isolation**: Use separate trust domains for different environments
- **Consistent Naming**: Follow a consistent naming convention

### 2. Key Management

- **Never Commit Keys**: Never commit private keys to version control
- **Use Environment Variables**: Store sensitive values in environment variables
- **Regular Rotation**: Implement regular key rotation policies
- **Audit Logging**: Enable audit logging for key access

### 3. JWKS

- **HTTPS Required**: Always use HTTPS for JWKS endpoints in production
- **Appropriate Caching**: Balance performance and key rotation speed
- **Issuer Validation**: Always validate issuer claims
- **Monitor Rotation**: Monitor key rotation and cache refresh

### 4. Service Discovery

- **Secure Communication**: Use HTTPS for all service communication
- **Environment Variables**: Use environment variables for service URLs
- **Health Checks**: Implement health checks for discovered services
- **Fallback Mechanisms**: Configure fallback URLs for critical services

---

## Troubleshooting

### Common Issues

#### 1. Key Provider Not Found

**Symptoms**: Application fails to start with "Key provider not found" error

**Solutions**:
- Verify provider name matches in both `providers` and `keys` sections
- Check provider type is valid (`in-memory`)
- Ensure provider configuration is complete

#### 2. JWKS Endpoint Not Accessible

**Symptoms**: Token verification fails with "Unable to fetch JWKS" error

**Solutions**:
- Verify JWKS endpoint URL is correct
- Check network connectivity
- Ensure provider service is running
- Verify firewall rules allow access

#### 3. Service Discovery Fails

**Symptoms**: Services cannot be discovered or connected to

**Solutions**:
- Verify service definitions are correct
- Check service URLs are accessible
- Ensure service discovery is enabled
- Verify service discovery type is configured correctly

### Debug Logging

Enable debug logging for infrastructure:

```yaml
logging:
  level:
    com.alibaba.openagentauth: DEBUG
```

---

## Next Steps

- **[Capabilities Configuration Guide](02-capabilities-configuration.md)**: Learn how to configure individual capabilities
- **[Roles Configuration Guide](03-roles-configuration.md)**: Learn how to compose roles from capabilities

---

## Additional Resources

- **[Configuration Overview](00-configuration-overview.md)**: Introduction to configuration architecture
- **[RFC 7517 - JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)**: JWKS specification
- **[WIMSE Specification](https://example.com/wimse)**: Workload Identity Management specification
