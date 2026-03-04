# Configuration Reference

## Overview

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

## Quick Start Configuration

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

## Infrastructure Configuration

Infrastructure configuration provides the foundational services shared across all roles in the Open Agent Auth framework. This guide explains how to configure trust domains, key management, JWKS (JSON Web Key Sets), and service discovery.

### Configuration Overview

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

## Security Best Practices for Infrastructure

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

## Capabilities Configuration

Capabilities represent reusable functional features in the Open Agent Auth framework. Each capability provides a specific set of functionality that can be composed by roles to create complete, working applications.

### Configuration Overview

Capabilities are configured under `open-agent-auth.capabilities`:

```yaml
open-agent-auth:
  capabilities:
    oauth2-server: {...}
    oauth2-client: {...}
    workload-identity: {...}
    operation-authorization: {...}
    user-authentication: {...}
    audit: {...}
```

### Available Capabilities

| Capability | Description | Typical Use Cases                           |
|------------|-------------|---------------------------------------------|
| **oauth2-server** | OAuth 2.0 authorization server functionality | Authorization Server, Agent User IDP, AS User IDP |
| **oauth2-client** | OAuth 2.0 client functionality | Agent, Resource Server                      |
| **workload-identity** | Workload identity management | Agent IDP, Agent, Resource Server           |
| **operation-authorization** | Fine-grained authorization for agent operations | Agent, Authorization Server                 |
| **user-authentication** | User identity and login | Agent User IDP, AS User IDP                 |
| **audit** | Audit logging for security events | Authorization Server                        |

---

## OAuth 2.0 Server Capability

### Overview

The OAuth 2.0 Server capability provides complete OAuth 2.0 authorization server functionality, including authorization flows, token issuance, and client management. It supports standard OAuth 2.0 flows such as authorization code, implicit, and client credentials.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
      endpoints:
        oauth2:
          authorize: /oauth2/authorize
          token: /oauth2/token
          par: /par
          userinfo: /oauth2/userinfo
          dcr: /oauth2/register
          logout: /oauth2/logout
      token:
        accessTokenExpiry: 3600
        refreshTokenExpiry: 2592000
        idTokenExpiry: 3600
        authorizationCodeExpiry: 600
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether OAuth 2.0 Server capability is enabled | `false` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `oauth2.authorize` | String | Authorization endpoint path | `/oauth2/authorize` |
| `oauth2.token` | String | Token endpoint path | `/oauth2/token` |
| `oauth2.par` | String | PAR endpoint path | `/par` |
| `oauth2.userinfo` | String | Userinfo endpoint path | `/oauth2/userinfo` |
| `oauth2.dcr` | String | DCR endpoint path | `/oauth2/register` |
| `oauth2.logout` | String | Logout endpoint path | `/oauth2/logout` |

#### Token Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `accessTokenExpiry` | Integer | Access token expiry in seconds | `3600` |
| `refreshTokenExpiry` | Integer | Refresh token expiry in seconds | `2592000` |
| `idTokenExpiry` | Integer | ID token expiry in seconds | `3600` |
| `authorizationCodeExpiry` | Integer | Authorization code expiry in seconds | `600` |

#### Auto-Register Clients Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether auto-register clients is enabled | `false` |
| `clients` | List | List of client configurations | Empty list |

#### Client Configuration Properties

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `clientName` | String | Human-readable client name | Yes |
| `clientId` | String | OAuth 2.0 client ID | Yes |
| `clientSecret` | String | OAuth 2.0 client secret | Yes |
| `redirectUris` | List | Allowed redirect URIs | Yes |
| `grantTypes` | List | Allowed grant types | Yes |
| `responseTypes` | List | Allowed response types | Yes |
| `tokenEndpointAuthMethod` | String | Token endpoint auth method | No |
| `scopes` | List | Allowed scopes | Yes |

### Supported Grant Types

| Grant Type | Description |
|------------|-------------|
| `authorization_code` | Authorization code flow (recommended) |
| `implicit` | Implicit flow |
| `client_credentials` | Client credentials flow |
| `refresh_token` | Refresh token flow |

### Supported Response Types

| Response Type | Description |
|---------------|-------------|
| `code` | Authorization code |
| `token` | Access token (implicit flow) |
| `id_token` | ID token (implicit flow) |

### Supported Token Endpoint Auth Methods

| Method | Description |
|--------|-------------|
| `client_secret_basic` | HTTP Basic authentication |
| `client_secret_post` | Client credentials in POST body |
| `private_key_jwt` | JWT-based authentication |
| `none` | Public client (no authentication) |

### Best Practices

1. **Use Authorization Code Flow**: Prefer authorization code flow with PKCE for security
2. **Set Appropriate Token Expiry**: Balance security and user experience
3. **Use HTTPS**: Always use HTTPS in production
4. **Validate Redirect URIs**: Strictly validate redirect URIs to prevent open redirect attacks
5. **Enable PAR**: Use Pushed Authorization Request (PAR) for enhanced security

---

## OAuth 2.0 Client Capability

### Overview

The OAuth 2.0 Client capability enables applications to act as OAuth 2.0 clients and obtain tokens from authorization servers. It provides authentication for protected endpoints and handles OAuth 2.0 authorization flows.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    oauth2-client:
      enabled: true
      authentication:
        enabled: true
        include-paths:
          - /api/**
          - /tools/**
        exclude-paths:
          - /health
          - /public/**
      callback:
        enabled: true
        endpoint: /callback
        client-id: agent-client-id
        client-secret: agent-client-secret
        auto-register: true
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether OAuth 2.0 Client capability is enabled | `false` |

#### Authentication Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether authentication is enabled | `true` |
| `include-paths` | List | Paths requiring authentication | `["/**"]` |
| `exclude-paths` | List | Paths excluded from authentication | `["/login", "/callback", "/public/**", "/oauth2/consent", "/oauth2/authorize", "/.well-known/**"]` |

#### Callback Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether callback is enabled | `false` |
| `endpoint` | String | Callback endpoint path | `/callback` |
| `auto-register` | Boolean | Whether to auto-register client | `false` |

> **Note**: Client credentials (`client-id`, `client-secret`) are now configured at the `oauth2-client` top level, not within `callback`. See [OAuth2 Client Properties](#properties) above.

### Path Matching

The framework supports Ant-style path patterns for path matching:

| Pattern | Description | Example Matches |
|---------|-------------|-----------------|
| `/**` | All paths | All paths |
| `/api/**` | All paths under `/api` | `/api/users`, `/api/posts` |
| `/api/v1/**` | All paths under `/api/v1` | `/api/v1/users`, `/api/v1/posts` |
| `/public/**` | All paths under `/public` | `/public/index.html` |
| `*.html` | All HTML files | `index.html`, `about.html` |

### Best Practices

1. **Use Specific Include Paths**: Be specific about which paths require authentication
2. **Exclude OAuth2 Endpoints**: Default exclude paths already include OAuth2 endpoints, health, and public paths
3. **Secure Client Credentials**: Store client secrets in environment variables
4. **Use Auto-Register**: Enable auto-register for dynamic client registration
5. **Monitor Authentication**: Monitor authentication failures for security

---

## Workload Identity Capability

### Overview

The Workload Identity capability provides workload identity management and token issuance for applications and services. It enables workloads to obtain identity tokens for authentication and authorization within the trust domain.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    workload-identity:
      enabled: true
      endpoints:
        workload:
          revoke: /api/v1/workloads/revoke
          retrieve: /api/v1/workloads/get
          issue: /api/v1/workloads/token/issue
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether Workload Identity capability is enabled | `false` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `workload.revoke` | String | Revoke workload endpoint path | `/api/v1/workloads/revoke` |
| `workload.retrieve` | String | Retrieve workload endpoint path | `/api/v1/workloads/get` |
| `workload.issue` | String | Issue workload token endpoint path | `/api/v1/workloads/token/issue` |

### Workload Identity Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Workload Identity Flow                       │
└─────────────────────────────────────────────────────────────────┘

1. Workload Token Issuance
   └─> POST /api/v1/workloads/token/issue
       └─> Returns Workload Identity Token (WIT)

2. Workload Query
   └─> POST /api/v1/workloads/get
       └─> Returns workload information

3. Workload Revocation
   └─> POST /api/v1/workloads/revoke
       └─> Invalidates workload and tokens
```

### Use Cases

- **Service-to-Service Authentication**: Enable services to authenticate with each other
- **Kubernetes Workloads**: Provide identity to Kubernetes pods and services
- **Microservices**: Enable secure communication between microservices
- **Batch Jobs**: Provide identity to batch jobs and scheduled tasks

### Best Practices

1. **Use Short-Lived Tokens**: Issue tokens with short expiry for security
2. **Implement Rotation**: Regularly rotate workload identities
3. **Audit Usage**: Monitor workload identity usage for security
4. **Secure Endpoints**: Protect workload identity endpoints with authentication
5. **Document Workflows**: Document workload identity creation and usage workflows

---

## Operation Authorization Capability

### Overview

The Operation Authorization capability provides fine-grained authorization for agent operations, including prompt protection, policy evaluation, and binding management. It enables agents to request authorization for specific operations based on policies and user bindings.

### Configuration
```yaml
open-agent-auth:
  capabilities:
    operation-authorization:
      enabled: true
      endpoints:
        policy:
          registry: /api/v1/policies/register
          retrieve: /api/v1/policies/get
          delete: /api/v1/policies/delete
        binding:
          registry: /api/v1/bindings/register
          retrieve: /api/v1/bindings/get
          delete: /api/v1/bindings/delete
      prompt-encryption:
        enabled: true
        encryption-key-id: null
        encryption-algorithm: RSA-OAEP-256
        content-encryption-algorithm: A256GCM
        jwks-consumer: authorization-server
      prompt-protection:
        enabled: true
        encryption-enabled: true
        sanitization-level: MEDIUM
      agent-context:
        default-client: my-agent-client
        default-channel: web
        default-language: zh-CN
        default-platform: my-agent-platform
        default-device-fingerprint: my-device-fingerprint
      authorization:
        require-user-interaction: false
        expiration-seconds: 3600
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether Operation Authorization capability is enabled | `false` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `policy.registry` | String | Policy registry endpoint path | `/api/v1/policies/register` |
| `policy.retrieve` | String | Retrieve policy by ID endpoint path | `/api/v1/policies/get` |
| `policy.delete` | String | Delete policy endpoint path | `/api/v1/policies/delete` |
| `binding.registry` | String | Binding registry endpoint path | `/api/v1/bindings/register` |
| `binding.retrieve` | String | Retrieve binding by ID endpoint path | `/api/v1/bindings/get` |
| `binding.delete` | String | Delete binding endpoint path | `/api/v1/bindings/delete` |

#### Prompt Encryption Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether prompt encryption is enabled | `false` |
| `encryption-key-id` | String | Encryption key ID | `null` |
| `encryption-algorithm` | String | Key encryption algorithm | `RSA-OAEP-256` |
| `content-encryption-algorithm` | String | Content encryption algorithm | `A256GCM` |
| `jwks-consumer` | String | JWKS consumer name for fetching public key | Optional |

#### Prompt Protection Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether prompt protection is enabled | `true` |
| `encryption-enabled` | Boolean | Whether encryption is enabled | `true` |
| `sanitization-level` | String | Sanitization level | `MEDIUM` |

#### Agent Context Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `default-client` | String | Default agent client identifier | `null` |
| `default-channel` | String | Default channel type | `web` |
| `default-language` | String | Default language preference | `zh-CN` |
| `default-platform` | String | Default platform identifier | `null` |
| `default-device-fingerprint` | String | Default device fingerprint | `null` |

> **Note**: OAuth 2.0 client credentials (`client-id`, `client-secret`) are now configured at the `capabilities.oauth2-client` top level, shared across all OAuth 2.0 flows. The `oauth2-client` sub-section has been removed from `operation-authorization`.

#### Authorization Behavior Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `require-user-interaction` | Boolean | Whether user interaction is required | `false` |
| `expiration-seconds` | Integer | Expiration time in seconds | `3600` |

### Sanitization Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `LOW` | Minimal sanitization | Development, testing |
| `MEDIUM` | Standard sanitization | Recommended for most cases |
| `HIGH` | Strict sanitization | High-security environments |

### Supported Encryption Algorithms

| Algorithm | Type | Description |
|-----------|------|-------------|
| `RSA-OAEP-256` | Key encryption | RSA with OAEP padding and SHA-256 |
| `RSA-OAEP` | Key encryption | RSA with OAEP padding and SHA-1 |
| `ECDH-ES` | Key encryption | Elliptic Curve Diffie-Hellman |

| Algorithm | Type | Description |
|-----------|------|-------------|
| `A256GCM` | Content encryption | AES-GCM with 256-bit key |
| `A128GCM` | Content encryption | AES-GCM with 128-bit key |
| `A256CBC-HS512` | Content encryption | AES-CBC with HMAC-SHA-512 |

### Operation Authorization Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              Operation Authorization Flow                        │
└─────────────────────────────────────────────────────────────────┘

1. Agent Request
   └─> Agent requests authorization for operation
       └─> Prompt is sanitized and encrypted

2. Authorization Request
   └─> POST /oauth2/authorize
       └─> Includes workload identity, operation details

3. Policy Evaluation
   └─> GET /api/v1/policies
       └─> Retrieves applicable policies

4. Binding Check
   └─> GET /api/v1/bindings/{bindingInstanceId}
       └─> Checks user bindings and permissions

5. User Approval (if required)
   └─> User approves or denies operation
       └─> Interactive consent flow

6. Token Issuance
   └─> Agent Operation Authorization Token (AOAT) issued
       └─> Token includes operation permissions

7. Operation Execution
   └─> Agent executes operation with AOAT
       └─> Resource server validates token
```

### Best Practices

1. **Enable Prompt Encryption**: Always encrypt prompts in production
2. **Use Appropriate Sanitization**: Choose sanitization level based on security requirements
3. **Require User Interaction**: Enable for sensitive operations
4. **Set Short Token Expiry**: Use short-lived tokens for security
5. **Monitor Authorizations**: Audit authorization requests and decisions

---

## User Authentication Capability

### Overview

The User Authentication capability provides user identity authentication including login page, user registry, and session management. It supports multiple user registry types and customizable login pages.

### Configuration
```yaml
open-agent-auth:
  capabilities:
    user-authentication:
      enabled: true
      loginPage:
        enabled: true
        pageTitle: Identity Provider - Login
        title: Identity Provider
        subtitle: Please sign in to continue
        usernameLabel: Username
        passwordLabel: Password
        buttonText: Sign In
        showDemoUsers: false
        demoUsers: ""
        footerText: © 2024 My Company
        template: classpath:/templates/login.html
      userRegistry:
        enabled: true
        type: in-memory
        presetUsers:
          - username: admin
            password: admin123
            subject: user_admin_001
            email: admin@example.com
            name: Admin User
          - username: user
            password: user123
            subject: user_001
            email: user@example.com
            name: Regular User
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether User Authentication capability is enabled | `false` |

#### Login Page Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether default login page is enabled | `true` |
| `pageTitle` | String | Page title displayed in browser tab | `Identity Provider - Login` |
| `title` | String | Main title displayed on login page | `Identity Provider` |
| `subtitle` | String | Subtitle displayed below main title | `Please sign in to continue` |
| `usernameLabel` | String | Label for username field | `Username` |
| `passwordLabel` | String | Label for password field | `Password` |
| `buttonText` | String | Text for login button | `Sign In` |
| `showDemoUsers` | Boolean | Whether to display demo users | `false` |
| `demoUsers` | String | Demo users in format "username:password;..." | Empty string |
| `footerText` | String | Footer text displayed at bottom | Empty string |
| `template` | String | Login page template path | `classpath:/templates/login.html` |

#### User Registry Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether user registry is enabled | `true` |
| `type` | String | User registry type | `in-memory` |
| `presetUsers` | List | List of preset users | Empty list |

#### Preset User Properties

| Property | Type | Description | Required |
|----------|------|-------------|----------|
| `username` | String | Username for authentication | Yes |
| `password` | String | Password for authentication | Yes |
| `subject` | String | Subject identifier | No |
| `email` | String | User email address | No |
| `name` | String | User display name | No |

### User Registry Types

| Type | Description | Use Case |
|------|-------------|----------|
| `in-memory` | Users stored in memory | Development, testing |

### Custom Login Page

To provide a custom login page:

1. Create a custom template at `classpath:/templates/custom-login.html`
2. Configure the template path:

```yaml
open-agent-auth:
  capabilities:
    user-authentication:
      loginPage:
        template: classpath:/templates/custom-login.html
```

### Best Practices

1. **Secure Passwords**: Hash passwords using strong algorithms (bcrypt, Argon2)
2. **Customize Login Page**: Customize login page for branding
3. **Disable Demo Users**: Never enable demo users in production
4. **Implement MFA**: Consider multi-factor authentication for enhanced security

---

## Capability Composition Examples

Capabilities are designed to be composed by roles to create complete applications. Here are some common compositions:

### Authorization Server Composition

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      enabled: true
    operation-authorization:
      enabled: true
    workload-identity:
      enabled: true
  roles:
    authorization-server:
      enabled: true
      capabilities:
        - oauth2-server
        - operation-authorization
        - workload-identity
```

### Agent Composition

```yaml
open-agent-auth:
  capabilities:
    oauth2-client:
      enabled: true
    operation-authorization:
      enabled: true
  roles:
    agent:
      enabled: true
      capabilities:
        - oauth2-client
        - operation-authorization
```

### Agent IDP Composition

```yaml
open-agent-auth:
  capabilities:
    workload-identity:
      enabled: true
  roles:
    agent-idp:
      enabled: true
      capabilities:
        - workload-identity
```

---

## Audit Capability

### Overview

The Audit capability provides audit logging functionality for tracking security events, user actions, agent operations, and system activities across the Idem Agent Auth framework.

### Configuration

```yaml
open-agent-auth:
  capabilities:
    audit:
      enabled: true
      provider: logging
      endpoints:
        event:
          retrieve: /api/v1/audit/events/get
          list: /api/v1/audit/events/list
```

### Properties

#### Main Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `enabled` | Boolean | Whether Audit capability is enabled | `false` |

#### Provider Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `provider` | String | Audit provider implementation | `logging` |

#### Endpoint Properties

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `event.retrieve` | String | Retrieve audit event by ID endpoint path | `/api/v1/audit/events/get` |
| `event.list` | String | List audit events endpoint path | `/api/v1/audit/events/list` |

### Supported Providers

| Provider | Description | Use Case |
|----------|-------------|----------|
| `logging` | Logs audit events to application logs | Development, testing |

### Best Practices

1. **Enable in Production**: Always enable audit logging in production deployments
2. **Monitor Audit Events**: Monitor audit events for security incidents
3. **Secure Audit Logs**: Protect audit logs from unauthorized access
4. **Regular Backup**: Regularly backup audit logs for compliance

---

## Roles Configuration

Roles represent specific functional instances in the Open Agent Auth framework. Each role composes one or more capabilities to create a complete, working application. This guide explains how to configure roles and how they interact with capabilities.

### Configuration Overview

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
      access-token-expiry: 3600
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

### General Configuration Best Practices

#### 1. Use Environment Variables

Make your configuration environment-agnostic:

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: ${TRUST_DOMAIN:wimse://default.trust.domain}
  roles:
    authorization-server:
      issuer: ${AUTH_SERVER_URL:http://localhost:8085}
```

#### 2. Leverage Defaults

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
        access-token-expiry: 7200  # Override only this
```

#### 3. Group Related Configuration

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

#### 4. Document Custom Values

Add comments when overriding defaults:

```yaml
open-agent-auth:
  capabilities:
    oauth2-server:
      token:
        # Extended token lifetime for mobile clients
        access-token-expiry: 7200
```

#### 5. Validate Configuration

Test your configuration before deploying:

```bash
# Validate YAML syntax
yamllint application.yml

# Test endpoint connectivity
curl http://localhost:8085/.well-known/jwks.json
```

### Infrastructure Best Practices

#### 1. Trust Domain

- **Use HTTPS**: Always use HTTPS for production trust domains
- **Environment Isolation**: Use separate trust domains for different environments
- **Consistent Naming**: Follow a consistent naming convention

#### 2. Key Management

- **Never Commit Keys**: Never commit private keys to version control
- **Use Environment Variables**: Store sensitive values in environment variables
- **Regular Rotation**: Implement regular key rotation policies
- **Audit Logging**: Enable audit logging for key access

#### 3. JWKS

- **HTTPS Required**: Always use HTTPS for JWKS endpoints in production
- **Appropriate Caching**: Balance performance and key rotation speed
- **Issuer Validation**: Always validate issuer claims
- **Monitor Rotation**: Monitor key rotation and cache refresh

#### 4. Service Discovery

- **Secure Communication**: Use HTTPS for all service communication
- **Environment Variables**: Use environment variables for service URLs
- **Health Checks**: Implement health checks for discovered services
- **Fallback Mechanisms**: Configure fallback URLs for critical services

### Capabilities Best Practices

#### 1. Enable Only Needed Capabilities

Only enable the capabilities that your role actually needs:

```yaml
# Good: Enable only needed capabilities
capabilities:
  oauth2-server:
    enabled: true
  # Other capabilities remain disabled
```

```yaml
# Bad: Enable all capabilities unnecessarily
capabilities:
  oauth2-server:
    enabled: true
  oauth2-client:
    enabled: true  # Not needed for authorization server
  workload-identity:
    enabled: true
  # ...
```

#### 2. Use Role-Specific Overrides

Override capability configuration at the role level:

```yaml
capabilities:
  oauth2-server:
    enabled: true
    token:
      access-token-expiry: 3600
roles:
  authorization-server:
    enabled: true
    capabilities:
      - oauth2-server
    config:
      oauth2-server:
        token:
          access-token-expiry: 7200  # Role-specific override
```

#### 3. Secure Sensitive Configuration

Use environment variables for sensitive configuration:

```yaml
capabilities:
  oauth2-client:
    client-id: ${CLIENT_ID}
    client-secret: ${CLIENT_SECRET}
```

#### 4. Document Custom Configuration

Add comments when overriding defaults:

```yaml
capabilities:
  oauth2-server:
    token:
      # Extended token lifetime for mobile clients
      access-token-expiry: 7200
```

#### 5. Test Capability Configuration

Test your configuration before deploying:

```bash
# Test OAuth 2.0 endpoints
curl http://localhost:8085/oauth2/authorize

# Test workload identity endpoints
curl http://localhost:8082/api/v1/workloads/token/issue

# Test audit endpoints
curl http://localhost:8085/api/v1/audit/events
```

### Roles Best Practices

#### 1. Use Descriptive Role Names

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

#### 2. Enable Only Needed Roles

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

#### 3. Document Role Purpose

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

#### 4. Test Role Configuration

Test your configuration before deploying:

```bash
# Test role endpoints
curl https://agent.mycompany.com/health
curl https://agent-idp.mycompany.com/api/v1/workloads/create
curl https://auth-server.mycompany.com/oauth2/authorize
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

#### 4. Key Provider Not Found

**Symptoms**: Application fails to start with "Key provider not found" error

**Solutions**:
- Verify provider name matches in both `providers` and `keys` sections
- Check provider type is valid (`in-memory`)
- Ensure provider configuration is complete

#### 5. JWKS Endpoint Not Accessible

**Symptoms**: Token verification fails with "Unable to fetch JWKS" error

**Solutions**:
- Verify JWKS endpoint URL is correct
- Check network connectivity
- Ensure provider service is running
- Verify firewall rules allow access

#### 6. Service Discovery Fails

**Symptoms**: Services cannot be discovered or connected to

**Solutions**:
- Verify service definitions are correct
- Check service URLs are accessible
- Ensure service discovery is enabled
- Verify service discovery type is configured correctly

#### 7. Capability Not Enabled

**Symptoms**: Capability features are not available

**Solutions**:
- Verify the capability is enabled in `capabilities.<capability-name>.enabled`
- Check if the capability is listed in the role's `capabilities` array
- Ensure required infrastructure (trust domain, keys) is configured

#### 8. Endpoint Not Found

**Symptoms**: 404 errors when calling capability endpoints

**Solutions**:
- Verify the endpoint path is correct
- Check if the capability is enabled
- Ensure the service is running
- Review the endpoint configuration

#### 9. Authentication Fails

**Symptoms**: Token verification fails

**Solutions**:
- Verify OAuth 2.0 client credentials are correct
- Check if the authorization server is accessible
- Ensure JWKS endpoint is configured correctly
- Review token expiration settings

#### 10. Capability Configuration Not Taking Effect

**Symptoms**: Capability configuration is not being applied as expected

**Solutions**:
- Verify the capability is configured under `open-agent-auth.capabilities.<capability-name>`
- Ensure property names match the capability's expected property structure
- Check for YAML indentation issues

### Debug Logging

Enable debug logging for configuration:

```yaml
logging:
  level:
    com.alibaba.openagentauth.spring.autoconfigure.properties: DEBUG
```

Enable debug logging for infrastructure:

```yaml
logging:
  level:
    com.alibaba.openagentauth: DEBUG
```

Enable debug logging for capabilities:

```yaml
logging:
  level:
    com.alibaba.openagentauth.core.capabilities: DEBUG
    com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities: DEBUG
```

Enable debug logging for roles:

```yaml
logging:
  level:
    com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties: DEBUG
    com.alibaba.openagentauth.spring.autoconfigure: DEBUG
```
