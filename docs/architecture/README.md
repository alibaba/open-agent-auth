# Architecture Documentation

This directory contains comprehensive documentation about the Open Agent Auth framework's architecture, design principles, and implementation details.

## Core Concepts

### Tokens
- [Token Reference](token/README.md) - Comprehensive overview of all token types (ID Token, Workload Identity Token, Workload Proof Token, PAR-JWT, Verifiable Credential, Agent Operation Authorization Token), their structures, and relationships

### Identity & Workload
- [Identity and Workload Management](identity/README.md) - User identity authentication, virtual workload creation, and workload lifecycle management

### Authorization
- [Authorization Flow](authorization/README.md) - Complete authorization flow including PAR, user consent, token issuance, and five-layer verification

## Protocols

- [MCP Protocol Adapter](protocol/mcp/README.md) - Model Context Protocol integration and adapter implementation

## Security

- [Security and Audit](security/README.md) - Security mechanisms, audit logging, and compliance features

## Integration

- [Spring Boot Integration](integration/spring-boot-integration.md) - Spring Boot starter configuration and integration guide

## Document Structure

The architecture documentation is organized by topic:

- **overview/** - System architecture overview and diagrams
- **tokens/** - Token design and structure
- **protocols/** - Protocol implementations (OAuth 2.0, OIDC, WIMSE, MCP)
- **authorization/** - Authorization flows and mechanisms
- **security/** - Security features and audit logging
- **identity/** - Identity and workload management
- **integration/** - Framework integration guides

## Related Documentation

- [API Documentation](../api/) - API reference and usage guide
- [User Guides](../guide/) - User guides and tutorials
- [Standards](../standard/) - Protocol standards and specifications

## Version History

- **v2.0.0** (2026-02-09) - Reorganized documentation structure by topic for better maintainability
- **v1.0.0** - Initial architecture documentation

## Contributing

When contributing to the architecture documentation:

1. Keep content focused on architecture and design
2. Use clear, concise language
3. Include diagrams where helpful (Mermaid syntax preferred)
4. Provide code examples to illustrate concepts
5. Update this README when adding new documents

---

## Key Resolution SPI

### Overview

The KeyResolver SPI provides a pluggable key resolution mechanism that decouples key acquisition logic from business code. This architecture allows for flexible key sourcing from multiple providers (local KeyStore, remote JWKS endpoints, custom sources) while maintaining a unified resolution strategy.

### Core Interfaces

#### KeyResolver
The SPI interface that defines the contract for key resolution implementations:

```java
public interface KeyResolver {
    /**
     * Determines if this resolver can handle the given key definition
     */
    boolean supports(KeyDefinition keyDefinition);
    
    /**
     * Resolves the key based on the key definition
     */
    Key resolve(KeyDefinition keyDefinition);
}
```

#### KeyDefinition
An immutable value object describing key metadata:

- **keyId**: Unique identifier for the key
- **algorithm**: Cryptographic algorithm (e.g., RSA, ECDSA)
- **provider**: Key provider type (e.g., LOCAL, JWKS)
- **jwksConsumer**: Configuration for remote JWKS endpoint (if applicable)

### Built-in Implementations

#### LocalKeyResolver
- **Priority**: 0 (highest)
- **Source**: Local KeyStore
- **Use Case**: Asymmetric keys managed within the application

#### JwksConsumerKeyResolver
- **Priority**: 10
- **Source**: Remote JWKS endpoints
- **Use Case**: Keys managed by external identity providers (IdPs)

### Extension Guide

To implement a custom key resolver:

1. Implement the `KeyResolver` interface
2. Register the implementation as a Spring Bean
3. The resolver will be automatically discovered and used based on priority

Example:

```java
@Component
public class CustomKeyResolver implements KeyResolver {
    
    @Override
    public boolean supports(KeyDefinition keyDefinition) {
        return "CUSTOM".equals(keyDefinition.getProvider());
    }
    
    @Override
    public Key resolve(KeyDefinition keyDefinition) {
        // Custom resolution logic
    }
}
```

### Configuration Example

Configure keys in `application.yml` under `open-agent-auth.infrastructures.key-management.keys`:

```yaml
open-agent-auth:
  infrastructures:
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        # Local key (resolved by LocalKeyResolver)
        aoat-signing:
          key-id: aoat-signing-key
          algorithm: RS256
          provider: local
        
        # Remote JWKS key (resolved by JwksConsumerKeyResolver)
        wit-verification:
          key-id: wit-signing-key
          algorithm: ES256
          jwks-consumer: agent-idp  # Public key fetched from JWKS endpoint
    
    jwks:
      consumers:
        agent-idp:
          enabled: true
          issuer: http://localhost:8082
```

---

## Peers Configuration (Convention over Configuration)

### Overview

The **peers** configuration provides a simplified way to declare peer services in the trust domain. Instead of separately configuring JWKS consumers, service discovery entries, and key definitions, a single `peers` declaration automatically expands into all required infrastructure.

### How It Works

When you declare a peer:

```yaml
open-agent-auth:
  peers:
    agent-idp:
      issuer: http://localhost:8082
```

The `RoleAwareConfigurationPostProcessor` automatically:

1. **Creates a JWKS consumer** for the peer (equivalent to `infrastructures.jwks.consumers.agent-idp`)
2. **Creates a service discovery entry** for the peer (equivalent to `infrastructures.service-discovery.services.agent-idp`)
3. **Infers key definitions** based on the enabled role's profile (e.g., an `authorization-server` role automatically gets `aoat-signing`, `jwe-decryption`, and `wit-verification` keys)
4. **Ensures a default key provider** exists (in-memory) if none is configured
5. **Enables the JWKS provider** if the role profile requires it

### Before vs After

**Before (explicit configuration — 50+ lines):**

```yaml
open-agent-auth:
  infrastructures:
    trust-domain: wimse://default.trust.domain
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        wit-verification:
          key-id: wit-signing-key
          algorithm: ES256
          jwks-consumer: agent-idp
        aoat-verification:
          key-id: aoat-signing-key
          algorithm: RS256
          jwks-consumer: authorization-server
    jwks:
      provider:
        enabled: true
      consumers:
        agent-idp:
          enabled: true
          issuer: http://localhost:8082
        authorization-server:
          enabled: true
          issuer: http://localhost:8085
    service-discovery:
      services:
        agent-idp:
          base-url: http://localhost:8082
        authorization-server:
          base-url: http://localhost:8085
  roles:
    resource-server:
      enabled: true
      issuer: http://localhost:8086
```

**After (simplified with peers — 12 lines):**

```yaml
open-agent-auth:
  roles:
    resource-server:
      enabled: true
      issuer: http://localhost:8086
  peers:
    agent-idp:
      issuer: http://localhost:8082
    authorization-server:
      issuer: http://localhost:8085
```

### Explicit Configuration Takes Precedence

If you manually configure a key, JWKS consumer, or service discovery entry, the post-processor will **not** overwrite it. This ensures backward compatibility and allows fine-grained control when needed.

### Role Profiles

Each role has a built-in profile (`RoleProfileRegistry`) that defines its default requirements:

| Role | Signing Keys | Verification Keys | Encryption Keys | Required Peers |
|------|-------------|-------------------|-----------------|----------------|
| `agent-idp` | wit-signing | id-token-verification | — | agent-user-idp |
| `agent` | par-jwt-signing, vc-signing | wit-verification, id-token-verification | jwe-encryption | agent-idp, agent-user-idp, authorization-server |
| `authorization-server` | aoat-signing | wit-verification | — (decryption: jwe-decryption) | as-user-idp, agent |
| `resource-server` | — | wit-verification, aoat-verification | — | agent-idp, authorization-server |
| `agent-user-idp` | id-token-signing | — | — | (none) |
| `as-user-idp` | id-token-signing | — | — | (none) |

---

## OAA Configuration Discovery

### Overview

The `/.well-known/oaa-configuration` endpoint exposes metadata about a service instance, enabling automatic service discovery and capability negotiation between peers. This design is inspired by OIDC Discovery (`/.well-known/openid-configuration`) but tailored for multi-role agent authorization.

### Endpoint

```
GET /.well-known/oaa-configuration
```

### Response Format

```json
{
  "issuer": "http://localhost:8082",
  "roles": ["agent-idp"],
  "trust_domain": "wimse://default.trust.domain",
  "protocol_version": "1.0",
  "jwks_uri": "http://localhost:8082/.well-known/jwks.json",
  "signing_algorithms_supported": ["ES256"],
  "capabilities": {
    "workload_identity": { "enabled": true }
  },
  "endpoints": {
    "jwks": "http://localhost:8082/.well-known/jwks.json",
    "authorization": "http://localhost:8082/oauth/authorize"
  },
  "peers_required": ["agent-user-idp"]
}
```

### Protocol Versioning

The `protocol_version` field uses semantic versioning (e.g., `"1.0"`) to ensure forward compatibility. Clients should check this field before processing the metadata.

### Discovery Client

The `PeerConfigurationDiscoveryClient` provides a robust mechanism for fetching peer metadata:

- **Retry with exponential backoff**: Up to 3 retries with 500ms → 1s → 2s delays
- **Fail-fast mode**: When enabled, throws `IllegalStateException` on discovery failure to prevent the application from starting with incomplete configuration
- **Caching**: Successful discovery results are cached to avoid redundant requests
- **Graceful degradation**: Returns `null` for 404 responses (peer doesn't expose OAA configuration), allowing fallback to explicit configuration

---

**Maintainer**: Open Agent Auth Team  
**Last Updated**: 2026-02-25
