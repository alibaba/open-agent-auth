# Integration Infrastructure

The integration infrastructure provides a comprehensive set of mechanisms for establishing trust relationships and managing configurations between peer services in the Open Agent Auth ecosystem. This infrastructure encompasses key resolution, peer configuration management, and automatic service discovery, enabling seamless integration across different roles and services while maintaining flexibility and security.

## Key Resolution SPI

### Overview

The `KeyResolver` SPI provides a pluggable key resolution mechanism that decouples key acquisition logic from business code. It supports flexible key sourcing from multiple providers (local KeyStore, remote JWKS endpoints, custom sources) while maintaining a unified resolution strategy.

### Core Interfaces

#### KeyResolver

```java
public interface KeyResolver {
    boolean supports(KeyDefinition keyDefinition);
    Key resolve(KeyDefinition keyDefinition);
}
```

#### KeyDefinition

Immutable value object describing key metadata:

- **`keyId`** — Unique identifier for the key
- **`algorithm`** — Cryptographic algorithm (e.g., RS256, ES256)
- **`provider`** — Key provider type (e.g., LOCAL, JWKS)
- **`jwksConsumer`** — Configuration for remote JWKS endpoint (if applicable)

### Built-in Implementations

| Resolver | Priority | Source | Use Case |
|----------|----------|--------|----------|
| `LocalKeyResolver` | 0 (highest) | Local KeyStore | Asymmetric keys managed within the application |
| `JwksConsumerKeyResolver` | 10 | Remote JWKS endpoints | Keys managed by external IdPs |

### Extension Guide

Implement a custom resolver by creating a Spring Bean:

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

The resolver is automatically discovered and prioritized.

### Configuration

```yaml
open-agent-auth:
  infrastructures:
    key-management:
      providers:
        local:
          type: in-memory
      keys:
        aoat-signing:
          key-id: aoat-signing-key
          algorithm: RS256
          provider: local
        wit-verification:
          key-id: wit-signing-key
          algorithm: ES256
          jwks-consumer: agent-idp
    jwks:
      consumers:
        agent-idp:
          enabled: true
          issuer: http://localhost:8082
```

## Peers Configuration (Convention over Configuration)

### Overview

The `peers` configuration provides a simplified way to declare peer services in the trust domain. A single `peers` declaration automatically expands into JWKS consumers, service discovery entries, and key definitions.

### How It Works

```yaml
open-agent-auth:
  peers:
    agent-idp:
      issuer: http://localhost:8082
```

The `RoleAwareConfigurationPostProcessor` automatically:

1. Creates a **JWKS consumer** for the peer
2. Creates a **service discovery entry** for the peer
3. **Infers key definitions** based on the enabled role's profile
4. Ensures a **default key provider** exists (in-memory) if none is configured
5. Enables the **JWKS provider** if the role profile requires it

### Before vs After

**Before (explicit — 50+ lines):**

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

**After (simplified — 12 lines):**

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

### Precedence

Explicit configuration always takes precedence. If you manually configure a key, JWKS consumer, or service discovery entry, the post-processor will **not** overwrite it.

### Role Profiles

Each role has a built-in profile (`RoleProfileRegistry`) defining its default requirements:

| Role | Signing Keys | Verification Keys | Encryption Keys | Required Peers |
|------|-------------|-------------------|-----------------|----------------|
| `agent-idp` | wit-signing | id-token-verification | — | agent-user-idp |
| `agent` | par-jwt-signing, vc-signing | wit-verification, id-token-verification | jwe-encryption | agent-idp, agent-user-idp, authorization-server |
| `authorization-server` | aoat-signing | wit-verification | jwe-decryption | as-user-idp, agent |
| `resource-server` | — | wit-verification, aoat-verification | — | agent-idp, authorization-server |
| `agent-user-idp` | id-token-signing | — | — | (none) |
| `as-user-idp` | id-token-signing | — | — | (none) |

## OAA Configuration Discovery

### Overview

The `/.well-known/oaa-configuration` endpoint exposes service metadata for automatic peer discovery and capability negotiation. Inspired by OIDC Discovery but tailored for multi-role agent authorization.

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

The `protocol_version` field uses semantic versioning (e.g., `"1.0"`). Clients should check this field before processing the metadata.

### Discovery Client

`PeerConfigurationDiscoveryClient` provides robust peer metadata fetching:

- **Retry with exponential backoff** — Up to 3 retries (500ms → 1s → 2s)
- **Fail-fast mode** — Throws `IllegalStateException` on failure to prevent startup with incomplete configuration
- **Caching** — Successful results are cached to avoid redundant requests
- **Graceful degradation** — Returns `null` for 404 responses, allowing fallback to explicit configuration
