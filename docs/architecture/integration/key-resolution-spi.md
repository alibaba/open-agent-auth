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
