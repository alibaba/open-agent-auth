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

**Maintainer**: Open Agent Auth Team  
**Last Updated**: 2026-02-25
