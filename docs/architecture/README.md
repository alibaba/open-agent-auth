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

**Maintainer**: Open Agent Auth Team  
**Last Updated**: 2026-02-09
