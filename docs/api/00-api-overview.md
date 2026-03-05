# Open Agent Auth API Documentation

Open Agent Auth provides a framework layer API for implementing Agent Operation Authorization based on industry-standard protocols (OAuth 2.0, OpenID Connect, WIMSE). This documentation focuses on the framework layer interfaces that developers should use, including Actor and Executor modules.

The framework layer design emphasizes role-based abstractions through independent actor entities, enabling developers to integrate authorization capabilities without dealing with the complexity of core implementation details. Each actor represents a distinct role in the authorization flow, providing clear separation of concerns and flexible integration patterns.

## 🏗️ Framework Layer Architecture

The framework layer provides high-level abstractions that hide the complexity of the core implementation:

```
Framework Layer (Developer Interface)
├── Actor Module
│   ├── Agent                    - Agent role for authorization requests
│   ├── ResourceServer           - Resource Server with five-layer verification
│   ├── AuthorizationServer      - Authorization Server for token issuance
│   ├── UserIdentityProvider     - User IDP for authentication
│   └── AgentIdentityProvider    - Agent IDP for workload identity management
└── Executor Module
    └── AgentAapExecutor         - Workflow executor for Agent Operation Authorization
```

## 📖 API Guides

- **[Actor API Guide](01-role-actor.md)** — Comprehensive guide to Actor interfaces including Agent, ResourceServer, AuthorizationServer, UserIdentityProvider, and AgentIdentityProvider. Each actor represents a distinct role in the authorization flow with specific responsibilities and methods.

- **[Executor API Guide](02-aap-executor.md)** — Detailed documentation of AgentAapExecutor, which orchestrates the complete Agent Operation Authorization Protocol (AOA) workflow. This guide covers workflow steps, execution flow, and simplified API for managing authorization processes.

- **[Spring Boot Controllers Guide](03-spring-boot-starter.md)** — Reference for pre-built REST API controllers including UserLoginController, WorkloadController, OAuth2DcrController, OAuth2ParController, OAuth2TokenController, and other endpoints for HTTP-based integration.

## 🔗 Related Resources

- [Quick Start Guide](../guide/01-quick-start.md) — Get started with Open Agent Auth in 5 minutes
- [User Guide](../guide/01-quick-start.md) — Comprehensive user guide and best practices
- [Configuration Guide](../guide/04-configuration.md) — Detailed configuration options
- [Architecture Documentation](../architecture/) — System architecture and design principles

---

**Version**: 0.1.0-beta.1-SNAPSHOT  
**Last Updated**: 2026-03-04
