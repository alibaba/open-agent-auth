## Implementation Details

### Core Components

The identity and workload management functionality is implemented across several core modules in the framework. The `open-agent-auth-core` module contains the fundamental interfaces and models, including `UserIdentity` and `AgentIdentity` classes that represent user and agent identity information, `WorkloadIdentityToken` class that encapsulates WIT data, and `WorkloadRegistry` interface that defines the contract for workload storage and retrieval.

The `UserIdentity` class provides a comprehensive model for user identity, including the subject identifier, display name, email address, email verification status, and additional custom attributes stored in a map. This model follows the OpenID Connect standard claims while allowing extensibility for application-specific attributes. The class is designed to be immutable, with all fields declared final and provided through a constructor, ensuring thread-safety and preventing accidental modification.

The `AgentIdentity` class represents agent identity with similar structure but includes agent-specific attributes such as agent type, version, and capabilities. This distinction between user and agent identities allows the framework to apply different authentication and authorization policies based on the type of entity being authenticated.

The `WorkloadRegistry` interface defines the contract for workload storage operations including save, findById, delete, and exists methods. The default implementation, `InMemoryWorkloadRegistry`, uses a `ConcurrentHashMap` for thread-safe storage and automatically filters expired workloads during retrieval operations. This implementation is suitable for development and testing scenarios, while production deployments would typically use database-backed implementations for persistence and scalability.

### Spring Boot Integration

The framework provides Spring Boot autoconfiguration for all identity provider roles, enabling developers to enable specific roles through simple configuration properties. The `AgentUserIdpAutoConfiguration` class automatically configures the Agent User IDP when `open-agent-auth.role` is set to `agent-user-idp`, creating beans for ID Token validation and user authentication. Similarly, `AsUserIdpAutoConfiguration` configures the AS User IDP, and `AgentIdpAutoConfiguration` configures the Agent IDP.

The autoconfiguration classes use conditional annotations to ensure that beans are only created when appropriate conditions are met. The `@ConditionalOnProperty` annotation checks for the correct role configuration, while `@ConditionalOnMissingBean` allows developers to override default implementations with custom beans. This design provides sensible defaults while maintaining flexibility for customization.

Configuration properties for each role are defined in dedicated property classes such as `AgentUserIdpProperties`, `AsUserIdpProperties`, and `AgentIdpProperties`. These classes use Spring Boot's `@ConfigurationProperties` annotation to bind YAML or properties file configurations to strongly-typed Java objects, providing type-safe configuration access and IDE autocomplete support.

The autoconfiguration loading order is defined in the `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` file, which specifies that `CoreAutoConfiguration` loads first to provide shared beans such as `KeyManager`, followed by role-specific configurations. This ordering ensures that dependencies are available when needed and prevents circular dependency issues.

### Key Management

Cryptographic key management is a critical aspect of the identity and workload management layer. The framework uses asymmetric cryptography (ECDSA with P-256 curve by default) for signing tokens and creating workload key pairs. Each identity provider maintains its own key pair for signing tokens, with the public key published through a JWKS endpoint for verification by other components.

The `KeyManager` interface provides methods for retrieving signing and verification keys by key ID, supporting key rotation and multiple active keys. The default implementation stores keys in memory, with keys generated on-demand and destroyed when the application shuts down.

Key rotation is an important security practice that the framework supports. When a new key is generated, it can be added to the JWKS endpoint alongside existing keys, allowing a gradual transition period where tokens signed with either key are accepted. Old keys can be removed after all tokens signed with them have expired, ensuring continuous operation without service interruption.

Workload key pairs are generated on-demand for each workload using strong random number generators. The private keys are stored only in memory and are automatically destroyed when the workload expires or is revoked. This ephemeral key management approach minimizes the attack surface by ensuring that workload credentials exist only for the minimum necessary time.

