## Implementation Details

### Core Components

The authorization flow functionality is implemented across several core modules in the framework. The `open-agent-auth-core` module contains the fundamental interfaces and models for OAuth 2.0 and PAR, including `OAuth2ParClient` and `OAuth2ParServer` interfaces that define the contract for pushed authorization requests. These interfaces support both standard OAuth 2.0 PAR flows and the extended Agent Operation Authorization flows with additional claims and validation requirements.

The `DefaultOAuth2ParClient` implementation provides client-side PAR functionality, constructing PAR-JWT requests, submitting them to the authorization server, and handling request_uri responses. The client supports the `private_key_jwt` client authentication method, where the client assertion is signed with the workload's private key, establishing a strong cryptographic binding between the PAR request and the workload identity.

The `AapOAuth2ParServer` interface extends the standard PAR server with agent-specific validation requirements. The `DefaultOAuth2ParServer` implementation validates PAR-JWT requests, extracts and validates embedded evidence (ID Token and WIT), performs identity consistency verification, and generates request URIs. The server maintains a temporary store of authorization requests with configurable expiration time, ensuring that request URIs remain secure and single-use.

The `OAuth2AuthorizationServer` interface defines the contract for processing authorization requests and issuing authorization codes, following RFC 6749 specifications. The `DefaultOAuth2AuthorizationServer` implementation handles user authentication, consent presentation, authorization code generation, and code storage. The implementation supports both traditional OAuth 2.0 authorization code flows and PAR-enhanced flows.

The five-layer verification is implemented by the `FiveLayerVerifier` interface, which orchestrates the sequential execution of all verification layers. The `DefaultFiveLayerVerifier` implementation delegates to specialized validator components including `WitValidator`, `WptValidator`, and `AoatValidator`, and integrates with the `PolicyEvaluator` for policy-based access control. The verifier returns a comprehensive `VerificationResult` containing the validation outcome, any errors encountered, and the extracted identity and policy information.

### Policy Evaluation

The OPA policy evaluation mechanism provides flexible, fine-grained access control that can be customized without code changes. Policies are written in Rego language and registered with the `PolicyRegistry` interface, which manages policy lifecycle operations including registration, retrieval, deletion, and listing. The `InMemoryPolicyRegistry` implementation stores policies in memory for simple deployments, while production deployments may use database-backed or distributed registry implementations.

The `PolicyEvaluator` interface defines the contract for evaluating policies against request contexts. The `LightweightPolicyEvaluator` implementation provides a streamlined evaluation engine that is optimized for the specific requirements of the Agent Operation Authorization framework. The evaluator constructs evaluation inputs from the request context, executes the Rego policy, and returns the evaluation result with any additional metadata.

Policy definitions can reference complex conditions and business logic. For example, a policy might restrict access to sensitive resources to users with specific roles, limit access to business hours, enforce rate limits per user, or apply data masking rules based on user permissions. The Rego language supports these capabilities through its rich set of built-in functions and composable rule structures.

The framework supports policy versioning, allowing multiple versions of a policy to coexist. The Agent OA Token includes a policyVersion claim that specifies which version should be used for evaluation, enabling controlled policy rollouts and rollbacks. Versioning is particularly important in production environments where policies need to be updated without disrupting ongoing operations.

### Spring Boot Integration

The authorization server functionality is automatically configured through Spring Boot autoconfiguration when `open-agent-auth.role` is set to `authorization-server`. The `AuthorizationServerAutoConfiguration` class creates beans for all required components including PAR server, authorization server, token server, policy registry, and policy evaluator.

Configuration properties for the authorization server are defined in `AuthorizationServerProperties` class, which supports configuration of PAR endpoint settings, token issuance parameters, client registration settings, and policy evaluation options. These properties can be configured through YAML or properties files, providing a flexible configuration mechanism that doesn't require code changes.

The autoconfiguration uses conditional annotations to ensure that beans are only created when appropriate conditions are met. The `@ConditionalOnProperty` annotation checks for the correct role configuration, while `@ConditionalOnMissingBean` allows developers to override default implementations with custom beans. This design provides sensible defaults while maintaining flexibility for customization scenarios.

The framework also supports dynamic client registration (DCR) through the `OAuth2DcrClient` interface, which allows agents to register themselves as OAuth clients with the authorization server dynamically. The `AgentDcrAutoRegistrationConfiguration` handles automatic DCR registration for agents, simplifying the integration process. According to the architecture design, DCR registration should be performed dynamically during the authorization flow using WIT as authentication proof, with WIT.sub as the client_id and private_key_jwt as the authentication method.

