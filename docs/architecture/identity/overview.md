# Identity and Workload Management Architecture

## Overview

The Identity and Workload Management layer provides the foundational identity infrastructure for the Open Agent Auth framework, implementing a dual-layer identity model that separates user identity from workload identity. This architecture enables fine-grained access control and accountability by establishing cryptographically verifiable bindings between human users and autonomous agents, following the Agent Operation Authorization specification's requirements for identity isolation and traceability.

The layer leverages the WIMSE (Workload Identity in Multi-Service Environments) protocol for workload identity management, providing a standardized approach to workload authentication and authorization. User identity is managed through OpenID Connect, ensuring interoperability with existing identity systems. The separation of concerns between user and workload identities enables the framework to support complex authorization scenarios while maintaining security and compliance.

## Identity Authentication Architecture

### Agent User IDP

The Agent User Identity Provider serves as the primary authentication endpoint for AI agent systems, responsible for verifying user credentials and issuing ID Tokens that establish the initial trust anchor for subsequent authorization flows. The implementation leverages OpenID Connect (OIDC) protocol to ensure interoperability with standard identity systems while supporting multiple authentication methods including username/password, SMS verification, OAuth 2.0, and multi-factor authentication (MFA).

The authentication process begins when a user interacts with the AI agent interface. The agent redirects unauthenticated users to the Agent User IDP login page, which presents a configurable login form with username and password fields. Upon receiving credentials, the IDP validates them against the configured user registry, which in the sample implementation uses an in-memory user store supporting predefined demo users for development and testing purposes. In production environments, this registry would be replaced with enterprise identity systems such as LDAP directories, database-backed user stores, or external identity providers.

Once credentials are validated, the Agent User IDP generates an ID Token containing essential user identity claims including the subject identifier (sub), issuer (iss), audience (aud), expiration time (exp), and optional profile attributes such as name and email. The token is cryptographically signed using the configured signing algorithm (ES256 by default) with the IDP's private key, ensuring authenticity and integrity. The signing key management follows best practices with key rotation support and JWKS (JSON Web Key Set) endpoints for public key distribution.

The ID Token serves multiple critical functions in the authorization framework. First, it provides proof of user authentication that can be verified by any component in the system without requiring additional authentication requests. Second, it establishes the user subject that will be bound to workloads and authorization tokens through cryptographic identity binding mechanisms. Third, it carries user attributes that may be used for policy evaluation and access control decisions throughout the authorization flow.

### AS User IDP

The Authorization Server User Identity Provider performs a similar authentication function but specifically serves the authorization server's authorization flow. When users are redirected to the authorization server to approve agent operations, the AS User IDP authenticates them to ensure that only legitimate users can grant authorization to agents. This separation of concerns allows different authentication policies and user registries for agent operations versus authorization decisions, supporting more flexible security architectures.

The AS User IDP implementation mirrors the Agent User IDP in many aspects, supporting OIDC protocol, multiple authentication methods, and configurable token lifetimes. However, its role in the authorization flow is distinct: it authenticates users specifically for the purpose of reviewing and approving authorization requests presented by the authorization server. This authentication happens after the agent has already initiated the authorization flow and submitted a PAR (Pushed Authorization Request) to the authorization server.

The authentication flow through AS User IDP follows the standard OAuth 2.0 authorization code flow pattern. Users are redirected to the authorization server's authorization endpoint with a request_uri parameter referencing a previously submitted PAR request. The authorization server retrieves the PAR request details, then redirects the user to the AS User IDP for authentication. After successful authentication, users are presented with a consent screen showing the specific operation the agent intends to perform, along with any policies or conditions attached to the authorization. User approval results in an authorization code that can be exchanged for an Agent OA Token.

### Agent IDP (WIMSE IDP)

The Agent Identity Provider implements the WIMSE protocol for workload identity management, representing a fundamental innovation in the framework's security architecture. Unlike traditional identity providers that authenticate human users, the Agent IDP authenticates and manages virtual workloads created for each user request. This workload-centric approach enables request-level isolation and cryptographic binding between user identity and workload identity.

When an agent needs to perform an operation on behalf of a user, it first creates a virtual workload by generating a temporary key pair (public/private key) specific to that request. The agent then submits a CreateWorkloadRequest to the Agent IDP, including the user's ID Token (proof of user authentication), the workload's public key, and metadata about the operation context. The Agent IDP validates the ID Token to ensure the user is authenticated, then creates a Workload Identity Token (WIT) that cryptographically binds the workload to the user.

The WIT construction process follows the WIMSE protocol specification and includes several critical claims. The subject claim (sub) contains a WIMSE workload identifier that uniquely identifies the workload within the trust domain. The issuer claim (iss) identifies the Agent IDP as the token issuer. The audience claim (aud) specifies the intended recipients of the token, typically the authorization server and resource servers. Most importantly, the agent_identity claim contains an issuedTo field that stores the user's subject identifier from the ID Token, establishing the cryptographic binding between user and workload.

The Agent IDP maintains a WorkloadRegistry that stores workload information including the workload ID, user ID, public key, creation timestamp, and expiration time. The registry implementation uses an in-memory concurrent hash map for thread-safe access, with automatic filtering of expired workloads during retrieval operations. For production deployments, this can be replaced with persistent storage solutions such as databases or distributed caches to support horizontal scaling and workload recovery after restarts.

Workload lifecycle management is a critical aspect of the Agent IDP's responsibilities. Workloads have a configurable expiration time (default 3600 seconds) and are automatically cleaned up when they expire. The registry provides methods for saving, finding, deleting, and checking existence of workloads, with all operations being thread-safe to support concurrent request processing. The temporary key pairs used for workload authentication are generated using strong cryptographic random number generators and are stored only in memory, ensuring they cannot be recovered after the workload expires or is revoked.

