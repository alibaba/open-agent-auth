# Authorization Flow Architecture

## Overview

The Authorization Flow architecture implements a comprehensive, standards-based authorization mechanism for AI agent operations, designed around the principle that every agent-executed operation must be traceable back to explicit user consent. This architecture follows the Agent Operation Authorization specification, where the Authorization Server acts as the witness of user consent, cryptographically binding the original user intent to the authorized operation through semantic audit trails.

The flow is orchestrated through the AOA (Agent Operation Authorization) Bridge pattern, which coordinates between multiple identity providers and authorization components. This pattern enables agents to obtain the necessary credentials and tokens while maintaining a clear separation of concerns: user authentication is handled by dedicated IDPs, workload identity is managed through WIMSE protocols, and authorization decisions are made by the Authorization Server with policy evaluation through OPA.

The Authorization Flow layer implements the core authorization logic of the Open Agent Auth framework, managing the complete lifecycle from agent operation proposals to access token issuance. This layer builds upon OAuth 2.0 and OpenID Connect standards while extending them with specialized features for AI agent scenarios, including Pushed Authorization Requests (PAR), fine-grained policy evaluation, and comprehensive audit tracking. The authorization flow ensures that agents can only perform operations explicitly authorized by users, with all decisions being cryptographically verifiable and fully auditable.

The authorization architecture follows a multi-stage approach that separates concerns between request preparation, authorization processing, and token issuance. This separation enables independent scaling of different components, clear security boundaries, and flexible integration with various identity providers and policy engines. The flow is designed to be both secure and user-friendly, balancing strong security guarantees with a smooth authorization experience that doesn't overwhelm users with technical details.

## OAuth 2.0 Authorization Code Flow

### Standard Authorization Flow

The authorization flow begins with the OAuth 2.0 authorization code grant, which provides a secure mechanism for obtaining user authorization without exposing user credentials to the agent. The agent initiates the flow by redirecting the user to the authorization server's authorization endpoint, providing parameters that describe the authorization request including the client identifier, requested scopes, redirect URI, and a state parameter for CSRF protection.

The authorization server receives the authorization request and must first authenticate the user before proceeding. This authentication is delegated to the AS User IDP, which verifies the user's identity through configured authentication methods such as username/password, SMS verification, or multi-factor authentication. The authentication result is returned as an ID Token that contains the user's subject identifier and other identity claims.

Once the user is authenticated, the authorization server presents a consent screen showing the specific operation the agent intends to perform. This consent screen is critical for transparency, ensuring users understand exactly what they are authorizing before granting permission. The screen displays the operation description, the resources that will be accessed, any conditions or limitations on the authorization, and the duration of the authorization. Users can either approve or deny the authorization request.

If the user approves the request, the authorization server generates an authorization code and redirects the user back to the agent's redirect URI with the code as a query parameter. The authorization code is a short-lived, single-use token that serves as proof of the user's authorization. The agent then exchanges this authorization code for an Agent OA Token by making a token request to the authorization server's token endpoint, providing the authorization code, client credentials, and the original redirect URI.

The authorization server validates the authorization code, ensuring it hasn't been used before and hasn't expired, then issues an Agent OA Token. This token contains the user's subject identifier, the agent's identity, the authorized scopes and permissions, policy information for access control decisions, and a complete audit trail of the authorization process. The token is cryptographically signed using the authorization server's private key, allowing resource servers to verify its authenticity without requiring additional calls to the authorization server.

### Pushed Authorization Request Extension

The framework extends the standard OAuth 2.0 flow with Pushed Authorization Request (PAR), as defined in RFC 9126, to enhance security for agent authorization scenarios. PAR addresses several security concerns in traditional OAuth flows where authorization parameters are transmitted through browser redirects, potentially exposing sensitive information to intermediaries or allowing parameter manipulation.

In the PAR flow, the agent first prepares a complete authorization request including all necessary parameters such as client ID, redirect URI, scopes, response type, state, and agent-specific extensions like evidence, operation proposals, and context information. This request is formatted as a JWT (PAR-JWT) and signed using the workload's private key, creating a cryptographically protected authorization request that cannot be forged or modified without detection.

The agent submits this PAR-JWT to the authorization server's PAR endpoint using an HTTP POST request with application/x-www-form-urlencoded content type. The request includes client authentication, typically using the private_key_jwt method where the client assertion is signed with the workload's private key, establishing a strong binding between the authorization request and the workload identity.

The authorization server validates the PAR-JWT by verifying its signature using the workload's public key extracted from the WIT, checking the token's expiration and issuance time, validating the issuer and audience claims, and ensuring all required claims are present. It also validates the embedded evidence including the user ID Token (verifying its signature and extracting the user subject) and the WIT (verifying its signature and extracting the agent_identity binding). The server performs identity consistency verification by checking that the user ID Token's subject matches the WIT's agent_identity.issuedTo field, ensuring the workload is bound to the authenticated user.

After successful validation, the authorization server generates a unique request URI and stores the authorization request parameters in a temporary store, typically with a short expiration time (default 90 seconds). The request URI is returned to the agent in a JSON response containing the request_uri and expires_in fields. The agent then redirects the user to the authorization server's authorization endpoint with the request_uri parameter instead of including all authorization parameters directly in the redirect URL.

The authorization server retrieves the stored authorization request using the request URI, ensuring that the request hasn't expired and hasn't been used before. The request_uri is single-use, preventing replay attacks where an attacker could reuse a valid authorization request. The server then proceeds with user authentication and consent presentation as in the standard flow.

The PAR extension provides several security benefits. Authorization parameters are transmitted directly to the authorization server over a secure TLS channel, avoiding exposure through browser redirects. The PAR-JWT signature ensures parameter integrity, preventing modification during transmission. The short expiration and single-use nature of request URIs limits the window for replay attacks. Client authentication using private_key_jwt provides strong client authentication that is cryptographically bound to the workload identity.

### PAR Request Processing

When the agent initiates an authorization request, it uses OAuth 2.0 Pushed Authorization Requests (PAR) to securely transmit operation proposals to the Authorization Server. The PAR mechanism prevents sensitive operation data from leaking through URLs and provides a secure, server-side storage mechanism for authorization parameters.

The PAR request includes several critical components that enable comprehensive authorization evaluation. The agent constructs a JWT containing the agent_operation_proposal claim, which defines the operation the agent intends to perform. This proposal is cryptographically signed to ensure integrity and authenticity. The request also includes the user's ID Token and the workload's WIT, establishing the identity context for the authorization.

The Authorization Server, acting as the witness of user consent, validates the semantic audit trail embedded in the request. This includes verifying the W3C Verifiable Credential that captures the user's original prompt and the agent's interpretation, ensuring that the transformation from user intent to operation proposal is transparent and auditable. The server extracts this evidence and stores it for later inclusion in the access token, creating a cryptographically verifiable link between the user's consent and the authorized operation.

