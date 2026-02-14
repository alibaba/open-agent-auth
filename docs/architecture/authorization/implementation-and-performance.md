## Security Considerations

### Authorization Code Security

Authorization codes are critical security tokens that represent user authorization and must be strongly protected. The framework implements several security measures for authorization codes including cryptographic randomness (minimum 128 bits of entropy), short expiration time (default 10 minutes), single-use enforcement (codes are immediately invalidated after being exchanged), and binding to client_id and redirect_uri (prevents code interception attacks).

The authorization code storage uses secure random generation algorithms to ensure unpredictability. Codes are stored in a secure registry that prevents unauthorized access and supports concurrent operations. The registry implementation should use encryption-at-rest for production deployments to protect codes even if the storage system is compromised.

The framework validates the redirect_uri parameter against the registered redirect URI for the client, preventing open redirect attacks where an attacker might redirect the authorization code to a malicious endpoint. The validation ensures that the redirect URI exactly matches (or is a subpath of) the registered URI, depending on the client's registration configuration.

### Token Security

The framework implements comprehensive token security measures to protect against token theft, replay, and tampering. All tokens are signed using asymmetric cryptography, allowing verification without sharing secrets. Token signatures are verified on every use, ensuring that modified tokens are rejected immediately.

Token expiration is enforced strictly, with no grace period for expired tokens. The framework supports clock skew tolerance (configurable, default 60 seconds) to handle minor time synchronization issues between servers, but tokens that are significantly past their expiration time are always rejected.

Token revocation is supported through a blacklist mechanism that tracks revoked token identifiers. While the framework primarily relies on expiration for token invalidation, the blacklist provides a mechanism for immediate revocation in security incident scenarios. The blacklist can be implemented as an in-memory cache for simple deployments or as a distributed cache for production deployments requiring high availability.

The framework supports token introspection through the OAuth 2.0 Token Introspection endpoint (RFC 7662), allowing resource servers to query the authorization server for token status and metadata. This is particularly useful for scenarios where tokens may be revoked before their expiration time.

### Replay Attack Prevention

The framework implements multiple layers of replay attack prevention. The PAR protocol's single-use request_uri prevents replay of authorization requests. Authorization codes are single-use and immediately invalidated after being exchanged. The WPT signature includes a timestamp that limits the validity window for signed requests.

The framework maintains state for all authorization codes and request URIs, tracking whether they have been used. This state is stored with expiration times, ensuring that old state is automatically cleaned up. The state storage should be designed for high concurrency and low latency to avoid becoming a performance bottleneck.

For additional protection, the framework supports nonce parameters in authorization requests, which provide additional randomness that must be included in the authorization code. The nonce is returned in the token and verified by the client, preventing replay attacks where an attacker might reuse an authorization code.

## Token Issuance

After the user approves the authorization request, the Authorization Server issues an Agent Operation Authorization Token (AOAT) that grants the agent permission to perform the requested operation. This token is a JWT that includes all necessary claims for authorization enforcement, including the user identity, workload identity, operation scope, and policy reference.

The token issuance process incorporates the semantic audit trail as a core component. The audit_trail claim within the token captures the complete context of the authorization decision, including the original user prompt (via a W3C VC), the rendered operation description, the semantic expansion details, and the user confirmation timestamp. This audit information is cryptographically signed by the Authorization Server, serving as verifiable evidence of the user's consent and enabling post-hoc analysis in case of disputes or compliance audits.

The Authorization Server also registers the policy referenced in the token, ensuring that the same policy is available to all resource servers that will validate the token. This registration process creates a shared understanding of the authorization rules across the distributed system, enabling consistent enforcement and reducing the risk of policy drift.