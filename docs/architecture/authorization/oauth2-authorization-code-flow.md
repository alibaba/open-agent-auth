## Agent OA Token Structure

### Token Claims

The Agent Operation Authorization Token (Agent OA Token) is a JWT that encapsulates all authorization information needed for resource access decisions. The token follows the standard JWT structure with a header, payload, and signature, using the ES256 signing algorithm by default for strong security with reasonable performance.

The token header contains the algorithm identifier (alg) and token type (typ), following JWT standards. The payload contains a rich set of claims that provide comprehensive authorization context. The standard JWT claims include the issuer (iss) identifying the authorization server, subject (sub) containing the user's subject identifier, audience (aud) specifying the intended recipients (typically resource servers), expiration time (exp), issued at time (iat), and JWT identifier (jti) for token tracking and potential revocation.

The agent_identity claim contains the binding information between the user and the workload, including the issuedTo field with the user's subject identifier and the workloadId field with the WIMSE workload identifier. This claim enforces the identity consistency requirement that the token can only be used by the specific workload that was bound to the specific user during authorization.

The agent_operation_authorization claim contains the authorization details including the operationType field describing the type of operation being authorized, the resourceId field identifying the target resource, the scopes field listing the granted permissions, and the conditions field specifying any limitations or conditions on the authorization such as time restrictions, rate limits, or data constraints.

The policy claim contains policy evaluation information including the policyId field referencing the registered OPA policy, the policyVersion field identifying the specific version of the policy, and the policyParameters field containing any parameters passed to the policy during evaluation. This information enables resource servers to perform consistent policy evaluation and supports policy versioning and rollback.

The evidence claim contains the cryptographic evidence supporting the authorization decision, including the userIdentityTokenHash field with a hash of the user ID Token, the workloadIdentityTokenHash field with a hash of the WIT, and the promptVc field containing the W3C Verifiable Credential representing the user's original input. This evidence provides a complete audit trail and enables verification that the authorization was based on valid user authentication and workload identity.

The audit_trail claim contains comprehensive audit information including the authorizationTimestamp field with the time when authorization was granted, the userConsent field indicating whether the user explicitly consented, the consentIpAddress field capturing the IP address from which consent was given, the consentUserAgent field recording the browser or client used for consent, and the semanticExtensionLevel field indicating the degree to which the agent extended the user's original intent.

### Token Security

The Agent OA Token implements several security measures to protect against common attacks while maintaining usability. Tokens are signed using asymmetric cryptography, allowing any component with access to the authorization server's public key to verify the token's authenticity. This signature verification is performed by resource servers without requiring additional calls to the authorization server, enabling distributed authorization decisions.

The token expiration time is set based on the sensitivity of the authorized operation and the expected duration of the operation. Short expiration times (5-15 minutes) are appropriate for sensitive operations like financial transactions, while longer expiration times (1-4 hours) may be acceptable for less sensitive operations like read-only queries. The expiration time should balance security (shorter is better) with usability (longer is better) and should be configurable per operation type.

The token includes a JWT identifier (jti) claim that uniquely identifies the token instance. This identifier can be used for token revocation tracking, allowing the authorization server to maintain a blacklist of revoked tokens. While the framework primarily relies on expiration for token invalidation, the jti claim provides a mechanism for immediate revocation in security incident scenarios.

The token signature covers all claims in the payload, ensuring that any modification to the token content invalidates the signature. This prevents token tampering where an attacker might attempt to modify the scopes, extend the expiration time, or change other claims to gain unauthorized access.

