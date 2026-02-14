## Security Best Practices

### Token Validation Requirements

All tokens must undergo comprehensive validation before being accepted. Signature verification ensures the token's authenticity and integrity by validating the cryptographic signature using the issuer's public key obtained from a trusted JWKS endpoint. Expiration checks ensure the token has not expired, with configurable clock skew tolerance to handle minor time synchronization issues. Issuer verification confirms the token is from a trusted issuer by checking the `iss` claim against a whitelist of authorized issuers. Audience verification ensures the token is intended for the current recipient by checking the `aud` claim. Nonce and replay prevention checks detect replay attacks by validating nonce values and checking token identifiers against recent usage.

### Token Storage Guidelines

Proper token storage is critical for maintaining security. ID Tokens should be stored securely in memory and cleared immediately after use, minimizing the window of opportunity for credential theft. WITs should be stored in memory for the workload's lifetime and never persisted to disk, as they contain sensitive cryptographic material. Agent OA Tokens can be cached for the token's remaining lifetime but must be validated on each use to ensure they have not been revoked or expired. Private keys must be stored only in memory and destroyed when the workload expires or is revoked, ensuring they cannot be recovered after their useful lifetime.

### Token Revocation Strategies

The framework supports multiple token revocation strategies. The `jti` claim provides a unique identifier for each token, enabling token identification for revocation tracking. Token blacklists provide immediate revocation capability in security incident scenarios, allowing compromised tokens to be invalidated before their natural expiration. The framework primarily relies on expiration for invalidation, as this provides a simple, stateless approach that doesn't require distributed coordination. OAuth 2.0 Token Introspection (RFC 7662) enables Resource Servers to query the Authorization Server for token status and metadata, which is particularly useful for scenarios where tokens may be revoked before expiration.

### Key Management Practices

Robust key management is essential for maintaining the security of the token system. The framework uses asymmetric cryptography (RS256 or ES256) for signing tokens, enabling distributed verification without requiring shared secrets. Public keys are published via JWKS endpoints, enabling automatic key discovery and rotation. Key rotation is implemented without service interruption by publishing new keys alongside existing keys, allowing a gradual transition period. The framework uses in-memory key storage, with keys generated on-demand using strong cryptographic random number generators, ensuring unpredictability and resistance to brute-force attacks. Private keys are stored only in memory and are automatically destroyed when the application shuts down or when the workload expires.

---

## References

This framework builds upon several established standards and protocols:

- **OAuth 2.0**: [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) - The foundation for authorization flows
- **OpenID Connect**: [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) - Provides identity layer on top of OAuth 2.0
- **PAR**: [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) - Pushed Authorization Requests for secure parameter transmission
- **JWT**: [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) - JSON Web Token format for signed tokens
- **WIMSE**: [I-D.ietf-wimse-workload-creds](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds) - Workload Identity Credentials protocol
- **HTTP Message Signatures**: [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421) - HTTP-layer request authentication
- **W3C VC**: [Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/) - Standard for tamper-evident credentials
- **OPA**: [Open Policy Agent](https://www.openpolicyagent.org/) - Policy evaluation engine for fine-grained authorization

---

## Glossary

- **ID Token**: OpenID Connect token representing user identity, issued by a trusted Identity Provider after authentication
- **WIT (Workload Identity Token)**: Token that authenticates virtual workloads, implementing the WIMSE protocol for request-level isolation
- **WPT (Workload Proof Token)**: Cryptographic signature over HTTP request components, proving request authenticity and integrity
- **PAR-JWT**: Pushed Authorization Request in JWT format, carrying operation proposals with embedded evidence
- **VC (Verifiable Credential)**: W3C-standard credential that cryptographically captures user intent, enabling semantic audit trails
- **Agent OA Token (Agent Operation Authorization Token)**: Final access token granting operational permission after user consent
- **WIMSE**: Workload Identity and Management protocol, standard for workload authentication
- **OPA**: Open Policy Agent, policy evaluation engine for fine-grained authorization decisions
- **JWKS**: JSON Web Key Set, standard mechanism for distributing public keys
- **JTI**: JWT ID, unique identifier for each token enabling revocation tracking

---

**Document Version**: 2.0.0  
**Last Updated**: 2026-02-06  
**Maintainer**: Open Agent Auth Team
