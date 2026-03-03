# ID Token

### Purpose and Role

The ID Token serves as the foundation of the entire authorization chain, representing the user's authenticated identity. It follows the OpenID Connect standard and is issued by a trusted Identity Provider after successful user authentication. This token is critical because all subsequent tokens in the flow ultimately derive their authority from the user's proven identity established by this token.

When a user logs into the system through the Agent User IDP, the Identity Provider validates the user's credentials and issues an ID Token containing the user's subject identifier, email address, and other profile information. The Agent Client then uses this ID Token as proof of user identity when requesting workload creation from the Agent IDP and when submitting authorization proposals to the Authorization Server.

### Token Structure

The ID Token is a standard JWT (JSON Web Token) signed by the Identity Provider using asymmetric cryptography. It contains standard OpenID Connect claims that identify the user and establish the token's validity.

```json
{
  "iss": "https://agent-user-idp.example.com",
  "sub": "user_12345",
  "aud": "https://agent.example.com",
  "exp": 1731668100,
  "iat": 1731664500,
  "nonce": "abc123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe"
}
```

The `iss` claim identifies the Identity Provider that issued the token, enabling verification through the provider's public keys published at their JWKS endpoint. The `sub` claim contains the user's canonical subject identifier, which becomes the foundation for all identity binding throughout the framework. The `aud` claim specifies the intended audience—in this case, the Agent Client—ensuring the token cannot be used by unauthorized parties. The `exp` and `iat` claims establish the token's validity period, typically one hour from issuance.

### Security Characteristics

The ID Token's security derives from its cryptographic signature, which can be verified by any component with access to the Identity Provider's public keys. This enables distributed verification without requiring shared secrets. The token's short lifetime limits the window of opportunity for credential misuse, while the `nonce` claim provides protection against replay attacks by binding the token to a specific authentication session.

The framework treats the ID Token's subject identifier as immutable and authoritative. All identity binding operations reference this identifier, ensuring that workload creation, authorization grants, and resource access remain consistently bound to the authenticated user throughout the authorization flow.

---

