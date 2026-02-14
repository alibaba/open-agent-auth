## Workload Proof Token (WPT)

### Purpose and Mechanism

The Workload Proof Token provides cryptographic proof that a request originated from an authenticated workload and possesses the required authorization tokens. It is implemented as a JWT following the WIMSE Workload Proof Token specification (draft-ietf-wimse-wpt), supporting DPoP (Demonstrating Proof-of-Possession) patterns for token binding.

The WPT addresses a critical security challenge in distributed systems: ensuring that requests cannot be forged or tampered with during transmission. Even if an attacker intercepts a valid WIT, they cannot use it to forge valid requests without possessing the workload's private key, which never leaves the workload's memory. This binding between the WIT and the WPT creates a two-factor authentication system where the attacker would need both the WIT (verifying the workload's identity) and the private key (proving possession of the workload's credentials).

The WPT supports flexible token binding through the `oth` (other tokens hashes) claim, enabling it to be cryptographically bound to additional tokens such as the Agent Operation Authorization Token (AOAT). This binding ensures that the workload presenting the WPT also possesses the corresponding authorization token, preventing token replay attacks and enabling fine-grained access control. The `oth` claim follows a flexible design pattern where any token implementing the `OthBindableToken` interface can be bound to the WPT without requiring modifications to the core WPT generation logic.

### Token Structure

The WPT is a JWT that contains claims proving possession of the workload's private key and optionally binding it to other tokens such as the Agent Operation Authorization Token (AOAT).

```json
{
  "header": {
    "typ": "wpt+jwt",
    "alg": "ES256"
  },
  "payload": {
    "aud": "https://api.example.com",
    "exp": 1731668100,
    "iat": 1731664500,
    "jti": "wpt-123xyz",
    
    "wth": "base64url-encoded-wit-hash",
    
    "oth": {
      "aoat": "base64url-encoded-aoat-hash"
    }
  }
}
```

The `wth` (Workload Token Hash) claim is the core of the WPT's security model. It contains the base64url-encoded SHA-256 hash of the WIT, cryptographically binding the WPT to a specific WIT. This ensures that the WPT was created by the workload identified by that WIT. When validating the WPT, the `wth` claim MUST match the hash of the WIT presented in the request.

The `oth` (Other Tokens Hashes) claim is a JSON object containing hashes of other tokens that this WPT is bound to. Each entry consists of a token type identifier (the key) and a base64url-encoded SHA-256 hash of that token (the value). For example, when binding to an Agent Operation Authorization Token, the `oth` claim would contain `"aoat": "base64url-encoded-aoat-hash"`. This creates a cryptographic binding between the WPT and the AOAT, ensuring that the workload presenting the WPT also possesses the corresponding authorization token.

The `aud`, `exp`, `iat`, and `jti` claims provide standard JWT functionality: audience specification, expiration time, issuance time, and unique identifier for replay protection. The `exp` claim provides protection against replay attacks by limiting the validity window for the WPT.

### WPT Generation Process

When an agent needs to make a request to a protected resource, it generates a WPT following a structured process. First, it retrieves the WIT and extracts the workload's private key. Second, it computes the SHA-256 hash of the WIT's JWT string and includes it in the `wth` claim. Third, if the request requires binding to an authorization token (e.g., AOAT), it computes the SHA-256 hash of that token's JWT string and includes it in the `oth` claim with the appropriate token type identifier. Fourth, it constructs the WPT claims including the `aud`, `exp`, `iat`, `jti`, `wth`, and optionally `oth` claims. Fifth, it signs the WPT using the workload's private key with the algorithm matching the WIT's `cnf.jwk.alg` field. Finally, it includes the resulting WPT in the request headers.

The Resource Server validates the WPT by extracting the WIT from the request headers and verifying its signature and expiration. It then extracts the workload's public key from the WIT's `cnf` claim and uses it to verify the WPT's signature. It verifies that the `wth` claim matches the hash of the presented WIT. If the `oth` claim is present, it verifies that the hashes match the corresponding tokens presented in the request. Only if all validations pass does the Resource Server process the request.

### Security Considerations

The WPT mechanism provides several important security benefits. The `wth` claim creates a cryptographic binding between the WPT and the WIT, ensuring that the WPT was created by the workload identified by that WIT. The `oth` claim enables flexible token binding, allowing the WPT to be bound to authorization tokens such as AOAT, preventing token replay attacks and enabling fine-grained access control.

The use of asymmetric cryptography enables distributed verification—any component with the public key from the WIT can verify the WPT signature without requiring shared secrets or coordination with the Agent IDP. This design supports horizontal scaling and high availability, as multiple Resource Server instances can validate WPTs independently.

The `oth` claim follows a flexible design pattern where any token implementing the `OthBindableToken` interface can be bound to the WPT. This provides extensibility, allowing new token types to be added without requiring modifications to the core WPT generation and validation logic.

---

