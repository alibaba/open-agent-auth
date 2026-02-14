## Verifiable Credential (VC)

### Purpose and Significance

The Verifiable Credential serves as the cryptographic foundation of the framework's auditability and dispute resolution capabilities. It captures the user's original natural language input in a tamper-evident format that can be verified independently by any component with access to the issuer's public keys. This is particularly important in AI agent scenarios where the system interprets and potentially expands the user's intent, creating a gap between what the user said and what the system does.

The VC addresses this gap by providing an immutable record of the user's original prompt. When disputes arise—for example, when a user claims "I didn't authorize that transaction" or "I didn't say to spend that much"—the VC provides cryptographic evidence of what the user actually authorized. This enables post-hoc analysis, compliance audits, and dispute resolution with a high degree of confidence.

The VC follows the W3C Verifiable Credentials Data Model, a standardized format for expressing tamper-evident claims that can be cryptographically verified. This standardization ensures interoperability with other systems and tools that support W3C VCs, enabling integration with broader identity and credential ecosystems.

### Credential Structure

The VC is embedded as a JWT within the PAR-JWT's `evidence` claim, following the W3C JWT VC format.

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "https://agent.example.com/.well-known/jwks.json#key-01"
  },
  
  "payload": {
    "jti": "pt-001",
    "iss": "https://agent.example.com",
    "sub": "user_12345",
    "iat": 1731664500,
    "exp": 1731668100,
    
    "type": "VerifiableCredential",
    "credentialSubject": {
      "type": "UserInputEvidence",
      "prompt": "Buy something cheap on Nov 11 night",
      "timestamp": "2025-11-11T10:30:00Z",
      "channel": "voice",
      "deviceFingerprint": "dfp_abc123"
    },
    "issuer": "https://agent.example.com",
    "issuanceDate": "2025-11-11T10:30:30Z",
    "expirationDate": "2025-11-11T23:59:00Z",
    
    "proof": {
      "type": "JwtProof2020",
      "created": "2025-11-11T10:30:30Z",
      "verificationMethod": "https://agent.example.com/#key-01"
    }
  }
}
```

The `credentialSubject` contains the core evidence: the user's original prompt text, the timestamp when the prompt was captured, the channel through which the input was received (e.g., voice, text), and a device fingerprint for additional context. The `type` field identifies this as "UserInputEvidence," a custom credential type defined by the framework for capturing user intent.

The `proof` object contains cryptographic proof of the credential's authenticity. It includes the proof type ("JwtProof2020"), the creation timestamp, and a reference to the verification method (the public key used to verify the signature). This proof enables any component with access to the issuer's public keys to verify that the credential has not been modified since issuance.

### Semantic Audit Trail

The VC is a key component of the framework's semantic audit trail, which provides a complete, traceable chain from the user's original intent to the system's final executed action. This audit trail captures not just what happened, but why it happened, enabling sophisticated analysis and compliance reporting.

The semantic audit trail serves several important purposes. First, it provides intent provenance by recording what the user originally said, preventing disputes about authorization. Second, it documents action interpretation by showing how the system interpreted and rendered the input into a concrete operation, reflecting the AI's reasoning process. Third, it provides semantic transparency by showing whether semantic expansions or default values were applied—for example, mapping "cheap" to a specific dollar amount or defining "night" as a specific time range. Fourth, it provides user confirmation evidence by including timestamps indicating when the user reviewed and confirmed the interpreted action. Fifth, it enables accountability support by facilitating post-hoc analysis in case of erroneous transactions, helping determine whether issues stemmed from ambiguous user input, system misinterpretation, or misleading UI guidance.

The Authorization Server incorporates the VC into the Agent Operation Authorization Token, ensuring that the evidence travels with the authorization through the entire system. This enables Resource Servers and audit systems to verify the provenance of each authorized operation, even if the original PAR-JWT has been deleted.

### Security Properties

The VC's security derives from its cryptographic signature, which can be verified independently by any component with access to the issuer's public keys. This enables distributed verification without requiring coordination with the issuing agent. The signature covers all claims in the credential, ensuring that any modification is detected.

The VC's short lifetime (typically matching the PAR-JWT's expiration) limits the window of opportunity for misuse. The credential's unique identifier (`jti`) enables tracking and potential revocation if needed. The inclusion of the device fingerprint provides additional context for fraud detection and security analytics.

The VC follows the W3C Verifiable Credentials Data Model, ensuring interoperability with standard VC tooling and enabling integration with broader identity ecosystems. This standardization also provides a clear specification for implementing VC validation and verification logic.

### JWE Encryption Support

The framework provides optional JWE (JSON Web Encryption) support for enhanced privacy protection of user prompts. When enabled, the VC's `source_prompt_credential` can be encrypted using JWE before being embedded in the PAR-JWT, ensuring that the user's original input remains confidential even in transit and at rest.

JWE encryption follows RFC 7516 and supports multiple encryption algorithms:

- **Key Encryption Algorithms**: RSA-OAEP, RSA-OAEP-256, ECDH-ES
- **Content Encryption Algorithms**: A128GCM, A192GCM, A256GCM, A128CBC-HS256, A256CBC-HS512

The encryption process uses the recipient's public key (obtained from their JWKS endpoint) to encrypt the VC, ensuring that only the intended recipient (typically the Authorization Server) can decrypt it using their private key. This end-to-end encryption provides an additional layer of security beyond the cryptographic signature, protecting sensitive user information from unauthorized access even if the token is intercepted.

JWE encryption is configurable and can be enabled or disabled based on security requirements. When disabled, the VC is transmitted as a standard JWS (JSON Web Signature) token, maintaining cryptographic integrity without confidentiality. This flexibility allows deployments to choose the appropriate security level based on their threat model and compliance requirements.

---

