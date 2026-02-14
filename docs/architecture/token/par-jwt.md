## PAR-JWT (Pushed Authorization Request JWT)

### Purpose and Design Philosophy

The PAR-JWT serves as the vehicle for the agent's authorization proposal, carrying the operation request, user intent evidence, and identity binding information to the Authorization Server in a secure, structured format. It follows OAuth 2.0 Pushed Authorization Requests (RFC 9126), which addresses a critical security vulnerability in traditional OAuth flows: the exposure of sensitive authorization parameters in URLs.

In traditional OAuth 2.0 authorization code flows, authorization parameters are transmitted as query parameters in the redirect URL. This exposes sensitive information—including scopes, requested permissions, and potentially user data—to browser history, server logs, and network intermediaries. The PAR protocol addresses this by having the client submit authorization parameters directly to the Authorization Server via a POST request, receiving a single-use `request_uri` that is then used in the redirect. This design ensures that sensitive information never appears in URLs.

The PAR-JWT extends this pattern by encoding the authorization request as a JWT, which provides additional security benefits. The JWT can be signed by the client, providing cryptographic proof of the request's origin. It can include custom claims that carry agent-specific information such as operation proposals, evidence credentials, and identity binding proposals. This enables a rich authorization request that captures the complete context of the agent's request.

### Token Structure

The PAR-JWT contains both standard OAuth 2.0 claims and custom claims specific to the Agent Operation Authorization framework.

```json
{
  "iss": "https://agent.example.com",
  "sub": "user_12345",
  "aud": "https://as.example.com",
  "exp": 1731668100,
  "iat": 1731664500,
  "jti": "par-req-456",
  
  "response_type": "code",
  "client_id": "agent_client_id",
  "redirect_uri": "https://agent.example.com/callback",
  "scope": "openid agent:operation",
  
  "evidence": {
    "source_prompt_credential": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  
  "agent_user_binding_proposal": {
    "user_identity_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "agent_workload_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
    "device_fingerprint": "dfp_abc123"
  },
  
  "agent_operation_proposal": "package agent\nallow { input.transaction.amount <= 50.0 }",
  
  "context": {
    "channel": "mobile-app",
    "deviceFingerprint": "dfp_abc123",
    "language": "zh-CN",
    "user": {
      "id": "user_12345"
    },
    "agent": {
      "instance": "dfp_abc123",
      "platform": "personal-agent.example.com",
      "client": "mobile-app-v1"
    }
  }
}
```

The `evidence` claim contains a Verifiable Credential (JWT-VC) that cryptographically captures the user's original natural language input. The `source_prompt_credential` field within the evidence is a JWT string containing the full Verifiable Credential structure. This credential serves as tamper-evident evidence of the user's intent, enabling the Authorization Server to present the original prompt to the user during the consent flow and enabling audit trails for compliance and dispute resolution.

The `agent_user_binding_proposal` claim proposes the binding between the user and the workload. It contains the user's ID Token and the workload's WIT, enabling the Authorization Server to verify that the workload requesting authorization is indeed bound to the authenticated user. The `device_fingerprint` field provides additional context about the client device, which can be used for fraud detection and security analytics.

The `agent_operation_proposal` claim contains a Rego policy string that defines the operation the agent wants to perform. This policy will be evaluated by the Open Policy Agent (OPA) at runtime to make fine-grained authorization decisions. The policy can express complex conditions and business logic, enabling the framework to support sophisticated authorization scenarios beyond simple scope-based permissions.

The `context` claim provides additional information for policy evaluation, including the interaction channel, device fingerprint, user language preference, and agent context. This information enables context-aware authorization decisions that consider factors such as the user's location, the device's security posture, and the agent's deployment characteristics.

### Authorization Flow

The PAR-JWT participates in a multi-step authorization flow that ensures user consent and cryptographic verification of all components. When the agent receives a user's natural language request, it parses the intent and constructs an operation proposal in the form of a Rego policy. It then creates a Verifiable Credential capturing the user's original prompt, including the timestamp, channel information, and device fingerprint. The agent builds the PAR-JWT with all required claims and signs it with its private key.

The agent submits the PAR-JWT to the Authorization Server via a POST request to the `/par` endpoint. The Authorization Server validates the PAR-JWT's signature, extracts and validates the embedded evidence and identity binding information, and generates a single-use `request_uri`. The Authorization Server stores the PAR-JWT temporarily, associating it with the `request_uri`, and returns the `request_uri` to the agent.

The agent then redirects the user's browser to the Authorization Server's authorization endpoint with the `request_uri` as a parameter. The Authorization Server retrieves the stored PAR-JWT, presents the user with a consent interface that shows the original prompt (from the evidence credential) and the interpreted operation (from the operation proposal), and waits for the user's approval.

### Security Advantages

The PAR-JWT design provides several important security advantages. By using the PAR protocol, it prevents sensitive authorization data from appearing in URLs, protecting against leakage through browser history, server logs, and network intermediaries. By encoding the request as a JWT, it enables cryptographic verification of the request's origin and integrity. By including custom claims for evidence and identity binding, it enables a rich authorization request that captures the complete context of the agent's request.

The single-use `request_uri` prevents replay attacks, ensuring that each authorization request can only be used once. The temporary storage of the PAR-JWT ensures that sensitive data is not persisted indefinitely, reducing the attack surface. The cryptographic signature on the PAR-JWT ensures that the request cannot be modified without detection.

---

