## Workload Identity Token (WIT)

### Purpose and Architecture

The Workload Identity Token represents a fundamental innovation in the framework's security architecture: request-level isolation through virtual workloads. Unlike traditional identity providers that authenticate long-lived service accounts or processes, the Agent IDP creates temporary, isolated workloads for each user request. This approach enables fine-grained security boundaries with minimal overhead, which is particularly valuable in AI agent scenarios where each interaction may involve different operations, permissions, and security requirements.

When an agent needs to perform an operation on behalf of a user, it doesn't simply use a long-lived service account. Instead, it creates a dedicated virtual workload for that specific request. This workload has its own cryptographic identity, represented by the WIT, and its own key pair for signing subsequent requests. All operations the agent performs for that user are authenticated using this workload's credentials, ensuring that operations from different users cannot interfere with each other and that every action can be traced back to its originating user.

The WIT implements the WIMSE (Workload Identity and Management) protocol specification, providing a standardized approach to workload authentication that aligns with modern cloud-native security practices. It enables the framework to support multi-tenant environments where multiple users and agents operate concurrently without compromising isolation or auditability.

### Token Structure

The WIT is a JWT that follows the WIMSE protocol specification (draft-ietf-wimse-workload-creds). It contains standard claims that identify the workload and provide the public key for verifying Workload Proof Tokens (WPT).

```json
{
  "iss": "wimse://example-trust-domain",
  "sub": "agent-001",
  "aud": ["https://as.example.com", "https://api.example.com"],
  "exp": 1731668100,
  "iat": 1731664500,
  "jti": "wit-789xyz",
  
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  }
}
```

The `sub` claim is the core of the WIT's identity model and represents the Workload Identifier. This identifier is scoped within a trust domain and should be unique within that domain. The identifier format is implementation-specific and may follow standards such as SPIFFE (`spiffe://<trust-domain>/<workload-identifier>`) or other formats.

The `aud` claim specifies the intended audiences for this token, typically including the Authorization Server and Resource Servers that will accept this WIT for authentication. This ensures that the token cannot be used by unauthorized parties.

The `cnf` (confirmation) claim contains the workload's public key, which Resource Servers use to verify Workload Proof Tokens (WPT) signed by the workload's private key. This design ensures that the private key never leaves the workload's memory, minimizing the attack surface. The key pair is generated using strong cryptographic algorithms (ECDSA with P-256 curve by default) and exists only for the duration of the workload's lifetime, typically one hour.

### Workload Lifecycle and Management

The Agent IDP manages the complete lifecycle of workloads, from creation through expiration. When an agent requests a workload creation, it submits the user's ID Token and a newly generated public key to the Agent IDP. The Agent IDP validates the ID Token to ensure the user is authenticated, extracts the user's subject identifier, and creates a WIT that cryptographically binds the workload to that user.

The Agent IDP maintains a WorkloadRegistry that stores workload information including the workload ID, user ID, public key, creation timestamp, and expiration time. This registry enables the Agent IDP to validate WITs presented by agents and to perform cleanup operations when workloads expire. The registry implementation uses thread-safe data structures to support concurrent workload creation and validation, which is essential for high-throughput agent scenarios.

Workloads have a configurable expiration time (default 3600 seconds) and are automatically cleaned up when they expire. This time-bounded approach follows the principle of least privilege, granting credentials only for the duration needed to complete the operation. In the event of a security breach where credentials are compromised, the impact is limited to the remaining lifetime of the workload, reducing potential damage.

### Security Benefits

The virtual workload pattern provides several security advantages beyond traditional isolation mechanisms. First, it prevents cross-request contamination where operations from one user could inadvertently access data or perform actions intended for another user. Second, it enables fine-grained auditing where each operation can be traced to a specific workload and user, providing complete audit trails for compliance and security monitoring. Third, it supports dynamic resource allocation where workloads can be assigned different resource limits, priorities, or quality of service levels based on the operation context.

The temporary nature of workload credentials enhances security by limiting the window of opportunity for credential misuse. Unlike long-lived service accounts that provide persistent access, workload credentials exist only for the minimum necessary time and are automatically destroyed when the workload expires. This ephemeral approach significantly reduces the risk of credential theft and misuse.

---

