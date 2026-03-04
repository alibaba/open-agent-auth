# Security and Audit Architecture

The Security and Audit layer provides comprehensive protection and observability for the Open Agent Auth framework, ensuring that all authorization operations are cryptographically secure, fully auditable, and compliant with enterprise security requirements. This layer implements defense-in-depth principles with multiple layers of cryptographic protection, identity binding mechanisms, threat mitigation strategies, and comprehensive audit logging, following the Agent Operation Authorization specification's dual-layer security model where JWS protects tokens and W3C Verifiable Credentials protect prompts.

The security architecture is designed around the principle of zero trust, where every authorization request is treated as potentially hostile and must be thoroughly verified before being granted access. This approach ensures that even trusted components and users are continuously authenticated and authorized, reducing the attack surface and limiting the potential impact of security breaches. The audit architecture complements this by providing complete visibility into all authorization decisions, enabling security monitoring, compliance reporting, and forensic analysis through semantic audit trails that capture the complete context from user input to resource operation.

## Cryptographic Protection

The framework relies extensively on asymmetric cryptography for token signing and verification, leveraging the security properties of public-key cryptography to enable distributed authorization without requiring secret sharing. All tokens including ID Tokens, Workload Identity Tokens (WIT), Agent OA Tokens, and Workload Proof Tokens (WPT) are signed using asymmetric algorithms, allowing any component with access to the appropriate public key to verify the token's authenticity.

The framework supports multiple signing algorithms with ES256 (ECDSA with SHA-256) being the default for its strong security guarantees and good performance characteristics. ES256 provides equivalent security to RSA-2048 but with smaller key sizes and faster signature verification, making it well-suited for high-throughput authorization scenarios. The framework also supports RSA algorithms such as RS256 for environments where RSA infrastructure is already established, and ES384 and ES512 for higher security requirements where the performance overhead is acceptable.

Token signing is performed by the component that creates the token. Agent User IDP and AS User IDP sign ID Tokens using their private keys. Agent IDP signs WITs using its private key. Authorization Server signs Agent OA Tokens using its private key. Workloads sign WPTs using their temporary private keys. This distribution of signing responsibility ensures that each token's signature can be verified independently by any component with access to the corresponding public key.

Token verification is performed by components that receive tokens. Agents verify ID Tokens using the Agent User IDP's public key. Authorization Server verifies WITs using the Agent IDP's public key. Resource Servers verify Agent OA Tokens using the Authorization Server's public key and verify WPTs using the public key extracted from the WIT. This verification pattern enables authorization decisions to be made locally without requiring additional calls to the token issuer, improving performance and scalability.

While asymmetric cryptography is used for token signing and verification, the framework also uses symmetric cryptography for specific use cases where performance is critical or where shared secrets can be securely managed. Symmetric encryption is used for encrypting sensitive data at rest, such as private keys stored in configuration files or database records. Symmetric encryption is also used for encrypting sensitive claims within tokens, such as personal information in audit trails.

The framework supports AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) as the default symmetric encryption algorithm. AES-GCM provides both confidentiality and integrity in a single operation, making it ideal for encrypting sensitive data where tamper detection is important. The framework uses 256-bit keys for production deployments, providing strong security with acceptable performance.

For key derivation, the framework uses PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256 and configurable iteration counts. This approach enables secure derivation of encryption keys from passwords or passphrases, with the iteration count providing protection against brute force attacks. The framework recommends using key derivation only when necessary, preferring direct key management where possible.

Hash functions are used throughout the framework for various purposes including integrity verification, deduplication, and indexing. The framework uses SHA-256 as the default hash function for its strong collision resistance and widespread support. SHA-256 is used to hash sensitive data such as user identifiers for inclusion in tokens without exposing the original values.

Hash functions are also used to create identifiers for tokens and requests. The JWT identifier (jti) claim is often implemented as a hash of the token content or a cryptographic random value. Request URIs in PAR are generated as hash-based URIs that incorporate unique identifiers and timestamps to prevent collisions.

The framework implements constant-time hash comparison for security-sensitive comparisons such as verifying token hashes or comparing digests. Constant-time comparison prevents timing side-channel attacks where an attacker could learn information about the expected value based on comparison timing.

## Identity Binding and Consistency

Cryptographic identity binding is the cornerstone of the framework's security model, ensuring that user identity, workload identity, and authorization tokens remain consistently linked throughout the authorization flow. This binding is achieved through cryptographic signatures and claims that establish unforgeable relationships between different tokens and identities.

The binding process begins when the Agent IDP creates the WIT. The issuedTo field in the agent_identity claim is set to the user's subject identifier extracted from the validated ID Token. This field is cryptographically signed as part of the WIT, meaning it cannot be modified without invalidating the signature. This binding ensures that the WIT can only represent the specific user who authenticated to obtain the ID Token.

When the authorization server issues the Agent OA Token, it includes the same issuedTo field in the agent_identity claim, creating a three-way binding: ID Token.sub == WIT.agent_identity.issuedTo == Agent OA Token.sub. This binding is enforced through signature verification, ensuring that any attempt to modify the binding will be detected and rejected.

The framework also implements binding between workload identity and authorization tokens through the workloadId field. The Agent OA Token's agent_identity.workloadId field matches the WIT's sub field, ensuring that the authorization token can only be used by the specific workload that was bound to the user during authorization. This prevents token reuse across different workloads, even if they are bound to the same user.

Identity consistency verification occurs at multiple points in the authorization flow to ensure that the binding remains intact. The first verification happens at the Agent IDP when creating the WIT, where the ID Token's subject is extracted and bound to the workload. The second verification happens at the authorization server when processing the PAR request, where the consistency between ID Token and WIT is checked. The third verification happens at the resource server when validating access requests, where the consistency between WIT and Agent OA Token is verified.

The verification is implemented by specialized validator components that parse and validate each token type. The WitValidator checks the WIT signature using the Agent IDP's public key and extracts the agent_identity claims. The AoatValidator checks the Agent OA Token signature using the authorization server's public key and extracts the agent_identity claims. The IdentityConsistencyChecker compares the extracted claims to ensure they match.

These verification steps collectively prevent identity spoofing and authorization token misuse. Even if an attacker manages to obtain a valid Agent OA Token, they cannot use it without also possessing the corresponding WIT that is bound to the same user. Similarly, even if an attacker obtains a valid WIT, they cannot use it to obtain authorization for a different user because the WIT is cryptographically bound to a specific user identity.

## Key Management

The framework uses strong cryptographic algorithms for key generation, following current security best practices. For asymmetric keys, the framework generates keys using ECDSA with the P-256 curve by default, providing 128 bits of security. For higher security requirements, the framework supports P-384 and P-521 curves, providing 192 and 256 bits of security respectively.

For RSA keys, the framework uses a minimum key size of 2048 bits, with 3072 and 4096 bit keys supported for higher security requirements. The framework discourages the use of RSA keys smaller than 2048 bits due to known vulnerabilities.

Key generation uses cryptographically secure random number generators to ensure unpredictability. The framework uses platform-specific secure random sources such as `/dev/urandom` on Unix systems or `CryptGenRandom` on Windows, ensuring that keys cannot be predicted or brute-forced.

The framework supports key generation on-demand for temporary workloads. Each workload receives a unique key pair generated specifically for that workload, with the private key stored only in memory and destroyed when the workload expires. This ephemeral key management minimizes the attack surface by ensuring that workload credentials exist only for the minimum necessary time.

The framework provides in-memory key storage for cryptographic keys. Keys are generated on-demand and stored only in memory, with the private keys destroyed when the application shuts down or when the workload expires. This ephemeral key management minimizes the attack surface by ensuring that credentials exist only for the minimum necessary time.

For development and testing scenarios, configuration files or environment variables can be used to specify key parameters. The framework supports secure key generation using cryptographically secure random number generators, ensuring keys cannot be predicted or brute-forced.

The framework supports key rotation to limit the exposure of compromised keys and follow security best practices. Key rotation involves generating new keys, updating JWKS endpoints to include both old and new keys, waiting for old keys to expire, and then removing old keys from the JWKS endpoint.

The framework's JWKS endpoint supports multiple active keys, each with a unique key ID (kid). Tokens include the key ID in the JWT header, allowing verifiers to select the correct public key for signature verification. This mechanism enables smooth key rotation without requiring coordination between components.

The framework recommends a key rotation frequency of 90 days for production deployments, with more frequent rotation (30 days) for high-security environments. The rotation frequency should be based on the security requirements, operational constraints, and risk tolerance of the organization.

Key rotation can be automated using the framework's key management APIs or external orchestration tools. The framework provides hooks and events that can be used to trigger key rotation processes, enabling integration with existing key management workflows.

## Threat Mitigation

The framework implements multiple layers of protection against replay attacks, where an attacker captures a valid request or token and resubmits it to gain unauthorized access. The protection mechanisms operate at different levels of the authorization flow, providing defense in depth.

At the PAR layer, request URIs are single-use and expire after a short time (default 90 seconds). This prevents attackers from reusing valid authorization requests. The authorization server tracks which request URIs have been used and rejects any attempt to reuse a request URI. The short expiration time limits the window for replay attacks even if the tracking mechanism fails.

At the authorization code layer, codes are single-use and expire after a short time (default 10 minutes). Similar to request URIs, authorization codes are tracked and immediately invalidated after being exchanged for tokens. This prevents attackers from capturing authorization codes and reusing them.

At the token layer, tokens include expiration times and JWT identifiers. The JWT identifier enables token revocation tracking, allowing the authorization server to maintain a blacklist of revoked tokens. While the framework primarily relies on expiration for token invalidation, the blacklist provides a mechanism for immediate revocation in security incident scenarios.

At the request layer, the Workload Proof Token includes a timestamp that limits its validity window. The timestamp is verified during request validation, preventing attackers from replaying old valid requests. The signature also binds the request to specific HTTP components (method, URI, headers, body), preventing attackers from modifying the request components while keeping the signature valid.

The framework implements several mechanisms to protect against token theft and misuse. Tokens are signed using asymmetric cryptography, preventing attackers from forging valid tokens without access to the private keys. Token expiration limits the window of opportunity for token misuse, with expiration times configured based on the sensitivity of the authorized operation.

The framework supports token binding mechanisms that tie tokens to specific contexts. The WPT binds requests to specific HTTP components, preventing attackers from using valid tokens in different contexts. The Agent OA Token includes the workload ID in the agent_identity claim, binding the token to a specific workload and preventing token reuse across different workloads.

The framework implements rate limiting to prevent brute force attacks where an attacker might attempt to guess valid tokens. Rate limits are applied per IP address and per user, allowing legitimate users to make normal requests while blocking automated attack attempts.

The framework supports token introspection through the OAuth 2.0 Token Introspection endpoint, allowing resource servers to query the authorization server for token status and metadata. This enables real-time token validation and revocation, providing protection against token theft even after tokens have been issued.

The framework protects against man-in-the-middle attacks through multiple mechanisms. All communication between components is required to use TLS encryption, preventing attackers from intercepting and modifying traffic. The framework validates TLS certificates rigorously, ensuring that attackers cannot use self-signed or expired certificates.

Token signatures provide additional protection even if TLS is compromised. Since tokens are signed by the issuer, any modification to the token content invalidates the signature. This means that even if an attacker can intercept and modify traffic, they cannot forge valid tokens without access to the private keys.

The framework implements certificate pinning for critical connections, particularly JWKS endpoint lookups. Certificate pinning ensures that the framework only accepts specific certificates for these connections, preventing attackers from using compromised certificate authorities to issue fraudulent certificates.

The framework supports mutual TLS (mTLS) for component-to-component communication, requiring both parties to present valid certificates. This provides strong authentication and prevents attackers from impersonating legitimate components even if they can intercept traffic.

## Audit and Compliance

The framework maintains comprehensive audit logs of all authorization-related events, providing a complete record of who did what, when, and with what result. Audit logs are generated for all critical events including user authentication, workload creation, authorization requests, policy evaluations, token issuances, and resource access attempts.

Each audit log entry includes a timestamp with millisecond precision, the user identity (subject identifier), the workload identity (workload ID), the event type (authentication, authorization, evaluation, etc.), the event outcome (success, failure, error), and detailed event context including request parameters, policy identifiers, and decision reasons. This comprehensive information enables security teams to reconstruct complete authorization flows and investigate incidents.

Audit logs are structured using a consistent format that can be easily parsed and analyzed. The framework supports multiple output formats including JSON for machine processing, key-value pairs for log aggregation systems, and plain text for human readability. The structured format enables automated analysis and reporting, which is essential for compliance and security monitoring.

The Agent OA Token includes an audit_trail claim that captures the complete audit information for the authorization decision. This claim includes the authorization timestamp, user consent indicator, consent IP address, consent user agent, and semantic extension level. This information travels with the token, enabling resource servers to access the complete audit context without requiring additional lookups.

The audit trail is cryptographically signed as part of the token, ensuring its integrity and authenticity. Resource servers can trust the audit trail information without needing to verify it with the authorization server, enabling distributed authorization decisions while maintaining auditability.

The audit trail also includes the promptVc field, which contains a W3C Verifiable Credential representing the user's original input. This credential provides cryptographically verifiable proof of the user's intent, enabling forensic analysis and compliance verification. The VC includes the original prompt text, rendered operation description, and semantic extension level, all signed by the agent to prevent tampering. This dual-layer protection—JWS for the token and VC for the prompt—ensures that the transformation from user intent to authorized operation is transparent, auditable, and verifiable, supporting post-hoc analysis in case of disputes or compliance audits.

The framework's audit capabilities support various compliance requirements including GDPR, HIPAA, PCI-DSS, and SOX. The comprehensive audit logs provide the evidence needed to demonstrate compliance with regulatory requirements for access control, data protection, and auditability.

The framework supports configurable retention policies for audit logs, allowing organizations to retain logs for the duration required by their compliance obligations. Logs can be exported to external systems such as SIEM platforms, data warehouses, or compliance management systems for long-term storage and analysis.

The framework provides audit reporting capabilities that can generate compliance reports on demand. These reports can be customized to include specific event types, time ranges, users, or resources. Reports can be exported in various formats including PDF, CSV, and JSON, enabling integration with compliance management workflows.

## Implementation Details

The framework uses standard, well-vetted cryptographic libraries to ensure the security of cryptographic operations. For JWT and JWS functionality, the framework uses the Nimbus JOSE+JWT library, which is widely used and regularly audited for security vulnerabilities. For cryptographic operations, the framework uses the Java Cryptography Architecture (JCA) with providers such as Bouncy Castle for additional algorithm support.

The framework abstracts cryptographic operations behind interfaces, allowing cryptographic libraries to be replaced without requiring changes to application code. This abstraction enables organizations to use FIPS-validated cryptographic libraries in regulated environments where FIPS compliance is required.

The framework implements constant-time operations for security-sensitive comparisons and validations, preventing timing side-channel attacks. This is particularly important for token signature verification and hash comparisons, where timing variations could leak information about expected values.

The framework's audit logging is implemented using the SLF4J logging facade, allowing integration with various logging frameworks such as Logback, Log4j2, and java.util.logging. This flexibility enables organizations to use their preferred logging infrastructure while maintaining consistent audit log formats.

Audit logs are written to multiple destinations to ensure durability and availability. Logs are written to local files for immediate access, to centralized log aggregation systems for long-term storage and analysis, and to external SIEM platforms for security monitoring. This multi-destination approach ensures that logs are not lost due to single points of failure.

The framework implements audit log buffering to improve performance while ensuring durability. Audit events are buffered in memory and periodically flushed to storage, reducing I/O overhead. The buffer size and flush interval are configurable, allowing organizations to tune performance based on their requirements.

The framework provides comprehensive security monitoring capabilities through integration with monitoring systems such as Prometheus, Grafana, and ELK Stack. Metrics are exposed for critical security events including authentication failures, authorization denials, suspicious access patterns, and anomalous behavior.

The framework supports real-time alerting based on security events and metrics. Alerts can be configured for specific event types such as repeated authorization failures, access to sensitive resources, or unusual access patterns. These alerts enable proactive security monitoring and rapid response to potential security incidents.

The framework implements anomaly detection using machine learning algorithms to identify unusual access patterns that may indicate security threats. Anomaly detection considers factors such as access frequency, access patterns, time of day, geographic location, and resource sensitivity to identify potentially malicious activity.

## Performance Considerations

Cryptographic operations are computationally expensive and can impact performance if not optimized properly. The framework implements several optimizations to minimize the performance impact of cryptographic operations while maintaining security.

Signature verification results are cached for the token's lifetime, avoiding repeated verification of the same token. The cache key includes the token's JWT identifier and a hash of the token content, ensuring that modified tokens are not cached incorrectly. This caching significantly reduces the overhead of signature verification for frequently accessed tokens.

The framework uses optimized cryptographic libraries that leverage hardware acceleration when available. Modern CPUs include instructions for accelerating cryptographic operations such as AES-NI for symmetric encryption and SHA extensions for hash functions. The framework automatically uses these hardware accelerations when available, improving performance without sacrificing security.

The framework supports parallel cryptographic operations for scenarios where multiple tokens or signatures need to be verified. Parallel processing takes advantage of multi-core processors to reduce overall verification time, particularly important for high-throughput authorization scenarios.

Audit logging can impact performance if not implemented carefully. The framework implements several optimizations to minimize the performance impact of audit logging while ensuring comprehensive auditability.

Audit events are buffered in memory and periodically flushed to storage, reducing I/O overhead. The buffer size and flush interval are configurable, allowing organizations to tune performance based on their requirements. Asynchronous logging is supported, where audit events are written to a separate thread to avoid blocking the main request processing thread.

The framework implements audit log compression to reduce storage requirements and I/O overhead. Compression is particularly effective for audit logs that contain repetitive information such as user identifiers, resource identifiers, and event types.

The framework supports selective audit logging, where organizations can configure which events are logged based on their security requirements. This allows organizations to reduce audit volume by logging only critical events while still maintaining comprehensive security visibility.

The framework is designed to minimize memory footprint while providing comprehensive security capabilities. Caches are sized appropriately to balance performance with memory usage, and cache eviction policies are implemented to prevent unbounded memory growth.

The framework uses efficient data structures for storing and accessing security-related data. For example, token validation results are stored in a hash map indexed by token identifier for O(1) lookup performance, with automatic eviction of expired entries to prevent memory leaks.

The framework implements memory pooling for expensive objects such as cryptographic contexts and buffers. Object pooling reduces the overhead of object creation and garbage collection, improving throughput under high load while maintaining predictable memory usage.

The framework supports memory profiling and tuning, providing metrics on memory usage by different components. This enables operators to identify memory-intensive components and tune cache sizes and other parameters for optimal memory efficiency.
