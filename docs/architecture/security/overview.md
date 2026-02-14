# Security and Audit Architecture

## Overview

The Security and Audit layer provides comprehensive protection and observability for the Open Agent Auth framework, ensuring that all authorization operations are cryptographically secure, fully auditable, and compliant with enterprise security requirements. This layer implements defense-in-depth principles with multiple layers of cryptographic protection, identity binding mechanisms, threat mitigation strategies, and comprehensive audit logging, following the Agent Operation Authorization specification's dual-layer security model where JWS protects tokens and W3C Verifiable Credentials protect prompts.

The security architecture is designed around the principle of zero trust, where every authorization request is treated as potentially hostile and must be thoroughly verified before being granted access. This approach ensures that even trusted components and users are continuously authenticated and authorized, reducing the attack surface and limiting the potential impact of security breaches. The audit architecture complements this by providing complete visibility into all authorization decisions, enabling security monitoring, compliance reporting, and forensic analysis through semantic audit trails that capture the complete context from user input to resource operation.

## Cryptographic Protection

### Asymmetric Cryptography

The framework relies extensively on asymmetric cryptography for token signing and verification, leveraging the security properties of public-key cryptography to enable distributed authorization without requiring secret sharing. All tokens including ID Tokens, Workload Identity Tokens (WIT), Agent OA Tokens, and Workload Proof Tokens (WPT) are signed using asymmetric algorithms, allowing any component with access to the appropriate public key to verify the token's authenticity.

The framework supports multiple signing algorithms with ES256 (ECDSA with SHA-256) being the default for its strong security guarantees and good performance characteristics. ES256 provides equivalent security to RSA-2048 but with smaller key sizes and faster signature verification, making it well-suited for high-throughput authorization scenarios. The framework also supports RSA algorithms such as RS256 for environments where RSA infrastructure is already established, and ES384 and ES512 for higher security requirements where the performance overhead is acceptable.

Token signing is performed by the component that creates the token. Agent User IDP and AS User IDP sign ID Tokens using their private keys. Agent IDP signs WITs using its private key. Authorization Server signs Agent OA Tokens using its private key. Workloads sign WPTs using their temporary private keys. This distribution of signing responsibility ensures that each token's signature can be verified independently by any component with access to the corresponding public key.

Token verification is performed by components that receive tokens. Agents verify ID Tokens using the Agent User IDP's public key. Authorization Server verifies WITs using the Agent IDP's public key. Resource Servers verify Agent OA Tokens using the Authorization Server's public key and verify WPTs using the public key extracted from the WIT. This verification pattern enables authorization decisions to be made locally without requiring additional calls to the token issuer, improving performance and scalability.

### Symmetric Cryptography

While asymmetric cryptography is used for token signing and verification, the framework also uses symmetric cryptography for specific use cases where performance is critical or where shared secrets can be securely managed. Symmetric encryption is used for encrypting sensitive data at rest, such as private keys stored in configuration files or database records. Symmetric encryption is also used for encrypting sensitive claims within tokens, such as personal information in audit trails.

The framework supports AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) as the default symmetric encryption algorithm. AES-GCM provides both confidentiality and integrity in a single operation, making it ideal for encrypting sensitive data where tamper detection is important. The framework uses 256-bit keys for production deployments, providing strong security with acceptable performance.

For key derivation, the framework uses PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256 and configurable iteration counts. This approach enables secure derivation of encryption keys from passwords or passphrases, with the iteration count providing protection against brute force attacks. The framework recommends using key derivation only when necessary, preferring direct key management where possible.

### Hash Functions

Hash functions are used throughout the framework for various purposes including integrity verification, deduplication, and indexing. The framework uses SHA-256 as the default hash function for its strong collision resistance and widespread support. SHA-256 is used to hash sensitive data such as user identifiers for inclusion in tokens without exposing the original values.

Hash functions are also used to create identifiers for tokens and requests. The JWT identifier (jti) claim is often implemented as a hash of the token content or a cryptographic random value. Request URIs in PAR are generated as hash-based URIs that incorporate unique identifiers and timestamps to prevent collisions.

The framework implements constant-time hash comparison for security-sensitive comparisons such as verifying token hashes or comparing digests. Constant-time comparison prevents timing side-channel attacks where an attacker could learn information about the expected value based on comparison timing.

