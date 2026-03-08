# WIMSE + OAuth DCR Integration

This document describes the integration of WIMSE (Workload Identity in Multi System Environments) with OAuth 2.0 Dynamic Client Registration (DCR) in the Open Agent Auth framework. It covers the complete protocol foundation, architecture design, implementation details, and security considerations for enabling workloads to dynamically register as OAuth clients and authenticate using cryptographic key binding.

The integration addresses a fundamental challenge in agent-based authorization: workloads need to dynamically register with an Authorization Server without pre-provisioned credentials, establish their identity through a trusted third party, and maintain cryptographic key consistency across all subsequent interactions. By combining WIMSE's Workload Identity Token (WIT) with OAuth DCR's software statement mechanism and `private_key_jwt` authentication, the framework provides a standards-compliant, secure, and efficient solution for workload-based client registration and authentication.

## Protocol Foundation

### OAuth 2.0 Dynamic Client Registration (RFC 7591)

OAuth 2.0 Dynamic Client Registration (DCR) defines a protocol that allows OAuth clients to register with an Authorization Server programmatically, without requiring manual pre-registration. RFC 7591 specifies the Client Registration Endpoint, the client metadata format, and the registration response structure.

The DCR protocol involves two key phases: the registration phase where the client provides its metadata to the Authorization Server, and the subsequent authentication phase where the registered client authenticates itself when requesting tokens.

During registration, the client sends a POST request to the Client Registration Endpoint with a JSON body containing client metadata. The `token_endpoint_auth_method` field declares how the client will authenticate in subsequent token requests. When set to `private_key_jwt`, the client commits to using JWT-based client authentication with asymmetric keys, as defined in RFC 7523.

The client provides its public keys through one of two mechanisms: `jwks_uri` provides a URL where the Authorization Server can fetch the client's JWK Set dynamically, while `jwks` provides the JWK Set inline in the registration request. These two mechanisms are mutually exclusive. The `jwks` approach is preferred for workload scenarios where the workload may not have a stable, publicly accessible URL for hosting its keys.

RFC 7591 Section 2.3 defines the `software_statement` mechanism, which allows a trusted third party to vouch for the client's identity by providing a signed JWT containing the client's metadata. The Authorization Server verifies the software statement's signature against the trusted third party's public key, establishing a chain of trust from the third party to the client. This mechanism is the foundation for integrating WIMSE identity into the DCR flow.

### JWT Profile for OAuth 2.0 Client Authentication (RFC 7523)

RFC 7523 defines how clients authenticate to the Authorization Server using JWT assertions. In the `private_key_jwt` mode, the client constructs a JWT with specific claims, signs it with its private key, and sends it as the `client_assertion` parameter in token requests.

The client assertion JWT must contain the following claims:

- **`iss` (Issuer):** Must be the client's `client_id`, identifying the JWT issuer as the client itself.
- **`sub` (Subject):** Must be the client's `client_id`, identifying the subject of the assertion.
- **`aud` (Audience):** Must be the Authorization Server's issuer identifier (as defined in RFC 8414 Authorization Server Metadata). Per the latest security update in draft-ietf-oauth-rfc7523bis-06, the `aud` value must be the issuer identifier as the sole value. Using the token endpoint URL as the audience is no longer permitted due to the audience injection vulnerability disclosed in January 2025 by Stuttgart University security researchers.
- **`jti` (JWT ID):** A unique identifier for the JWT, used to prevent replay attacks. Each assertion must use a different `jti` value, and the Authorization Server should maintain a record of used `jti` values.
- **`exp` (Expiration Time):** The expiration time of the JWT, typically set to a few minutes after issuance.
- **`iat` (Issued At):** The time at which the JWT was issued.

The JWT Header should include `typ` set to `client-authentication+jwt` (recommended by draft-ietf-oauth-rfc7523bis-06) to explicitly distinguish client authentication JWTs from other JWT types. The `alg` field must specify a non-symmetric signing algorithm such as ES256, RS256, or PS256. The `kid` field should match the key ID of the public key registered during DCR.

The client assertion is sent to the Token Endpoint as:

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<authorization_code>&
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&
client_assertion=<signed JWT>
```

The `client_assertion_type` value is fixed as `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, defined by RFC 7523. Since authentication is based entirely on asymmetric key pairs, no `client_secret` is issued or required.

### WIMSE Protocol

WIMSE (Workload Identity in Multi System Environments) is an IETF working group protocol that addresses how workloads in microservice, containerized, and multi-cloud environments obtain trusted identity credentials and perform cross-system authentication without relying on manually pre-allocated long-term keys.

The WIMSE architecture (draft-ietf-wimse-arch-07) defines the concept of a Workload Identity Token (WIT), which is a JWT issued by a WIMSE Identity Server that binds a workload's identity to a specific cryptographic key pair. The WIT contains the workload's unique identifier in the `sub` claim and the workload's public key in the `cnf.jwk` (confirmation key) claim. The WIT is signed by the Identity Server's private key, allowing any party that trusts the Identity Server to verify the workload's identity.

The key characteristic of WIT is that it implements Proof of Possession (PoP): holding the WIT alone is not sufficient to prove identity. The workload must also demonstrate possession of the private key corresponding to the public key bound in `cnf.jwk`. This design aligns perfectly with `private_key_jwt` authentication, where the client assertion signature serves as the proof of possession.

The WIMSE S2S protocol (draft-ietf-wimse-s2s-protocol-07) specifies that WIT must not be used as a bearer token. Instead, it must be accompanied by a Workload Proof Token (WPT) or HTTP Message Signatures that prove private key possession. This security requirement is inherently satisfied in the DCR integration because the `private_key_jwt` client assertion signature provides the required proof of possession.

### Why Combine WIMSE with OAuth DCR

The combination of WIMSE and OAuth DCR addresses a specific scenario: a workload starts up, needs to register itself with an OAuth Authorization Server, and does not hold any pre-provisioned `client_id` or `client_secret`. Instead, the workload uses the identity credential issued by the WIMSE Identity Server (or platform infrastructure) to establish its identity during registration.

The WIT serves as a natural software statement because it is a signed JWT from a trusted third party (the Identity Server) that contains the workload's identity and public key binding. The Authorization Server can verify the WIT signature, extract the workload identifier, and register the workload as an OAuth client with the public key from the WIT's `cnf.jwk` claim.

After registration, the workload uses the same private key for `private_key_jwt` authentication in all subsequent interactions (PAR requests, token exchanges), maintaining cryptographic key consistency across the entire authorization flow.

## Architecture Design

### Overall Flow

The integration consists of three sequential phases that transform a workload from an unregistered entity with only a WIMSE identity into a fully authenticated OAuth client:

```
Phase 1: Credential Bootstrap    →  Workload obtains WIT from WIMSE Identity Server
Phase 2: Dynamic Client Registration  →  Workload registers with AS using WIT as software statement
Phase 3: Authenticated Operations     →  Workload authenticates using private_key_jwt
```

### Phase 1: Credential Bootstrap (WIT Acquisition)

The workload obtains a Workload Identity Token (WIT) from the WIMSE Identity Server. The acquisition method varies by deployment environment:

- **Kubernetes:** Through projected service account tokens or Token Request API, the workload obtains a platform credential and exchanges it with the Identity Server for a WIT.
- **SPIFFE:** Through the Workload API (typically over Unix Domain Socket), the workload obtains a JWT-SVID or X509-SVID.
- **Cloud Platforms:** Through Instance Metadata Service (IMDS), the workload obtains platform-specific credentials for WIT exchange.
- **Agent-assisted:** Through an agent process that manages credential distribution to workloads.

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────────────┐
│  Workload   │      │  WIMSE IDP       │      │  Trust Anchor        │
└──────┬──────┘      └────────┬─────────┘      └──────────┬───────────┘
       │                      │                           │
       │ 1. Request WIT       │                           │
       │  (with platform      │                           │
       │   credential +       │                           │
       │   public key)        │                           │
       │─────────────────────>│                           │
       │                      │                           │
       │                      │ 2. Verify platform        │
       │                      │    credential, bind       │
       │                      │    public key to WIT      │
       │                      │                           │
       │                      │ 3. Sign WIT with          │
       │                      │    Identity Server key    │
       │                      │──────────────────────────>│
       │                      │                           │
       │                      │ 4. Return signed WIT      │
       │                      │<──────────────────────────│
       │                      │                           │
       │ 5. WIT (with cnf.jwk)│                           │
       │<─────────────────────│                           │
```

**WIT Structure (based on draft-ietf-wimse-s2s-protocol-07 Section 3.1):**

JOSE Header:
```json
{
  "alg": "ES256",
  "kid": "identity-server-key-1",
  "typ": "wit+jwt"
}
```

JWT Claims:
```json
{
  "sub": "wimse://example.com/my-service",
  "iss": "https://identity-server.example.com",
  "exp": 1709917200,
  "iat": 1709913600,
  "jti": "wit-unique-id-001",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "kid": "workload-key-1",
      "x": "kXqnA2Op7hgd4zRMbw0iFcc_hDxUxhojxOFVGjE2gks",
      "y": "n__VndPMR021-59UAs0b9qDTFT-EZtT6xSNs_xFskLo"
    }
  }
}
```

Key characteristics of the WIT:

- The WIT is signed by the Identity Server's private key, enabling third-party verification.
- The `sub` claim contains the workload's unique identifier within its trust domain.
- The `cnf.jwk` claim binds the WIT to the workload's public key, meaning that possessing the WIT alone does not prove identity — the corresponding private key must also be demonstrated.
- The `typ` header is set to `wit+jwt` to distinguish WITs from other JWT types.
- The WIT is short-lived (typically hours), limiting the window of exposure if compromised.

### Phase 2: Dynamic Client Registration (DCR with Software Statement)

The workload registers with the Authorization Server using the WIT as a software statement. This is **Path A** (Software Statement mode) from the WIMSE + DCR integration options, which is the approach implemented in this framework.

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────────────┐
│  Workload   │      │  Agent Actor     │      │  Authorization Server│
└──────┬──────┘      └────────┬─────────┘      └──────────┬───────────┘
       │                      │                           │
       │ 1. DCR Request       │                           │
       │─────────────────────>│                           │
       │ (WIT + jwks)         │                           │
       │                      │                           │
       │                      │ 2. POST /register         │
       │                      │──────────────────────────>│
       │                      │ {                         │
       │                      │   "software_statement":   │
       │                      │     "<WIT JWT>",          │
       │                      │   "token_endpoint_auth_   │
       │                      │    method": "private_key_ │
       │                      │    jwt",                  │
       │                      │   "grant_types":          │
       │                      │     ["client_credentials"]│
       │                      │   "jwks": {...}           │
       │                      │ }                         │
       │                      │                           │
       │                      │ 3. Validate:              │
       │                      │    - WIT signature        │
       │                      │    - WIT claims           │
       │                      │    - cnf.jwk == jwks      │
       │                      │                           │
       │                      │ 4. Register client        │
       │                      │    (client_id = WIT.sub)  │
       │                      │<──────────────────────────│
       │                      │                           │
       │ 5. DcrResponse       │                           │
       │<─────────────────────│                           │
       │ (client_id,          │                           │
       │  jwks stored)        │                           │
```

**DCR Request Body:**

```json
{
  "software_statement": "<WIT JWT value>",
  "token_endpoint_auth_method": "private_key_jwt",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "jwks": {
    "keys": [
      {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": "workload-key-1",
        "x": "kXqnA2Op7hgd4zRMbw0iFcc_hDxUxhojxOFVGjE2gks",
        "y": "n__VndPMR021-59UAs0b9qDTFT-EZtT6xSNs_xFskLo"
      }
    ]
  }
}
```

Note that the `jwks` field contains only the public key (no `d` parameter). The private key is never transmitted and remains solely with the workload.

**DCR Response:**

```json
{
  "client_id": "wimse://example.com/my-service",
  "client_id_issued_at": 1709913600,
  "token_endpoint_auth_method": "private_key_jwt",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "jwks": {
    "keys": [...]
  }
}
```

Since the authentication method is `private_key_jwt`, no `client_secret` is included in the response. Client authentication is entirely based on the asymmetric key pair.

**Authorization Server Validation Steps:**

1. Extract the `software_statement` field from the DCR request body.
2. Parse the software statement as a JWT (the WIT).
3. Verify the WIT signature using the WIMSE Identity Server's public key (trust anchor).
4. Validate the WIT claims: check `iss` against trusted issuers, verify `exp` is not past, verify `nbf` (if present) is not in the future, and validate `aud` (if present) is appropriate.
5. Extract the `sub` claim from the WIT — this becomes the `client_id`.
6. Extract the `cnf.jwk` from the WIT and compare it against the `jwks` provided in the DCR request body. Only the core cryptographic key material is compared (kty, crv, x, y for EC keys; kty, n, e for RSA keys). Metadata fields such as `kid`, `alg`, and `use` are excluded from comparison because different representations of the same key may carry different metadata.
7. If all validations pass, register the client with the extracted `client_id` and store the `jwks` for future `private_key_jwt` verification.

### Alternative: Path B (Token Exchange)

While this framework implements Path A (Software Statement), an alternative approach exists for cross-trust-domain scenarios. In Path B, the workload first exchanges its WIT for an Initial Access Token via RFC 8693 Token Exchange, then uses that token to authenticate the DCR request via the `Authorization: Bearer` header.

Path B provides stronger decoupling because the Authorization Server does not need to understand the WIT format directly — it only needs to trust the Token Exchange endpoint. However, Path B requires an additional round-trip and a Token Exchange endpoint, making it more complex. Path A is preferred for scenarios where the Authorization Server and WIMSE Identity Server share a direct trust relationship (e.g., within the same organization).

### Phase 3: Authenticated Operations (private_key_jwt)

After registration, the workload uses `private_key_jwt` authentication for all subsequent interactions with the Authorization Server, including PAR requests and token exchanges. The critical security property is that the private key used for signing client assertions is the same key whose public counterpart is bound in the WIT's `cnf.jwk` claim, ensuring cryptographic key consistency across the entire flow.

```
┌─────────────┐      ┌──────────────────┐      ┌──────────────────────┐
│  Workload   │      │  Agent Actor     │      │  Authorization Server│
└──────┬──────┘      └────────┬─────────┘      └──────────┬───────────┘
       │                      │                           │
       │ 1. PAR/Token Request │                           │
       │─────────────────────>│                           │
       │                      │                           │
       │                      │ 2. Construct client       │
       │                      │    assertion JWT          │
       │                      │                           │
       │                      │ 3. POST /par or /token    │
       │                      │──────────────────────────>│
       │                      │ client_assertion_type=    │
       │                      │   urn:ietf:params:oauth:  │
       │                      │   client-assertion-type:  │
       │                      │   jwt-bearer              │
       │                      │ client_assertion=         │
       │                      │   <signed JWT>            │
       │                      │                           │
       │                      │ 4. Validate:              │
       │                      │    - Parse JWT header     │
       │                      │    - Look up client by    │
       │                      │      iss/sub claim        │
       │                      │    - Fetch registered     │
       │                      │      jwks                 │
       │                      │    - Select key by kid    │
       │                      │    - Verify signature     │
       │                      │    - Validate aud, exp,   │
       │                      │      jti                  │
       │                      │                           │
       │                      │ 5. Process request        │
       │                      │<──────────────────────────│
       │                      │                           │
       │ 6. Response          │                           │
       │<─────────────────────│                           │
```

**Client Assertion JWT Structure:**

JOSE Header:
```json
{
  "typ": "client-authentication+jwt",
  "alg": "ES256",
  "kid": "workload-key-1"
}
```

JWT Claims:
```json
{
  "iss": "wimse://example.com/my-service",
  "sub": "wimse://example.com/my-service",
  "aud": "https://as.example.com",
  "jti": "a1b2c3d4-unique-assertion-id",
  "iat": 1709913600,
  "exp": 1709913900
}
```

The `iss` and `sub` are both set to the `client_id` (which equals the WIT's `sub`). The `aud` is the Authorization Server's issuer identifier. The assertion is signed with the workload's private key — the same key whose public counterpart is registered in the client's JWKS and bound in the WIT's `cnf.jwk`.

**Authorization Server Verification Flow:**

1. Extract `client_assertion` from the request parameters.
2. Parse the JWT Header to obtain `kid` and `alg`.
3. Extract `iss` or `sub` from the JWT Claims to identify the client.
4. Look up the client's registered JWKS from the client store.
5. Select the verification key from the JWKS using `kid` (via `JwkUtils.selectVerificationKey()`).
6. Create a signature verifier for the key type (via `SignatureVerificationUtils.createVerifier()`).
7. Verify the JWT signature.
8. Validate claims: confirm `aud` matches the AS's issuer identifier, `exp` is not past, and `jti` has not been previously used (replay prevention).
9. If all validations pass, the client is authenticated.

## Implementation Details

### Agent Side (Client)

#### WimseOAuth2DcrClientAuthentication

Applies WIMSE authentication to DCR requests using the standard `software_statement` mechanism defined in RFC 7591 Section 2.3.

**Key Behavior:**
- Extracts WIT from `DcrRequest.softwareStatement` (preferred) or legacy `wit` parameter for backward compatibility.
- Places the WIT in the `software_statement` field of the DCR request body.
- Cleans up legacy parameters to ensure the request conforms to the standard format.

**Code Location:** `open-agent-auth-core/.../protocol/oauth2/dcr/client/authentication/WimseOAuth2DcrClientAuthentication.java`

#### ClientAssertionGenerator

Generates standard RFC 7523 client assertion JWTs for `private_key_jwt` authentication.

**Key Features:**
- Supports both EC (ES256, ES384, ES512) and RSA (RS256, RS384, RS512, PS256, PS384, PS512) keys.
- Generates JWT with all required claims: `iss`, `sub`, `aud`, `jti`, `iat`, `exp`.
- Sets `typ` header to `client-authentication+jwt` per draft-ietf-oauth-rfc7523bis-06 recommendation.
- Uses 5-minute default expiration to minimize the window of exposure.
- Generates cryptographically random `jti` values to prevent replay attacks.

**Code Location:** `open-agent-auth-core/.../protocol/oauth2/client/ClientAssertionGenerator.java`

#### ClientAssertionAuthentication

Applies `private_key_jwt` authentication to token requests by generating a client assertion and adding the required parameters.

**Key Behavior:**
- Generates client assertion using `ClientAssertionGenerator`.
- Adds `client_assertion_type` (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) and `client_assertion` parameters to the request.
- Supports `workload_private_key` mode where the signing key comes from the workload context.

#### DefaultAgent

Orchestrates the complete DCR → PAR → Token flow as the top-level agent implementation.

**Flow:**
1. Obtain WIT from WIMSE IDP via `issueWorkloadIdentityToken()`.
2. Register OAuth client using DCR with WIT as software statement via `registerOAuthClient()`.
3. Store client credentials and JWKS in the authorization context.
4. Submit PAR request with client assertion via `submitParRequest()`.
5. Handle authorization callback and exchange code for token via `handleAuthorizationCallback()`.
6. Prepare authorization context for tool execution via `prepareAuthorizationContext()`.

### Authorization Server Side (Server)

#### WimseOAuth2DcrAuthenticator

Authenticates DCR requests using WIMSE protocol via the software statement mechanism.

**Key Behavior:**
- Extracts WIT from the `software_statement` field of the DCR request.
- Validates WIT signature using the WIMSE trust anchor (Identity Server's public key).
- Verifies WIT claims: `iss` against trusted issuers, `sub` for format validity, `exp` for expiration, `nbf` for not-before, and `aud` for audience restriction.
- Extracts the subject identifier from the WIT to use as the `client_id`.
- Verifies `cnf.jwk` in the WIT matches the `jwks` in the DCR request using `JwkUtils.publicKeysMatch()`, comparing only core cryptographic key material.

**Code Location:** `open-agent-auth-core/.../protocol/oauth2/dcr/server/authenticator/WimseOAuth2DcrAuthenticator.java`

#### OAuth2ClientAuthenticator

Validates `private_key_jwt` client assertions for token and PAR requests on the Authorization Server side.

**Key Behavior:**
- Extracts `client_assertion` from request parameters.
- Parses the JWT and identifies the client via `iss`/`sub` claims.
- Retrieves the client's registered JWKS from the client store.
- Selects the verification key using `JwkUtils.selectVerificationKey()` based on the JWT header's `kid`.
- Creates a signature verifier using `SignatureVerificationUtils.createVerifier()` based on the key type.
- Validates claims: `iss` and `sub` must equal the `client_id`, `aud` must match the AS's issuer identifier, `exp` must not be past, and `jti` must be unique.

**Code Location:** `open-agent-auth-spring-boot-starter/.../util/OAuth2ClientAuthenticator.java`

#### DefaultOAuth2DcrServer

Handles DCR registration requests and client lifecycle management.

**Key Behavior:**
- Validates DCR request using the configured authenticator (e.g., `WimseOAuth2DcrAuthenticator`).
- Extracts and stores JWKS from the request in the client's metadata.
- Creates `OAuth2RegisteredClient` with all relevant metadata including `token_endpoint_auth_method`, `grant_types`, and `jwks`.
- Returns `DcrResponse` with client details including the registered JWKS.
- Stores JWKS in `additionalMetadata` for later retrieval during `private_key_jwt` verification.

### Shared Utilities

#### JwkUtils

Provides reusable JWK operations shared across multiple modules, extracted to `open-agent-auth-core` to avoid code duplication between the WIMSE DCR authenticator and the OAuth2 client authenticator.

**Key Methods:**
- `publicKeysMatch(Jwk witJwk, JWK dcrJwk)`: Compares core cryptographic key material between a WIT `cnf.jwk` and a NimbusDS JWK. For EC keys, compares `kty`, `crv`, `x`, `y`. For RSA keys, compares `kty`, `n`, `e`. Metadata fields (`kid`, `alg`, `use`) are intentionally excluded.
- `selectVerificationKey(JWKSet jwkSet, String headerKeyId)`: Selects the appropriate JWK for signature verification from a JWKSet. If a `kid` is provided, matches by `kid`; otherwise, uses the first key in the set.

**Code Location:** `open-agent-auth-core/.../crypto/jwk/JwkUtils.java`

#### SignatureVerificationUtils

Provides signature verification utilities including JWS verifier creation based on key type.

**Key Methods:**
- `createVerifier(JWK jwk)`: Creates a `JWSVerifier` appropriate for the given JWK type (ECDSAVerifier for EC keys, RSASSAVerifier for RSA keys).

**Code Location:** `open-agent-auth-core/.../crypto/verify/SignatureVerificationUtils.java`

## Data Model

### DcrRequest

```java
private String softwareStatement;  // WIT as software statement JWT (RFC 7591 Section 2.3)
private Map<String, Object> jwks;  // Client's public key set for private_key_jwt verification
```

The `software_statement` carries the WIT for identity verification during registration. The `jwks` provides the public keys that will be stored and used for `private_key_jwt` signature verification in subsequent requests.

### OAuth2RegisteredClient

```java
private Map<String, Object> jwks;  // Stored public key set from registration
```

The `jwks` field stores the client's public keys registered during DCR. These keys are retrieved during `private_key_jwt` verification to validate client assertion signatures.

### DcrResponse

```java
private Map<String, Object> additionalMetadata;  // Includes registered jwks
```

The `additionalMetadata` returns the registered client metadata including the stored JWKS, allowing the client to confirm that its keys were correctly registered.

## Key Rotation and Credential Lifecycle

### WIT Lifecycle

WIT credentials are designed to be short-lived, with expiration typically set to hours. When a WIT expires, the workload obtains a new WIT from the Identity Server, which may bind a new public key. This triggers a key rotation flow.

### Key Rotation Strategies

When the workload's key pair changes, the registered JWKS at the Authorization Server must be updated. Two strategies are supported:

**Strategy 1: jwks_uri (Recommended for frequent rotation)**

If the client registered with a `jwks_uri`, the workload updates the JWK Set at that URI. The Authorization Server fetches the latest keys dynamically during verification. This approach aligns well with WIMSE's trust domain model and supports frequent key rotation without requiring explicit update requests.

**Strategy 2: Client Update via RFC 7592**

If the client registered with inline `jwks`, the workload must use the OAuth 2.0 Dynamic Client Registration Management Protocol (RFC 7592) to update the registered keys. The workload sends a PUT request to the Client Configuration Endpoint with the updated JWKS.

### Credential Expiration Hierarchy

The framework implements a layered expiration strategy where each credential layer has a progressively shorter lifetime, providing defense-in-depth:

| Credential | Typical Lifetime | Purpose |
|---|---|---|
| WIT | Hours | Primary identity credential from WIMSE Identity Server |
| Client Assertion | Minutes (default: 5 min) | Authentication proof for token/PAR requests |
| WPT | Seconds to minutes | Request-level binding for HTTP message signatures |
| Authorization Code | Minutes (default: 10 min) | Single-use authorization grant |
| Request URI (PAR) | Seconds (default: 90 sec) | Single-use PAR reference |

This hierarchy ensures that even if a credential at one layer is compromised, the exposure window is limited and the impact is contained by the shorter-lived credentials at lower layers.

## Security Considerations

### Key Binding Consistency

The most critical security invariant in this integration is maintaining cryptographic key consistency across all three phases:

```
WIT.cnf.jwk  ==  DCR Request.jwks  ==  Client Assertion Signing Key
```

- The WIT's `cnf.jwk` binds the workload's identity to a specific public key.
- The DCR request must provide the same public key in its `jwks` field.
- All subsequent client assertions must be signed with the corresponding private key.
- The Authorization Server verifies this chain at each step to prevent key substitution attacks.

This invariant is enforced by `WimseOAuth2DcrAuthenticator` during registration (comparing `cnf.jwk` against request `jwks`) and by `OAuth2ClientAuthenticator` during authentication (verifying the assertion signature against the registered `jwks`).

### Proof of Possession

Both WIMSE and `private_key_jwt` implement Proof of Possession (PoP), creating a multi-layer PoP architecture:

- **WIT PoP:** The `cnf.jwk` claim in the WIT requires the workload to prove possession of the corresponding private key. The WIT itself is not a bearer token (draft-ietf-wimse-s2s-protocol-07 Section 3.1 explicitly prohibits this).
- **Client Assertion PoP:** The JWT signature in the client assertion proves that the client holds the private key corresponding to the registered public key.
- **Request Binding PoP:** HTTP Message Signatures (WPT) bind individual requests to specific WIT instances, preventing request-level replay.

This multi-layer PoP prevents token theft and replay attacks at every level of the authorization flow.

### Audience Security

Audience validation is critical for preventing token confusion and cross-service attacks:

- **WIT audience:** Should be scoped to specific purposes or Authorization Server endpoints. WITs should not be accepted by services they were not intended for.
- **Client assertion audience:** Must use the Authorization Server's issuer identifier as the sole value (per draft-ietf-oauth-rfc7523bis-06). Using the token endpoint URL is no longer permitted. Including multiple audience values is also prohibited.
- **Cross-domain validation:** WITs must not be reused across different trust domains without transformation through an Identity Proxy or Token Exchange.

The 2025 security update (audience injection vulnerability) specifically requires that the `aud` claim in client assertions uses the Authorization Server's issuer identifier rather than the token endpoint URL. This prevents an attacker from crafting a client assertion that is valid at multiple endpoints. The framework enforces this by validating the `aud` claim against the configured issuer identifier.

### Trust Domain Isolation

Workload identity identifiers (e.g., `wimse://internal.example.com/service-a`) are internal to a trust domain and should not be exposed across trust boundaries. When workloads need to communicate across trust domains:

- An Identity Proxy at the trust boundary should perform identity abstraction, mapping internal identifiers to external-acceptable formats.
- Cross-domain DCR should use Token Exchange (Path B) to transform internal WITs into credentials acceptable by the external Authorization Server.
- Internal WIMSE identifiers should never appear in tokens or requests sent to external services.

### Replay Prevention

The framework implements replay prevention at multiple levels:

- **Client assertion `jti`:** Each client assertion must have a globally unique `jti` value. The Authorization Server should maintain a record of used `jti` values and reject any assertion with a previously seen `jti`.
- **Client assertion `exp`:** Short expiration times (default 5 minutes) limit the replay window even if `jti` tracking fails.
- **PAR request_uri:** Single-use and short-lived (default 90 seconds), preventing replay of authorization requests.
- **Authorization code:** Single-use and short-lived (default 10 minutes), preventing replay of authorization grants.

## Protocol References

| Protocol | Description |
|---|---|
| **RFC 7591** | OAuth 2.0 Dynamic Client Registration Protocol |
| **RFC 7523** | JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants |
| **RFC 7521** | Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants |
| **RFC 7592** | OAuth 2.0 Dynamic Client Registration Management Protocol |
| **RFC 8693** | OAuth 2.0 Token Exchange |
| **RFC 8414** | OAuth 2.0 Authorization Server Metadata |
| **RFC 9126** | OAuth 2.0 Pushed Authorization Requests (PAR) |
| **RFC 9421** | HTTP Message Signatures |
| **draft-ietf-oauth-rfc7523bis-06** | Updated JWT Profile (audience security fix) |
| **draft-ietf-wimse-arch-07** | WIMSE Architecture |
| **draft-ietf-wimse-s2s-protocol-07** | WIMSE Service-to-Service Protocol |
| **draft-ietf-wimse-workload-identity-practices-03** | Workload Identity Practices |

## Design Decisions

### Path A over Path B

This implementation uses Path A (Software Statement + private_key_jwt) rather than Path B (Token Exchange + Bearer Token) for the following reasons:

- **Simplicity:** Direct use of WIT as software statement eliminates the need for an intermediate Token Exchange endpoint and reduces the number of round-trips.
- **Standards compliance:** Directly leverages RFC 7591's software statement mechanism, which was designed for exactly this use case — a trusted third party vouching for a client's identity.
- **Strong security:** Maintains end-to-end cryptographic key binding from WIT issuance through client registration to token authentication, with no intermediate bearer tokens that could be stolen.
- **Efficiency:** Single registration request establishes both identity and key binding, compared to Path B's two-step process (token exchange + registration).

Path B remains a valid option for cross-trust-domain scenarios where the Authorization Server cannot directly verify WIT signatures from the WIMSE Identity Server. In such cases, a Token Exchange endpoint at the trust boundary can translate WITs into access tokens that the Authorization Server can accept.

### Inline jwks over jwks_uri

The framework defaults to inline `jwks` in DCR requests rather than `jwks_uri` because workloads in agent scenarios may not have stable, publicly accessible URLs for hosting their JWK Sets. Inline `jwks` ensures that the public keys are immediately available to the Authorization Server without requiring additional network requests. For production deployments with stable infrastructure, `jwks_uri` can be used instead to support dynamic key rotation without explicit client updates.

### Deprecation of Legacy client_assertion Mode

The previous implementation used `client_assertion` directly in the DCR request for WIMSE authentication. This has been deprecated in favor of the `software_statement` approach because:

- `software_statement` is the standard RFC 7591 mechanism for third-party identity attestation.
- Using `client_assertion` for DCR conflates the registration authentication mechanism with the token authentication mechanism, creating semantic confusion.
- The `software_statement` approach cleanly separates the identity attestation (WIT as software statement) from the authentication method declaration (`token_endpoint_auth_method: private_key_jwt`).
