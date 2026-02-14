/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.core.protocol.vc.jwt;

import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.util.HashMap;
import java.util.Map;

/**
 * Encoder for converting VerifiableCredential objects to JWT format.
 * <p>
 * This class handles the conversion of VerifiableCredential model objects into
 * JWT strings that can be signed and transmitted. It maps the VC fields to JWT claims
 * according to the W3C VC Data Model and draft-liu-agent-operation-authorization-01.
 * </p>
 * <p>
 * <b>Claim Mapping:</b>
 * <ul>
 *   <li><b>Standard JWT Claims:</b>
 *     <ul>
 *       <li>jti (JWT ID) → credential unique identifier</li>
 *       <li>iss (issuer) → JWT issuer</li>
 *       <li>sub (subject) → credential subject identifier</li>
 *       <li>iat (issued at) → Unix timestamp (seconds since epoch)</li>
 *       <li>exp (expiration) → Unix timestamp (seconds since epoch)</li>
 *     </ul>
 *   </li>
 *   <li><b>W3C VC Custom Claims:</b>
 *     <ul>
 *       <li>type → credential type (e.g., "VerifiableCredential")</li>
 *       <li>credentialSubject → the subject of the credential (e.g., UserInputEvidence)</li>
 *       <li>issuer → W3C VC issuer (URI string)</li>
 *       <li>issuanceDate → ISO 8601 timestamp</li>
 *       <li>expirationDate → ISO 8601 timestamp</li>
 *       <li>proof → cryptographic proof information</li>
 *     </ul>
 *   </li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * <pre>{@code
 * VerifiableCredential credential = VerifiableCredential.builder()
 *     .jti("pt-001")
 *     .type("VerifiableCredential")
 *     .build();
 *
 * RSAKey signingKey = ...;
 * String keyId = "key-01";
 *
 * // Unsigned JWT
 * String unsignedJwt = JwtVcEncoder.encode(credential);
 *
 * // Signed JWT
 * String signedJwt = JwtVcEncoder.encodeAndSign(credential, signingKey, keyId);
 * }</pre>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C VC Data Model</a>
 * @since 1.0
 */
public class JwtVcEncoder {

    /**
     * Encodes a VerifiableCredential to an unsigned JWT string.
     * <p>
     * This method converts the VerifiableCredential object to JWT claims and
     * returns the serialized JWT without cryptographic signature.
     * </p>
     * <p>
     * The resulting JWT uses RS256 algorithm in the header but has an empty signature.
     * This is useful for testing or when the signature will be added separately.
     * The JWT format is: header.payload.signature (with empty signature).
     * </p>
     *
     * @param credential the VerifiableCredential to encode
     * @return the unsigned JWT string with empty signature
     * @throws NullPointerException if credential is null
     */
    public static String encode(VerifiableCredential credential) {

        // Validate parameters
        if (credential == null) {
            throw new NullPointerException("credential cannot be null");
        }

        JWTClaimsSet claimsSet = convertToClaims(credential);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claimsSet);

        // For unsigned JWT, serialize header and payload with empty signature
        // Format: header.payload. (empty signature part)
        try {
            String header = jwt.getHeader().toBase64URL().toString();
            String payload = jwt.getPayload().toBase64URL().toString();
            // Return with empty signature to maintain 3-part JWT structure
            return header + "." + payload + ".";
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize unsigned JWT", e);
        }
    }

    /**
     * Encodes and signs a VerifiableCredential to a JWT string.
     * <p>
     * This method performs the following steps:
     * <ol>
     *   <li>Converts the VerifiableCredential to JWT claims</li>
     *   <li>Creates a JWS header with the appropriate algorithm and key ID</li>
     *   <li>Signs the JWT using the provided private key (RSA or EC)</li>
     *   <li>Returns the serialized signed JWT</li>
     * </ol>
     * </p>
     * <p>
     * Supports both RSA (RS256, RS384, RS512) and ECDSA (ES256, ES384, ES512) algorithms.
     * The algorithm is automatically determined based on the key type.
     * </p>
     * <p>
     * The resulting JWT can be verified using the corresponding public key
     * from the JWKS endpoint identified by the key ID.
     * </p>
     *
     * @param credential the VerifiableCredential to encode
     * @param signingKey the signing key (RSA or EC) for signing
     * @param keyId the key ID to include in the JWT header (references the public key in JWKS)
     * @return the signed JWT string
     * @throws JOSEException if encoding or signing fails
     * @throws NullPointerException if any parameter is null
     */
    public static String encodeAndSign(VerifiableCredential credential, JWK signingKey, String keyId) throws JOSEException {

        // Validate parameters
        if (credential == null) {
            throw new NullPointerException("credential cannot be null");
        }
        if (signingKey == null) {
            throw new NullPointerException("signingKey cannot be null");
        }
        if (keyId == null) {
            throw new NullPointerException("keyId cannot be null");
        }

        // Convert VerifiableCredential to JWT claims
        JWTClaimsSet claimsSet = convertToClaims(credential);

        // Determine algorithm based on key type
        JWSAlgorithm algorithm = determineAlgorithm(signingKey);

        // Build JWS header with algorithm and key ID
        JWSHeader header = new JWSHeader.Builder(algorithm)
                .keyID(keyId)
                .build();

        // Create signed JWT
        SignedJWT signedJwt = new SignedJWT(header, claimsSet);

        // Sign with the appropriate signer based on key type
        JWSSigner signer = createSigner(signingKey);
        signedJwt.sign(signer);
        
        return signedJwt.serialize();
    }

    /**
     * Converts a VerifiableCredential to JWT claims.
     * <p>
     * This method maps VC fields to JWT claims according to the specification.
     * Standard JWT claims (jti, iss, sub, iat, exp) are set using the builder's
     * dedicated methods, while W3C VC-specific claims are added as custom claims.
     * </p>
     * <p>
     * <b>Standard JWT Claims:</b>
     * <ul>
     *   <li>jti → JWT ID (credential unique identifier)</li>
     *   <li>iss → JWT issuer</li>
     *   <li>sub → subject (credential subject identifier)</li>
     *   <li>iat → issued at (converted from Unix timestamp to Date)</li>
     *   <li>exp → expiration (converted from Unix timestamp to Date)</li>
     * </ul>
     * </p>
     * <p>
     * <b>W3C VC Custom Claims:</b>
     * <ul>
     *   <li>type → credential type (e.g., "VerifiableCredential")</li>
     *   <li>credentialSubject → the credential subject (e.g., UserInputEvidence)</li>
     *   <li>issuer → W3C VC issuer (URI string)</li>
     *   <li>issuanceDate → ISO 8601 timestamp</li>
     *   <li>expirationDate → ISO 8601 timestamp</li>
     *   <li>proof → cryptographic proof information</li>
     * </ul>
     * </p>
     * <p>
     * Note: Time-based claims (iat, exp) are converted from Unix timestamp (seconds)
     * to Date objects as required by the JWT library.
     * </p>
     *
     * @param credential the VerifiableCredential
     * @return the JWT claims set
     * @throws NullPointerException if credential is null
     */
    private static JWTClaimsSet convertToClaims(VerifiableCredential credential) {

        // Initialize builder
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        // Standard JWT claims
        if (credential.getJti() != null) {
            builder.jwtID(credential.getJti());
        }
        if (credential.getIss() != null) {
            builder.issuer(credential.getIss());
        }
        if (credential.getSub() != null) {
            builder.subject(credential.getSub());
        }
        // Convert Unix timestamp (seconds) to Date
        if (credential.getIat() != null) {
            builder.issueTime(new java.util.Date(credential.getIat() * 1000));
        }
        if (credential.getExp() != null) {
            builder.expirationTime(new java.util.Date(credential.getExp() * 1000));
        }
        
        // W3C VC specific claims
        Map<String, Object> customClaims = new HashMap<>();
        
        if (credential.getType() != null) {
            customClaims.put("type", credential.getType());
        }
        
        if (credential.getCredentialSubject() != null) {
            customClaims.put("credentialSubject", credential.getCredentialSubject());
        }
        
        if (credential.getIssuer() != null) {
            customClaims.put("issuer", credential.getIssuer());
        }
        
        if (credential.getIssuanceDate() != null) {
            customClaims.put("issuanceDate", credential.getIssuanceDate());
        }
        
        if (credential.getExpirationDate() != null) {
            customClaims.put("expirationDate", credential.getExpirationDate());
        }
        
        if (credential.getProof() != null) {
            customClaims.put("proof", credential.getProof());
        }
        
        // Add all custom claims to the builder
        for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        
        return builder.build();
    }

    /**
     * Determines the JWS algorithm based on the key type.
     *
     * @param key the signing key
     * @return the appropriate JWS algorithm
     * @throws JOSEException if the key type is not supported
     */
    private static JWSAlgorithm determineAlgorithm(JWK key) throws JOSEException {
        if (key instanceof RSAKey) {
            return JWSAlgorithm.RS256;
        } else if (key instanceof ECKey) {
            ECKey ecKey = (ECKey) key;
            // Determine algorithm based on curve
            Algorithm algorithm = ecKey.getAlgorithm();
            if (algorithm instanceof JWSAlgorithm) {
                return (JWSAlgorithm) algorithm;
            }
            // Default to ES256 for EC keys if algorithm is not a JWSAlgorithm
            return JWSAlgorithm.ES256;
        } else {
            throw new JOSEException("Unsupported key type: " + key.getKeyType());
        }
    }

    /**
     * Creates a JWS signer based on the key type.
     *
     * @param key the signing key
     * @return the appropriate JWS signer
     * @throws JOSEException if the key type is not supported
     */
    private static JWSSigner createSigner(JWK key) throws JOSEException {
        if (key instanceof RSAKey) {
            return new RSASSASigner((RSAKey) key);
        } else if (key instanceof ECKey) {
            return new ECDSASigner((ECKey) key);
        } else {
            throw new JOSEException("Unsupported key type: " + key.getKeyType());
        }
    }
}
