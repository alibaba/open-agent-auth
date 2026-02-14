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
package com.alibaba.openagentauth.core.protocol.vc;

import com.alibaba.openagentauth.core.exception.workload.VcVerificationException;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.crypto.jwk.JwksProvider;
import com.alibaba.openagentauth.core.protocol.vc.jwt.JwtVcDecoder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Default implementation of {@link VcVerifier} for verifying Verifiable Credentials.
 * <p>
 * This implementation provides comprehensive validation of JWT-based Verifiable Credentials
 * following the draft-liu-agent-operation-authorization-01 specification.
 * </p>
 * <p>
 * The verification process includes:
 * <ul>
 *   <li>JWT parsing and algorithm validation</li>
 *   <li>Signature verification using JWKS</li>
 *   <li>Required claims validation (type, credentialSubject, issuer, jti)</li>
 *   <li>Issuer validation (if configured)</li>
 *   <li>Time-based validation (expiration, not-before, max age)</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class DefaultVcVerifier implements VcVerifier {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultVcVerifier.class);

    /**
     * Provider for fetching JSON Web Key Set (JWKS) containing public keys
     * used to verify Verifiable Credential signatures.
     */
    private final JwksProvider jwksProvider;

    /**
     * Verification policy defining validation rules and constraints.
     */
    private final VcVerificationPolicy policy;

    /**
     * Creates a new DefaultVcVerifier with default verification policy.
     *
     * @param jwksProvider the JWKS provider for fetching public keys
     * @throws IllegalArgumentException if jwksProvider is null
     */
    public DefaultVcVerifier(JwksProvider jwksProvider) {
        this(jwksProvider, new VcVerificationPolicy());
    }

    /**
     * Creates a new DefaultVcVerifier with custom verification policy.
     *
     * @param jwksProvider the JWKS provider for fetching public keys
     * @param policy the verification policy
     * @throws IllegalArgumentException if any parameter is null
     */
    public DefaultVcVerifier(JwksProvider jwksProvider, VcVerificationPolicy policy) {
        this.jwksProvider = ValidationUtils.validateNotNull(jwksProvider, "JWKS provider");
        this.policy = ValidationUtils.validateNotNull(policy, "Verification policy");
        logger.info("DefaultVcVerifier initialized");
    }

    @Override
    public VerifiableCredential verify(String jwtVc) throws ParseException, VcVerificationException {

        // Validate parameters
        ValidationUtils.validateNotNull(jwtVc, "JWT VC");
        logger.debug("Verifying VerifiableCredential JWT");

        try {
            // Step 1-2: Parse JWT and verify algorithm
            SignedJWT signedJwt = verifyJwtStructure(jwtVc);

            // Step 3: Verify signature
            verifySignature(signedJwt);

            // Step 4: Decode to credential
            VerifiableCredential credential = JwtVcDecoder.decode(jwtVc);

            // Step 5: Verify required claims
            verifyRequiredClaims(credential);

            // Step 6: Verify issuer
            if (policy.getExpectedIssuer() != null) {
                if (!policy.getExpectedIssuer().equals(credential.getIss())) {
                    String errorMessage = String.format(
                            "Issuer mismatch: expected=%s, actual=%s",
                            policy.getExpectedIssuer(), credential.getIss()
                    );
                    throw new VcVerificationException(errorMessage, "VC-INVALID-ISSUER");
                }
            }

            // Step 7-9: Verify time constraints (expiration, not-before, max age)
            verifyTimeConstraints(credential);

            logger.info("VerifiableCredential verified successfully: {}", credential.getJti());
            return credential;

        } catch (ParseException | JOSEException e) {
            String errorMessage = "Failed to verify credential: " + e.getMessage();
            throw new VcVerificationException(errorMessage, "VC-VERIFICATION-FAILED", e);
        }
    }

    /**
     * Parses the JWT and verifies the signing algorithm is allowed.
     * <p>
     * This method validates the JWT structure and ensures the algorithm
     * is one of the allowed algorithms specified in the verification policy.
     * </p>
     *
     * @param jwtVc the JWT string to parse
     * @return the parsed SignedJWT
     * @throws ParseException if the JWT cannot be parsed
     * @throws VcVerificationException if the algorithm is invalid or not allowed
     */
    private SignedJWT verifyJwtStructure(String jwtVc) throws ParseException, VcVerificationException {

        // Parse JWT
        SignedJWT signedJwt = SignedJWT.parse(jwtVc);

        // Verify algorithm
        JWSAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();
        if (algorithm == null || !policy.isAlgorithmAllowed(algorithm.getName())) {
            String errorMessage = String.format("Invalid or unsupported algorithm: %s", algorithm);
            throw new VcVerificationException(errorMessage, "VC-INVALID-ALGORITHM");
        }

        return signedJwt;
    }

    /**
     * Verifies the JWT signature using the public key from JWKS.
     * <p>
     * This method fetches the public key based on the key ID from the JWT header,
     * creates an appropriate verifier, and validates the signature.
     * </p>
     *
     * @param signedJwt the signed JWT to verify
     * @throws VcVerificationException if signature verification fails
     * @throws JOSEException if a JOSE-related error occurs
     */
    private void verifySignature(SignedJWT signedJwt) throws VcVerificationException, JOSEException {

        // Fetch public key and create verifier
        String keyId = signedJwt.getHeader().getKeyID();
        JWK publicKey = fetchPublicKey(keyId);
        JWSVerifier verifier = createVerifier(publicKey);

        // Verify signature
        if (!signedJwt.verify(verifier)) {
            throw new VcVerificationException("Signature verification failed", "VC-INVALID-SIGNATURE");
        }
    }

    /**
     * Verifies time-based constraints on the credential.
     * <p>
     * This method validates:
     * <ul>
     *   <li>Expiration time (exp claim) - the credential must not be expired</li>
     *   <li>Issued at time (iat claim) - the credential must be valid now</li>
     *   <li>Maximum age - the credential must not exceed the maximum allowed age</li>
     * </ul>
     * All-time comparisons include clock skew tolerance.
     * </p>
     *
     * @param credential the credential to validate
     * @throws VcVerificationException if any time constraint is violated
     */
    private void verifyTimeConstraints(VerifiableCredential credential) throws VcVerificationException {

        // Get current time and clock skew
        Instant now = policy.getClock().instant();
        Duration skew = policy.getClockSkewTolerance();

        // Verify expiration
        if (credential.getExp() != null) {
            Instant expirationTime = Instant.ofEpochSecond(credential.getExp());
            if (expirationTime.plus(skew).isBefore(now)) {
                throw new VcVerificationException("Credential expired at: " + expirationTime, "VC-EXPIRED");
            }
        }

        // Verify not-before and max age
        if (credential.getIat() != null) {
            Instant issuedAt = Instant.ofEpochSecond(credential.getIat());
            if (issuedAt.minus(skew).isAfter(now)) {
                throw new VcVerificationException("Credential not valid until: " + issuedAt, "VC-NOT-YET-VALID");
            }

            Duration maxAge = policy.getMaxAge();
            if (issuedAt.plus(maxAge).isBefore(now)) {
                throw new VcVerificationException("Credential exceeds maximum age", "VC-EXCEEDS-MAX-AGE");
            }
        }
    }

    /**
     * Fetches the public key from JWKS using the key ID.
     * <p>
     * This method queries the JWKS provider for the public key matching
     * the specified key ID. The key is used to verify the signature.
     * </p>
     *
     * @param keyId the key ID from the JWT header
     * @return the public key
     * @throws VcVerificationException if the key is not found or fetching fails
     */
    private JWK fetchPublicKey(String keyId) throws VcVerificationException {
        try {
            // Fetch public key
            JWKSource<SecurityContext> jwkSource = jwksProvider.getJwkSource();
            JWKSelector selector = new JWKSelector(
                    new JWKMatcher.Builder()
                            .keyID(keyId)
                            .build()
            );
            List<JWK> jwkList = jwkSource.get(selector, null);

            // Check if key is found
            if (jwkList == null || jwkList.isEmpty()) {
                String errorMessage = String.format("Public key not found for keyId: %s", keyId);
                throw new VcVerificationException(errorMessage, "VC-KEY-NOT-FOUND");
            }
            return jwkList.get(0);

        } catch (VcVerificationException e) {
            throw e;
        } catch (Exception e) {
            String errorMessage = String.format("Failed to fetch public key: " + e.getMessage());
            throw new VcVerificationException(errorMessage, "VC-KEY-FETCH-ERROR", e);
        }
    }

    /**
     * Creates a JWS verifier for the given public key.
     * <p>
     * This method creates an appropriate verifier based on the key type.
     * Supports both RSA and ECDSA keys.
     * </p>
     *
     * @param publicKey the public key
     * @return the JWS verifier
     * @throws VcVerificationException if the key type is not supported
     * @throws JOSEException if a JOSE-related error occurs
     */
    private JWSVerifier createVerifier(JWK publicKey) throws VcVerificationException, JOSEException {

        // Create verifier based on key type
        if (publicKey instanceof RSAKey) {
            RSAKey rsaKey = (RSAKey) publicKey.toPublicJWK();
            return new RSASSAVerifier(rsaKey);
        } else if (publicKey instanceof ECKey) {
            ECKey ecKey = (ECKey) publicKey.toPublicJWK();
            return new ECDSAVerifier(ecKey);
        }

        // Unsupported key type
        String errorMessage = String.format("Unsupported key type: %s", publicKey.getKeyType());
        throw new VcVerificationException(errorMessage, "VC-UNSUPPORTED-KEY-TYPE");
    }

    /**
     * Verifies that all required claims are present in the credential.
     * <p>
     * Required claims according to the specification:
     * <ul>
     *   <li>type: must be "VerifiableCredential"</li>
     *   <li>credentialSubject: the subject of the credential</li>
     *   <li>issuer: the issuer of the credential</li>
     *   <li>jti: the unique identifier</li>
     * </ul>
     * </p>
     *
     * @param credential the credential to verify
     * @throws VcVerificationException if any required claim is missing or invalid
     */
    private void verifyRequiredClaims(VerifiableCredential credential) throws VcVerificationException {

        if (credential.getType() == null || credential.getType().isEmpty()) {
            throw new VcVerificationException("Missing required claim: type", "VC-MISSING-CLAIM");
        }

        if (!"VerifiableCredential".equals(credential.getType())) {
            String errorMessage = String.format("Invalid credential type: %s", credential.getType());
            throw new VcVerificationException(errorMessage, "VC-INVALID-TYPE");
        }

        if (credential.getCredentialSubject() == null) {
            throw new VcVerificationException("Missing required claim: credentialSubject", "VC-MISSING-SUBJECT");
        }

        if (credential.getIss() == null || credential.getIss().isEmpty()) {
            throw new VcVerificationException("Missing required claim: issuer", "VC-MISSING-ISSUER");
        }

        if (credential.getJti() == null || credential.getJti().isEmpty()) {
            throw new VcVerificationException("Missing required claim: jti", "VC-MISSING-JTI");
        }
    }

    /**
     * Sets the expected issuer for the credential.
     *
     * @param issuer the expected issuer
     */
    @Override
    public void setExpectedIssuer(String issuer) {
        policy.setExpectedIssuer(issuer);
        logger.info("Expected issuer set to: {}", issuer);
    }

    /**
     * Gets the expected issuer for the credential.
     *
     * @return the expected issuer, or null if not set
     */
    @Override
    public String getExpectedIssuer() {
        return policy.getExpectedIssuer();
    }

    /**
     * Gets the verification policy.
     *
     * @return the verification policy
     */
    public VcVerificationPolicy getPolicy() {
        return policy;
    }
}