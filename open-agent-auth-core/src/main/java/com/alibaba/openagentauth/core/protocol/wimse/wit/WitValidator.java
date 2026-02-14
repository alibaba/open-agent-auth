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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.trust.model.TrustAnchor;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * Validator for Workload Identity Tokens (WIT) following the WIMSE protocol.
 * Verifies the signature, expiration, and structure of WITs.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds-00</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/">draft-ietf-wimse-http-signature-01</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-mutual-tls/">draft-ietf-wimse-mutual-tls-00</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt-00</a>
 */
public class WitValidator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WitValidator.class);

    /**
     * The expected trust domain for validation.
     */
    private final TrustDomain expectedTrustDomain;

    /**
     * The trust anchor for signature verification.
     */
    private final TrustAnchor trustAnchor;

    /**
     * The RSA public key used for verifying WIT signatures.
     * This field is used only when trustAnchor is null (backward compatibility).
     */
    private final RSAKey verificationKey;

    /**
     * The JWK public key used for verifying WIT signatures.
     * This field supports both RSA and EC keys and is used when verificationKey is null.
     */
    private final JWK verificationJwk;

    /**
     * The WIT parser.
     */
    private final WitParser witParser;

    /**
     * Creates a new WIT validator with a trust anchor.
     * <p>
     * This constructor is recommended for production use as it supports dynamic key rotation
     * and multi-key scenarios through the trust anchor.
     * </p>
     *
     * @param trustAnchor the trust anchor containing the verification key and trust domain
     * @throws IllegalArgumentException if trustAnchor is null
     */
    public WitValidator(TrustAnchor trustAnchor) {

        // Set instance variables
        this.trustAnchor = ValidationUtils.validateNotNull(trustAnchor, "Trust anchor");
        this.expectedTrustDomain = trustAnchor.getTrustDomain();
        this.verificationKey = null;
        this.verificationJwk = null;
        this.witParser = new WitParser();

        logger.info("WitValidator initialized with trust anchor: keyId={}, domain={}", 
                trustAnchor.getKeyId(), expectedTrustDomain.getDomainId());
    }

    /**
     * Creates a new WIT validator with a verification key and trust domain.
     * <p>
     * This constructor is provided for backward compatibility and simple use cases.
     * For production use, consider using the constructor with TrustAnchor.
     * </p>
     *
     * @param verificationKey the RSA public key used for verifying WIT signatures
     * @param expectedTrustDomain the expected trust domain for validation
     * @throws IllegalArgumentException if verificationKey or expectedTrustDomain is null
     */
    public WitValidator(RSAKey verificationKey, TrustDomain expectedTrustDomain) {

        // Set instance variables
        this.trustAnchor = null;
        this.verificationKey = ValidationUtils.validateNotNull(verificationKey, "Verification key");
        this.verificationJwk = null;
        this.expectedTrustDomain = ValidationUtils.validateNotNull(expectedTrustDomain, "Expected trust domain");
        this.witParser = new WitParser();

        logger.info("WitValidator initialized with verification key ID: {}, domain: {}", 
                verificationKey.getKeyID(), expectedTrustDomain.getDomainId());
    }

    /**
     * Creates a new WIT validator with a verification key and trust domain.
     * <p>
     * This constructor supports both RSA and EC keys for WIT signature verification.
     * </p>
     *
     * @param verificationKey the JWK public key used for verifying WIT signatures (supports both RSA and EC)
     * @param expectedTrustDomain the expected trust domain for validation
     * @throws IllegalArgumentException if verificationKey or expectedTrustDomain is null
     */
    public WitValidator(JWK verificationKey, TrustDomain expectedTrustDomain) {

        // Set instance variables
        this.trustAnchor = null;
        this.expectedTrustDomain = ValidationUtils.validateNotNull(expectedTrustDomain, "Expected trust domain");
        this.witParser = new WitParser();
        
        // Validate and store the verification key
        ValidationUtils.validateNotNull(verificationKey, "Verification key");
        
        // For backward compatibility, store RSAKey in verificationKey field
        // For EC keys, store in verificationJwk field
        if (verificationKey instanceof RSAKey) {
            this.verificationKey = (RSAKey) verificationKey;
            this.verificationJwk = null;
        } else {
            this.verificationKey = null;
            this.verificationJwk = verificationKey;
        }

        logger.info("WitValidator initialized with verification key ID: {}, domain: {}", 
                verificationKey.getKeyID(), expectedTrustDomain.getDomainId());
    }

    /**
     * Validates a Workload Identity Token.
     *
     * @param witJwt the JWT string representing the WIT
     * @return a TokenValidationResult containing the validation outcome and parsed token
     * @throws ParseException if the JWT cannot be parsed
     */
    public TokenValidationResult<WorkloadIdentityToken> validate(String witJwt) throws ParseException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(witJwt)) {
            return TokenValidationResult.failure("WIT cannot be null or empty");
        }

        SignedJWT signedJwt = SignedJWT.parse(witJwt);

        // 1. Verify the signature of the WIT
        if (!verifySignature(signedJwt)) {
            return TokenValidationResult.failure("Invalid WIT signature");
        }

        // 2. Verify that the WIT has not expired
        if (!verifyExpiration(signedJwt)) {
            return TokenValidationResult.failure("WIT has expired");
        }

        // 3. Verify that the WIT issuer matches the expected trust domain
        if (!verifyTrustDomain(signedJwt)) {
            return TokenValidationResult.failure("Invalid trust domain");
        }

        // 3.5. Verify that the WIT key ID matches the trust anchor (if trust anchor is provided)
        if (trustAnchor != null && !verifyKeyId(signedJwt)) {
            return TokenValidationResult.failure("Invalid key ID");
        }

        // 4. Verify that all required claims are present in the WIT
        if (!verifyRequiredClaims(signedJwt)) {
            return TokenValidationResult.failure("Missing required claims");
        }

        // 5. Verify that the cnf claim contains a valid JWK
        // cnf is REQUIRED in this implementation, so missing cnf is a required claims error
        CnfValidationResult cnfResult = verifyCnfClaim(signedJwt);
        if (!cnfResult.valid()) {
            if (cnfResult.missing()) {
                return TokenValidationResult.failure("Missing required claims");
            } else {
                return TokenValidationResult.failure("Invalid cnf claim");
            }
        }

        // Parse the WIT and return the parsed token
        WorkloadIdentityToken wit = witParser.parse(signedJwt);
        logger.debug("Successfully validated WIT with subject: {}", wit.getSubject());

        return TokenValidationResult.success(wit);
    }

    /**
     * Verifies the signature of the WIT.
     *
     * @param signedJwt the signed JWT
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifySignature(SignedJWT signedJwt) {
        try {
            // Get WIT key ID and algorithm
            String witKeyId = signedJwt.getHeader().getKeyID();
            JWSAlgorithm witAlgorithm = signedJwt.getHeader().getAlgorithm();

            // Get verification key
            JWK key = (trustAnchor != null) ? 
                    convertToJWK(trustAnchor.getPublicKey(), trustAnchor.getKeyId()) : 
                    (verificationKey != null ? verificationKey : verificationJwk);
            
            String verificationKeyId = key.getKeyID();
            
            logger.info("Verifying WIT signature - WIT kid: {}, Verification key kid: {}, Algorithm: {}, Key Algorithm: {}",
                       witKeyId, verificationKeyId, witAlgorithm, key.getAlgorithm());

            // Verify that the algorithm is supported
            if (!isSupportedAlgorithm(witAlgorithm)) {
                logger.warn("WIT algorithm '{}' is not supported", witAlgorithm);
                return false;
            }

            // Create appropriate verifier based on key type and algorithm
            JWSVerifier verifier = createVerifier(key, witAlgorithm);
            if (verifier == null) {
                logger.error("Failed to create verifier for algorithm '{}' and key type '{}'", 
                           witAlgorithm, key.getKeyType());
                return false;
            }

            // Verify signature
            boolean isValid = signedJwt.verify(verifier);

            // Log if signature is invalid
            if (!isValid) {
                logger.warn("WIT signature verification failed - WIT kid: {}, Verification key kid: {}, WIT Algorithm: {}, Key Algorithm: {}",
                           witKeyId, verificationKeyId, witAlgorithm, key.getAlgorithm());
            }

            // Log signature verification result
            logger.debug("WIT signature verification result: {}", isValid);
            return isValid;

        } catch (JOSEException e) {
            logger.error("Error verifying WIT signature", e);
            return false;
        }
    }

    /**
     * Verifies that the WIT has not expired.
     *
     * @param signedJwt the signed JWT
     * @return true if the token is not expired, false otherwise
     */
    private boolean verifyExpiration(SignedJWT signedJwt) {
        try {
            // Get WIT expiration time
            Date expirationTime = signedJwt.getJWTClaimsSet().getExpirationTime();
            if (expirationTime == null) {
                logger.warn("WIT missing expiration time");
                return false;
            }

            // Verify that the token is not expired
            boolean isValid = expirationTime.after(Date.from(Instant.now()));
            if (!isValid) {
                logger.warn("WIT has expired at: {}", expirationTime);
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing WIT expiration time", e);
            return false;
        }
    }

    /**
     * Verifies that the WIT issuer matches the expected trust domain.
     *
     * @param signedJwt the signed JWT
     * @return true if the trust domain is valid, false otherwise
     */
    private boolean verifyTrustDomain(SignedJWT signedJwt) {
        try {
            // Get WIT issuer
            String issuer = signedJwt.getJWTClaimsSet().getIssuer();
            boolean isValid = expectedTrustDomain.getDomainId().equals(issuer);

            // Log if trust domain is invalid
            if (!isValid) {
                logger.warn("WIT issuer '{}' does not match expected trust domain '{}'",
                           issuer, expectedTrustDomain.getDomainId());
            }
            return isValid;

        } catch (ParseException e) {
            logger.error("Error parsing WIT issuer", e);
            return false;
        }
    }

    /**
     * Verifies that the WIT key ID matches the trust anchor.
     * <p>
     * This verification is only performed when a trust anchor is provided.
     * It ensures that the WIT was signed by the expected key.
     * </p>
     *
     * @param signedJwt the signed JWT
     * @return true if the key ID is valid, false otherwise
     */
    private boolean verifyKeyId(SignedJWT signedJwt) {
        String witKeyId = signedJwt.getHeader().getKeyID();
        String expectedKeyId = trustAnchor.getKeyId();
        boolean isValid = expectedKeyId.equals(witKeyId);

        if (!isValid) {
            logger.warn("WIT key ID '{}' does not match expected key ID '{}'", 
                       witKeyId, expectedKeyId);
        }
        return isValid;
    }

    /**
     * Converts a generic PublicKey to JWK for signature verification.
     * <p>
     * This is a helper method to bridge between the TrustAnchor's PublicKey
     * and the NimbusDS JWK expected by the verifier. Supports both RSA and EC keys.
     * </p>
     *
     * @param publicKey the public key to convert
     * @param keyId the key ID to set
     * @return the JWK
     * @throws JOSEException if the conversion fails
     */
    private JWK convertToJWK(PublicKey publicKey, String keyId) throws JOSEException {

        // Convert RSA public key to JWK
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            // Build RSAKey with algorithm based on TrustAnchor's KeyAlgorithm
            RSAKey.Builder rsaKeyBuilder = new RSAKey.Builder(rsaPublicKey)
                    .keyID(keyId);
            
            // Set the algorithm based on TrustAnchor's KeyAlgorithm
            // This is critical for RS256/RS384/RS512 signature verification
            if (trustAnchor != null && trustAnchor.getAlgorithm() != null) {
                JWSAlgorithm jwsAlgorithm = convertKeyAlgorithmToJWSAlgorithm(trustAnchor.getAlgorithm());
                if (jwsAlgorithm != null) {
                    rsaKeyBuilder.algorithm(jwsAlgorithm);
                }
            }
            
            RSAKey result = rsaKeyBuilder.build();
            logger.debug("Converted RSA public key to JWK: keyId={}, algorithm={}", result.getKeyID(), result.getAlgorithm());
            return result;
        }

        // Convert EC public key to JWK
        if (publicKey instanceof ECPublicKey ecPublicKey) {

            // Infer curve from EC key parameters
            Curve curve = inferCurveFromECKey(ecPublicKey);
            
            // Build ECKey with algorithm based on TrustAnchor's KeyAlgorithm
            ECKey.Builder ecKeyBuilder = new ECKey.Builder(curve, ecPublicKey)
                    .keyID(keyId);
            
            // Set the algorithm based on TrustAnchor's KeyAlgorithm
            // This is critical for ES256/ES384/ES512 signature verification
            if (trustAnchor != null && trustAnchor.getAlgorithm() != null) {
                JWSAlgorithm jwsAlgorithm = convertKeyAlgorithmToJWSAlgorithm(trustAnchor.getAlgorithm());
                if (jwsAlgorithm != null) {
                    ecKeyBuilder.algorithm(jwsAlgorithm);
                }
            }
            
            ECKey result = ecKeyBuilder.build();
            logger.debug("Converted EC public key to JWK: keyId={}, algorithm={}, curve={}", result.getKeyID(), result.getAlgorithm(), result.getCurve());
            return result;
        }

        // Unsupported public key type
        throw new JOSEException("Unsupported public key type: " + publicKey.getClass().getName());
    }

    /**
     * Converts KeyAlgorithm to JWSAlgorithm.
     *
     * @param keyAlgorithm the key algorithm
     * @return the corresponding JWSAlgorithm, or null if not supported
     */
    private JWSAlgorithm convertKeyAlgorithmToJWSAlgorithm(KeyAlgorithm keyAlgorithm) {
        if (keyAlgorithm == null) {
            return null;
        }
        return switch (keyAlgorithm) {
            case ES256 -> JWSAlgorithm.ES256;
            case ES384 -> JWSAlgorithm.ES384;
            case ES512 -> JWSAlgorithm.ES512;
            case RS256 -> JWSAlgorithm.RS256;
            case RS384 -> JWSAlgorithm.RS384;
            case RS512 -> JWSAlgorithm.RS512;
        };
    }

    /**
     * Checks if the given JWS algorithm is supported.
     *
     * @param algorithm the JWS algorithm to check
     * @return true if the algorithm is supported, false otherwise
     */
    private boolean isSupportedAlgorithm(JWSAlgorithm algorithm) {
        return JWSAlgorithm.RS256.equals(algorithm) ||
               JWSAlgorithm.RS384.equals(algorithm) ||
               JWSAlgorithm.RS512.equals(algorithm) ||
               JWSAlgorithm.ES256.equals(algorithm) ||
               JWSAlgorithm.ES384.equals(algorithm) ||
               JWSAlgorithm.ES512.equals(algorithm);
    }

    /**
     * Infers the JWS curve from EC key parameters.
     *
     * @param ecPublicKey the EC public key
     * @return the inferred Curve
     * @throws JOSEException if the curve cannot be inferred
     */
    private Curve inferCurveFromECKey(java.security.interfaces.ECPublicKey ecPublicKey) throws JOSEException {
        java.security.spec.ECParameterSpec params = ecPublicKey.getParams();
        String field = params.getCurve().getField().getFieldSize() + "";
        
        // Determine curve based on field size
        if (params.getCurve().getField().getFieldSize() == 256) {
            return Curve.P_256;
        } else if (params.getCurve().getField().getFieldSize() == 384) {
            return Curve.P_384;
        } else if (params.getCurve().getField().getFieldSize() == 521) {
            return Curve.P_521;
        }
        
        throw new JOSEException("Unsupported EC curve with field size: " + field);
    }

    /**
     * Creates a JWS verifier based on the key type and algorithm.
     *
     * @param key the JWK used for verification
     * @param algorithm the JWS algorithm
     * @return the JWS verifier, or null if the combination is not supported
     * @throws JOSEException if the verifier creation fails
     */
    private JWSVerifier createVerifier(JWK key, JWSAlgorithm algorithm) throws JOSEException {

        // RSA algorithms: RS256, RS384, RS512
        if (key instanceof RSAKey) {

            // RSA algorithms: RS256, RS384, RS512
            if (!JWSAlgorithm.Family.RSA.contains(algorithm)) {
                logger.error("Algorithm {} is not compatible with RSA key", algorithm);
                return null;
            }
            RSASSAVerifier verifier = new RSASSAVerifier((RSAKey) key);
            logger.debug("Created RSA verifier for algorithm: {}", algorithm);
            return verifier;
        }

        // EC algorithms: ES256, ES384, ES512
        if (key instanceof ECKey) {

            // ECDSA algorithms: ES256, ES384, ES512
            if (!JWSAlgorithm.Family.EC.contains(algorithm)) {
                logger.error("Algorithm {} is not compatible with EC key", algorithm);
                return null;
            }
            // CRITICAL: Must specify the algorithm explicitly for ECDSA verification
            // Without this, the verifier may use the wrong algorithm and verification will fail
            ECDSAVerifier verifier = new ECDSAVerifier((ECKey) key);
            logger.debug("Created ECDSA verifier for algorithm: {}, curve: {}", algorithm, ((ECKey) key).getCurve());
            return verifier;
        }

        // Unsupported key type
        logger.error("Unsupported key type for algorithm {}: {}", algorithm, key.getKeyType());
        return null;
    }

    /**
     * Verifies that all required claims are present in the WIT.
     * <p>
     * According to draft-ietf-wimse-workload-creds, the required claims are:
     * - sub (Subject): Workload Identifier (REQUIRED)
     * - exp (Expiration Time): Token expiration time (REQUIRED)
     * - cnf (Confirmation): Contains the public key for WPT/HTTP-Sig verification (REQUIRED)
     * </p>
     *
     * @param signedJwt the signed JWT
     * @return true if all required claims are present, false otherwise
     */
    private boolean verifyRequiredClaims(SignedJWT signedJwt) {
        try {
            // Get WIT claims
            var claims = signedJwt.getJWTClaimsSet().getClaims();

            // Verify subject (sub) claim - REQUIRED
            if (!claims.containsKey("sub")) {
                logger.warn("WIT missing required claim: sub (subject)");
                return false;
            }

            // Verify expiration (exp) claim - REQUIRED
            if (!claims.containsKey("exp")) {
                logger.warn("WIT missing required claim: exp (expiration time)");
                return false;
            }

            // cnf (confirmation) claim is REQUIRED for application-level authentication
            // as per draft-ietf-wimse-s2s-protocol-04 and later versions
            if (!claims.containsKey("cnf")) {
                logger.warn("WIT missing required claim: cnf (confirmation)");
                return false;
            }

            return true;

        } catch (ParseException e) {
            logger.error("Error parsing WIT claims", e);
            return false;
        }
    }

    /**
     * Verifies the cnf claim contains a valid JWK.
     * <p>
     * The cnf claim is REQUIRED in this implementation for WPT verification.
     * According to draft-ietf-wimse-workload-creds, cnf is OPTIONAL, but this
     * implementation requires it for proof-of-possession verification scenarios.
     * </p>
     *
     * @param signedJwt the signed JWT
     * @return a CnfValidationResult indicating whether the cnf claim is valid, missing, or invalid
     */
    private CnfValidationResult verifyCnfClaim(SignedJWT signedJwt) {
        try {
            // Get WIT cnf claim
            Map<String, Object> cnfClaim = signedJwt.getJWTClaimsSet().getJSONObjectClaim("cnf");

            // cnf claim is REQUIRED in this implementation
            if (cnfClaim == null) {
                logger.warn("WIT cnf claim is not present (required)");
                return new CnfValidationResult(false, true);
            }

            // Verify it contains a valid jwk
            if (!cnfClaim.containsKey("jwk")) {
                logger.warn("WIT cnf claim missing jwk");
                return new CnfValidationResult(false, false);
            }

            // Validate that the jwk is a valid JWK with safe type conversion
            Object jwkObj = cnfClaim.get("jwk");
            if (!(jwkObj instanceof Map)) {
                logger.warn("WIT cnf.jwk is not a Map");
                return new CnfValidationResult(false, false);
            }

            // Validate that the jwk is a valid JWK
            @SuppressWarnings("unchecked")
            Map<String, Object> jwkMap = (Map<String, Object>) jwkObj;
            try {
                JWK.parse(jwkMap);
                logger.debug("WIT cnf.jwk is valid");
                return new CnfValidationResult(true, false);
            } catch (ParseException e) {
                logger.warn("WIT cnf.jwk is invalid: {}", e.getMessage());
                return new CnfValidationResult(false, false);
            }
        } catch (ParseException e) {
            logger.error("Error parsing WIT cnf claim", e);
            return new CnfValidationResult(false, false);
        }
    }

    /**
     * Result of cnf claim validation.
     */
    private record CnfValidationResult(boolean valid, boolean missing) { }

}