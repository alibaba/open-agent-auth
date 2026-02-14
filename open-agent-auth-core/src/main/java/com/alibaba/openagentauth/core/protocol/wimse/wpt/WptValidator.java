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
package com.alibaba.openagentauth.core.protocol.wimse.wpt;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
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

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.text.ParseException;
import java.util.Base64;
import java.util.Map;

/**
 * Validator for Workload Proof Tokens (WPT) following the WIMSE protocol.
 * Verifies the signature and validity of WPTs.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-s2s-protocol-07.html">draft-ietf-wimse-s2s-protocol-07</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt-00.html">draft-ietf-wimse-wpt-00</a>
 */
public class WptValidator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WptValidator.class);

    /**
     * Creates a new WPT validator.
     * <p>
     * According to WIMSE protocol, the WPT must be verified with the public key
     * from the WIT's cnf.jwk claim. This ensures cryptographic binding between WIT and WPT.
     * </p>
     */
    public WptValidator() {
        // No verification key needed - it will be extracted from WIT's cnf.jwk
    }

    /**
     * Validates a Workload Proof Token.
     *
     * @param wpt the WorkloadProofToken to validate
     * @param wit the Workload Identity Token to verify against
     * @return a TokenValidationResult containing the validation outcome and parsed token
     */
    public TokenValidationResult<WorkloadProofToken> validate(WorkloadProofToken wpt, WorkloadIdentityToken wit) {

        // Validate arguments
        if (wpt == null) {
            logger.warn("WPT cannot be null");
            return TokenValidationResult.failure("WPT cannot be null");
        }
        if (wit == null) {
            logger.warn("WIT cannot be null");
            return TokenValidationResult.failure("WIT cannot be null");
        }
        logger.debug("Validating WPT, WIT: {}, WPT: {}", wit, wpt);

        // 1. Verify that the WPT has not expired
        String expirationError = verifyExpiration(wpt);
        if (expirationError != null) {
            logger.warn("WPT has expired: {}", expirationError);
            return TokenValidationResult.failure(expirationError);
        }

        // 2. Verify that all required claims are present in the WPT
        String requiredClaimsError = verifyRequiredClaims(wpt);
        if (requiredClaimsError != null) {
            logger.warn("WPT missing required claims: {}", requiredClaimsError);
            return TokenValidationResult.failure(requiredClaimsError);
        }

        // 3. Verify that the WPT algorithm matches the algorithm specified in WIT cnf.jwk.alg
        // This check must be done before signature verification to prevent algorithm confusion attacks
        String algorithmError = verifyAlgorithmConsistency(wpt, wit);
        if (algorithmError != null) {
            logger.warn("WPT algorithm does not match WIT cnf.jwk.alg: {}", algorithmError);
            return TokenValidationResult.failure(algorithmError);
        }

        // 4. Verify that the wth claim matches the hash of the WIT
        String wthError = verifyWth(wpt, wit);
        if (wthError != null) {
            logger.warn("WPT wth does not match WIT hash: {}", wthError);
            return TokenValidationResult.failure(wthError);
        }

        // 5. Verify the oth claim (other tokens hashes) if present
        String othError = verifyOtherTokens(wpt, wit);
        if (othError != null) {
            logger.warn("WPT oth validation failed: {}", othError);
            return TokenValidationResult.failure(othError);
        }

        // 6. Verify the signature of the WPT
        String signatureError = verifySignature(wpt, wit);
        if (signatureError != null) {
            logger.warn("WPT signature verification failed: {}", signatureError);
            return TokenValidationResult.failure(signatureError);
        }

        // All checks passed
        logger.debug("Successfully validated WPT");
        return TokenValidationResult.success(wpt);
    }

    /**
     * Verifies that the WPT has not expired.
     *
     * @param wpt the WorkloadProofToken
     * @return error message if expired, null if valid
     */
    private String verifyExpiration(WorkloadProofToken wpt) {
        if (wpt.getClaims() == null || wpt.getClaims().getExpirationTime() == null) {
            return "WPT missing expiration time";
        }
        if (wpt.getClaims().isExpired()) {
            return "WPT expired at: " + wpt.getClaims().getExpirationTime();
        }
        return null;
    }

    /**
     * Converts the internal Jwk model to a NimbusDS JWK object.
     *
     * @param jwk the internal Jwk model
     * @return the NimbusDS JWK object
     * @throws JOSEException if conversion fails
     */
    private JWK convertToJWK(Jwk jwk) throws JOSEException {
        if (jwk == null) {
            throw new JOSEException("Jwk cannot be null");
        }

        String keyId = jwk.getKeyId();
        String algorithm = jwk.getAlgorithm();

        if (jwk.getKeyType() == Jwk.KeyType.EC) {
            // Convert EC key
            if (jwk.getX() == null || jwk.getY() == null) {
                throw new JOSEException("EC key missing required components");
            }
            
            Curve curve = convertToNimbusCurve(jwk.getCurve());
            BigInteger x = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getX()));
            BigInteger y = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.getY()));
            
            ECKey.Builder builder = new ECKey.Builder(curve, new ECPublicKey() {
                @Override
                public ECPoint getW() {
                    return new ECPoint(x, y);
                }
                @Override
                public String getAlgorithm() {
                    return "EC";
                }
                @Override
                public String getFormat() {
                    return "X.509";
                }
                @Override
                public byte[] getEncoded() {
                    return null;
                }
                @Override
                public java.security.spec.ECParameterSpec getParams() {
                    return curve.toECParameterSpec();
                }
            }).keyID(keyId);
            
            if (algorithm != null) {
                JWSAlgorithm jwsAlgorithm = convertAlgorithmToJWSAlgorithm(algorithm);
                if (jwsAlgorithm != null) {
                    builder.algorithm(jwsAlgorithm);
                }
            }
            return builder.build();
        } else if (jwk.getKeyType() == Jwk.KeyType.RSA) {
            throw new JOSEException("RSA key conversion not yet supported");
        }
        
        throw new JOSEException("Unsupported key type: " + jwk.getKeyType());
    }

    /**
     * Converts the internal Curve enum to NimbusDS Curve.
     *
     * @param curve the internal Curve enum
     * @return the NimbusDS Curve object
     * @throws JOSEException if the curve is not supported
     */
    private Curve convertToNimbusCurve(Jwk.Curve curve) throws JOSEException {
        if (curve == null) {
            throw new JOSEException("Curve cannot be null");
        }
        return switch (curve) {
            case P_256 -> Curve.P_256;
            case P_384 -> Curve.P_384;
            case P_521 -> Curve.P_521;
            default -> throw new JOSEException("Unsupported curve: " + curve);
        };
    }

    /**
     * Converts algorithm string to JWSAlgorithm.
     *
     * @param algorithm the algorithm string
     * @return the JWSAlgorithm object, or null if not supported
     */
    private JWSAlgorithm convertAlgorithmToJWSAlgorithm(String algorithm) {
        if (algorithm == null) {
            return null;
        }
        return switch (algorithm.toUpperCase()) {
            case "RS256" -> JWSAlgorithm.RS256;
            case "RS384" -> JWSAlgorithm.RS384;
            case "RS512" -> JWSAlgorithm.RS512;
            case "ES256" -> JWSAlgorithm.ES256;
            case "ES384" -> JWSAlgorithm.ES384;
            case "ES512" -> JWSAlgorithm.ES512;
            default -> null;
        };
    }

    /**
     * Verifies the signature of the WPT.
     *
     * @param wpt the WorkloadProofToken
     * @param wit the WorkloadIdentityToken
     * @return error message if invalid, null if valid
     */
    private String verifySignature(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Use the JWT string for signature verification
            String wptJwtString = wpt.getJwtString();
            if (ValidationUtils.isNullOrEmpty(wptJwtString)) {
                logger.warn("WPT missing JWT string, cannot verify signature");
                return "WPT missing JWT string";
            }

            // Parse the JWT string to get SignedJWT object
            SignedJWT signedJwt = SignedJWT.parse(wptJwtString);

            // Extract the public key from WIT cnf.jwk for WPT signature verification
            // According to WIMSE protocol, WPT must be signed with the private key corresponding to cnf.jwk
            if (wit.getConfirmation() == null || wit.getConfirmation().getJwk() == null) {
                logger.warn("WIT missing cnf.jwk, cannot verify WPT signature");
                return "WIT missing cnf.jwk";
            }

            JWK wptVerificationKey = convertToJWK(wit.getConfirmation().getJwk());
            
            // Create verifier using the WIT cnf.jwk key based on key type
            JWSVerifier verifier = createVerifier(wptVerificationKey);

            // Verify the signature
            boolean isValid = signedJwt.verify(verifier);

            if (!isValid) {
                logger.warn("WPT signature verification failed");
                return "WPT signature verification failed";
            } else {
                logger.debug("WPT signature verified successfully");
                return null;
            }

        } catch (JOSEException e) {
            logger.error("Error verifying WPT signature", e);
            return "Error verifying WPT signature: " + e.getMessage();
        } catch (ParseException e) {
            logger.error("Error parsing WPT JWT string during signature verification", e);
            // If parsing fails, it's likely due to an invalid signature format
            // Return a signature verification error message for consistency
            return "WPT signature verification failed";
        }
    }

    /**
     * Creates a JWS verifier based on the key type.
     *
     * @param verificationKey the verification key
     * @return the JWS verifier
     * @throws JOSEException if the key type is not supported
     */
    private static JWSVerifier createVerifier(JWK verificationKey) throws JOSEException {
        if (verificationKey instanceof RSAKey) {
            return new RSASSAVerifier((RSAKey) verificationKey);
        } else if (verificationKey instanceof ECKey) {
            return new ECDSAVerifier((ECKey) verificationKey);
        } else {
            throw new JOSEException("Unsupported key type: " + verificationKey.getClass().getSimpleName());
        }
    }

    /**
     * Verifies that all required claims are present in the WPT.
     *
     * @param wpt the WorkloadProofToken
     * @return error message if missing required claims, null if valid
     */
    private String verifyRequiredClaims(WorkloadProofToken wpt) {
        if (wpt.getClaims() == null) {
            return "WPT missing claims";
        }
        if (wpt.getClaims().getWorkloadTokenHash() == null ||
            wpt.getClaims().getWorkloadTokenHash().trim().isEmpty()) {
            return "WPT missing required claim: wth";
        } else {
            return null;
        }
    }

    /**
     * Verifies that the wth claim matches the hash of the WIT.
     *
     * @param wpt the WorkloadProofToken
     * @param wit the Workload Identity Token
     * @return error message if not match, null if valid
     */
    private String verifyWth(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Use the JWT string to compute hash
            String witJwtString = wit.getJwtString();
            if (ValidationUtils.isNullOrEmpty(witJwtString)) {
                logger.warn("WIT missing JWT string, cannot verify wth");
                return "WIT missing JWT string";
            }

            String expectedWth = JwtHashUtil.computeWitHash(witJwtString);
            String actualWth = wpt.getClaims().getWorkloadTokenHash();

            // Verify that the wth claim matches the hash of the WIT
            if (ValidationUtils.isNullOrEmpty(actualWth)) {
                return "WPT missing wth claim";
            }

            if (!expectedWth.equals(actualWth)) {
                return String.format("WPT wth '%s' does not match WIT hash '%s'", actualWth, expectedWth);
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Error calculating WIT hash", e);
            return "Error calculating WIT hash: " + e.getMessage();
        }
    }

    /**
     * Verifies the oth (other tokens hashes) claim if present.
     * <p>
     * According to WIMSE specification, the oth claim contains hashes of other tokens
     * that this WPT is bound to. This method validates those hashes against the actual
     * tokens if they are provided. If the oth claim contains entries that are not
     * understood by the recipient, the WPT MUST be rejected.
     * </p>
     * <p>
     * Supported token types in oth claim:
     * <ul>
     *   <li><b>aoat</b>: Agent Operation Authorization Token hash</li>
     * </ul>
     * </p>
     *
     * @param wpt the WorkloadProofToken
     * @param wit the Workload Identity Token (used for context)
     * @return error message if validation fails, null if valid or oth not present
     */
    private String verifyOtherTokens(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Check if oth claim is present
            if (wpt.getClaims().getOtherTokenHashes() == null ||
                wpt.getClaims().getOtherTokenHashes().isEmpty()) {
                // oth is optional, so it's okay if not present
                logger.debug("WPT does not contain oth claim, skipping validation");
                return null;
            }

            Map<String, String> otherTokenHashes = wpt.getClaims().getOtherTokenHashes();
            logger.debug("Validating WPT oth claim with {} token types", otherTokenHashes.size());

            // Validate each token type in oth claim
            for (Map.Entry<String, String> entry : otherTokenHashes.entrySet()) {
                String tokenType = entry.getKey();
                String expectedHash = entry.getValue();

                String validationResult = validateOtherTokenType(tokenType, expectedHash);
                if (validationResult != null) {
                    return validationResult;
                }
            }

            logger.debug("All oth claim entries validated successfully");
            return null;

        } catch (Exception e) {
            logger.error("Error validating oth claim", e);
            return "Error validating oth claim: " + e.getMessage();
        }
    }

    /**
     * Validates a specific token type in the oth claim.
     * <p>
     * According to WIMSE spec, if oth contains entries not understood by the recipient,
     * the WPT MUST be rejected.
     * </p>
     * <p>
     * This method validates the format of the oth claim entry. The actual hash comparison
     * with the provided token will be done in the validation pipeline (Layer 3).
     * </p>
     * <p>
     * This design supports any token type implementing {@link OthBindableToken}, providing
     * flexibility and extensibility without requiring modifications to this validator.
     * </p>
     *
     * @param tokenType the token type identifier (e.g., "aoat", "tth", "dpop")
     * @param expectedHash the expected hash value
     * @return error message if validation fails, null if valid
     */
    private String validateOtherTokenType(String tokenType, String expectedHash) {

        // Validate hash format
        if (expectedHash == null || expectedHash.trim().isEmpty()) {
            return String.format("WPT oth claim has empty hash for token type: '%s'", tokenType);
        }

        // Validate token type format
        if (tokenType == null || tokenType.trim().isEmpty()) {
            return "WPT oth claim contains empty token type key";
        }

        // Validate token type follows naming conventions (lowercase, alphanumeric, hyphens, underscores)
        if (!tokenType.matches("^[a-z0-9_-]+$")) {
            return String.format("WPT oth claim token type '%s' has invalid format", tokenType);
        }

        // Note: The actual token validation and hash comparison happens in Layer 3
        // Here we only validate that the oth claim format is correct
        // This design supports any token type implementing OthBindableToken interface
        logger.debug("WPT oth claim contains valid entry for token type: {}", tokenType);
        return null;
    }

    /**
     * Verifies that the WPT algorithm matches the algorithm specified in WIT cnf.jwk.alg.
     * <p>
     * According to draft-ietf-wimse-wpt, the WPT header alg parameter MUST match the alg value
     * of the jwk in the cnf claim of the WIT. This prevents algorithm confusion attacks.
     * </p>
     *
     * @param wpt the WorkloadProofToken
     * @param wit the Workload Identity Token
     * @return error message if not match, null if valid
     */
    private String verifyAlgorithmConsistency(WorkloadProofToken wpt, WorkloadIdentityToken wit) {
        try {
            // Get WPT header algorithm
            String wptAlg = wpt.getHeader().getAlgorithm();
            if (ValidationUtils.isNullOrEmpty(wptAlg)) {
                return "WPT missing algorithm in header";
            }

            // Get WIT cnf.jwk.alg from the structured object
            if (wit.getConfirmation() == null || wit.getConfirmation().getJwk() == null) {
                return "WIT missing cnf.jwk claim";
            }

            String witAlg = wit.getConfirmation().getJwk().getAlgorithm();
            if (ValidationUtils.isNullOrEmpty(witAlg)) {
                return "WIT cnf.jwk missing alg field";
            }

            // Verify algorithm consistency
            if (!wptAlg.equals(witAlg)) {
                return String.format("WPT algorithm '%s' does not match WIT cnf.jwk.alg '%s'", wptAlg, witAlg);
            } else {
                return null;
            }
        } catch (Exception e) {
            logger.error("Error verifying algorithm consistency", e);
            return "Error verifying algorithm consistency: " + e.getMessage();
        }
    }
}