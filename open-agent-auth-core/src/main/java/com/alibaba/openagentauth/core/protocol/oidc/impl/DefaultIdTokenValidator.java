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
package com.alibaba.openagentauth.core.protocol.oidc.impl;

import com.alibaba.openagentauth.core.exception.oidc.IdTokenException;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.oidc.IdTokenClaims;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Default implementation of {@link IdTokenValidator}.
 * <p>
 * This implementation validates ID Tokens according to the OpenID Connect Core 1.0
 * specification. It performs comprehensive validation including signature verification,
 * claims validation, and timing checks.
 * </p>
 * <p>
 * <b>Validation Steps:</b></p>
 * <ol>
 *   <li>Verify the token signature</li>
 *   <li>Verify the issuer (iss claim)</li>
 *   <li>Verify the audience (aud claim)</li>
 *   <li>Verify the token has not expired (exp claim)</li>
 *   <li>Verify the token was issued in the past (iat claim)</li>
 *   <li>Verify the nonce if provided (nonce claim)</li>
 * </ol>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect Core 1.0 - ID Token Validation</a>
 * @since 1.0
 */
public class DefaultIdTokenValidator implements IdTokenValidator {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultIdTokenValidator.class);

    /**
     * Allowed clock skew in seconds (default: 5 minutes).
     */
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 300;

    /**
     * The signing key for verification.
     */
    private final Object verificationKey;

    /**
     * The allowed clock skew in seconds.
     */
    private final long clockSkewSeconds;

    /**
     * Creates a new DefaultIdTokenValidator with default clock skew.
     *
     * @param verificationKey the verification key
     */
    public DefaultIdTokenValidator(Object verificationKey) {
        this(verificationKey, DEFAULT_CLOCK_SKEW_SECONDS);
    }

    /**
     * Creates a new DefaultIdTokenValidator with custom clock skew.
     *
     * @param verificationKey the verification key
     * @param clockSkewSeconds the allowed clock skew in seconds
     */
    public DefaultIdTokenValidator(Object verificationKey, long clockSkewSeconds) {

        // Validate the verification key
        this.verificationKey = ValidationUtils.validateNotNull(verificationKey, "Verification key");
        this.clockSkewSeconds = clockSkewSeconds;
        
        logger.info("DefaultIdTokenValidator initialized with clock skew: {} seconds", clockSkewSeconds);
    }

    /**
     * Validates a JWT token string.
     *
     * @param token the JWT string
     * @param expectedIssuer the expected issuer
     * @param expectedAudience the expected audience
     * @param expectedNonce the expected nonce (optional)
     * @return the parsed IdToken
     * @throws IdTokenException if validation fails
     */
    @Override
    public IdToken validate(String token, String expectedIssuer, String expectedAudience, String expectedNonce) {

        // Validate parameters
        ValidationUtils.validateNotNull(token, "Token");
        ValidationUtils.validateNotNull(expectedIssuer, "Expected issuer");
        ValidationUtils.validateNotNull(expectedAudience, "Expected audience");
        logger.debug("Validating ID token for issuer: {}, audience: {}", expectedIssuer, expectedAudience);

        // Parse the token
        IdToken idToken = parseToken(token);

        // Validate the parsed token
        return validate(idToken, expectedIssuer, expectedAudience, expectedNonce);
    }

    /**
     * Validates a JWT token string.
     *
     * @param token the JWT string
     * @param expectedIssuer the expected issuer
     * @param expectedAudience the expected audience
     * @return the parsed IdToken
     * @throws IdTokenException if validation fails
     */
    @Override
    public IdToken validate(String token, String expectedIssuer, String expectedAudience) {
        return validate(token, expectedIssuer, expectedAudience, null);
    }

    /**
     * Validates an IdToken object.
     *
     * @param idToken the IdToken object
     * @param expectedIssuer the expected issuer
     * @param expectedAudience the expected audience
     * @param expectedNonce the expected nonce (optional)
     * @return the validated IdToken
     * @throws IdTokenException if validation fails
     */
    @Override
    public IdToken validate(IdToken idToken, String expectedIssuer, String expectedAudience, String expectedNonce) {

        // Validate the ID token
        ValidationUtils.validateNotNull(idToken, "ID token");
        ValidationUtils.validateNotNull(expectedIssuer, "Expected issuer");
        ValidationUtils.validateNotNull(expectedAudience, "Expected audience");
        logger.debug("Validating ID token object for issuer: {}, audience: {}", expectedIssuer, expectedAudience);

        IdTokenClaims claims = idToken.getClaims();
        if (claims == null) {
            throw new IdTokenException("ID token claims are missing");
        }

        // Validate issuer
        validateIssuer(claims.getIss(), expectedIssuer);

        // Validate audience
        validateAudience(claims.getAud(), expectedAudience);

        // Validate expiration
        validateExpiration(claims.getExp());

        // Validate issued at
        validateIssuedAt(claims.getIat());

        // Validate nonce if provided
        if (expectedNonce != null) {
            validateNonce(claims.getNonce(), expectedNonce);
        }

        logger.info("ID token validated successfully for subject: {}", claims.getSub());

        return idToken;
    }

    /**
     * Parses a JWT token string into an IdToken object.
     * <p>
     * This method parses the JWT, verifies the signature, and extracts the claims.
     * </p>
     *
     * @param token the JWT string
     * @return the parsed IdToken
     * @throws IdTokenException if parsing or verification fails
     */
    private IdToken parseToken(String token) {
        try {
            // Parse the signed JWT
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Verify the signature
            JWSVerifier verifier = createVerifier(signedJWT.getHeader().getAlgorithm(), signedJWT.getHeader().getKeyID());
            if (!signedJWT.verify(verifier)) {
                throw new IdTokenException("Invalid JWT signature");
            }
            logger.debug("JWT signature verified successfully");

            // Extract claims
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            IdTokenClaims claims = convertToIdTokenClaims(claimsSet);

            // Build and return the IdToken
            return IdToken.builder().tokenValue(token).claims(claims).build();

        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to parse ID token", e);
            throw new IdTokenException("Failed to parse ID token: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a JWT verifier based on the algorithm.
     *
     * @param algorithm the JWS algorithm
     * @param keyId the key ID (optional, used for JWKSource)
     * @return the JWT verifier
     * @throws IdTokenException if the verifier cannot be created
     */
    private JWSVerifier createVerifier(JWSAlgorithm algorithm, String keyId) {

        // Validate the algorithm
        if (algorithm == null) {
            throw new IdTokenException("Algorithm cannot be null");
        }

        // If verification key is JWKSource, fetch the JWK and create verifier
        if (verificationKey instanceof JWKSource) {
            return createJWKSourceVerifier(algorithm, keyId);
        }

        // Create the verifier based on key type
        if (JWSAlgorithm.Family.RSA.contains(algorithm)) {
            return createRSAVerifier(algorithm);
        }
        if (JWSAlgorithm.Family.EC.contains(algorithm)) {
            return createECVerifier(algorithm);
        }

        throw new IdTokenException("Unsupported verification algorithm: " + algorithm);
    }

    /**
     * Creates an RSA verifier.
     *
     * @param algorithm the JWS algorithm
     * @return the RSA verifier
     * @throws IdTokenException if the verifier cannot be created
     */
    private JWSVerifier createRSAVerifier(JWSAlgorithm algorithm) {
        try {
            if (verificationKey instanceof RSAKey) {
                return new RSASSAVerifier((RSAKey) verificationKey);
            }
            if (verificationKey instanceof RSAPublicKey) {
                return new RSASSAVerifier((RSAPublicKey) verificationKey);
            }
            throw new IdTokenException(String.format(
                    "Invalid verification key for RSA algorithm: %s. Expected RSAKey or RSAPublicKey, got %s",
                    algorithm,
                    verificationKey.getClass().getSimpleName()));
        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to create RSA verifier", e);
            throw new IdTokenException("Failed to create RSA verifier: " + e.getMessage(), e);
        }
    }

    /**
     * Creates an EC verifier.
     *
     * @param algorithm the JWS algorithm
     * @return the EC verifier
     * @throws IdTokenException if the verifier cannot be created
     */
    private JWSVerifier createECVerifier(JWSAlgorithm algorithm) {
        try {
            if (verificationKey instanceof ECKey) {
                return new ECDSAVerifier((ECKey) verificationKey);
            }
            if (verificationKey instanceof ECPublicKey) {
                return new ECDSAVerifier((ECPublicKey) verificationKey);
            }
            throw new IdTokenException(String.format(
                    "Invalid verification key for EC algorithm: %s. Expected ECKey or ECPublicKey, got %s",
                    algorithm,
                    verificationKey.getClass().getSimpleName()));
        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to create EC verifier", e);
            throw new IdTokenException("Failed to create EC verifier: " + e.getMessage(), e);
        }
    }

    /**
     * Creates a verifier using JWKSource.
     * <p>
     * This method fetches the appropriate JWK from the JWKSource based on the
     * algorithm and key ID, then creates a corresponding verifier.
     * </p>
     *
     * @param algorithm the JWS algorithm
     * @param keyId the key ID (optional)
     * @return the JWS verifier
     * @throws IdTokenException if the verifier cannot be created
     */
    @SuppressWarnings("unchecked")
    private JWSVerifier createJWKSourceVerifier(JWSAlgorithm algorithm, String keyId) {
        try {
            JWKSource<SecurityContext> jwkSource = (JWKSource<SecurityContext>) verificationKey;
            
            // Create a JWK selector to get the appropriate JWK
            JWKMatcher.Builder matcherBuilder = new JWKMatcher.Builder()
                    .algorithm(algorithm);
            
            // If key ID is provided, match by key ID for better precision
            if (!ValidationUtils.isNullOrEmpty(keyId)) {
                matcherBuilder.keyID(keyId);
            }
            
            JWKSelector selector = new JWKSelector(matcherBuilder.build());
            
            // Get the JWK from the source
            List<JWK> jwkList = jwkSource.get(selector, null);
            
            if (jwkList == null || jwkList.isEmpty()) {
                logger.warn("No JWK found for algorithm: {}, keyId: {}. Retrying with algorithm only.", algorithm, keyId);
                // Retry without key ID for backward compatibility
                selector = new JWKSelector(new JWKMatcher.Builder().algorithm(algorithm).build());
                jwkList = jwkSource.get(selector, null);
                
                if (jwkList == null || jwkList.isEmpty()) {
                    throw new IdTokenException("No JWK found for algorithm: " + algorithm);
                }
            }
            
            // Use the first matching JWK
            JWK jwk = jwkList.get(0);
            logger.debug("Found JWK for signature verification: kid={}, kty={}, alg={}", 
                    jwk.getKeyID(), jwk.getKeyType(), jwk.getAlgorithm());
            
            // Create verifier based on JWK type
            if (jwk instanceof RSAKey) {
                return new RSASSAVerifier((RSAKey) jwk);
            } else if (jwk instanceof ECKey) {
                return new ECDSAVerifier((ECKey) jwk);
            } else {
                throw new IdTokenException("Unsupported JWK type: " + jwk.getKeyType());
            }
        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to create JWKSource verifier", e);
            throw new IdTokenException("Failed to create JWKSource verifier: " + e.getMessage(), e);
        }
    }
    /**
     * Converts JWTClaimsSet to IdTokenClaims.
     *
     * @param claimsSet the JWT claims set
     * @return the ID token claims
     * @throws IdTokenException if claims conversion fails
     */
    private IdTokenClaims convertToIdTokenClaims(JWTClaimsSet claimsSet) {

        // Build standard claims
        IdTokenClaims.Builder builder = buildStandardClaims(claimsSet);

        // Extract auth_time claim
        extractAuthTime(claimsSet, builder);

        // Extract optional string claims (nonce, acr, azp)
        extractOptionalStringClaims(claimsSet, builder);

        // Extract amr claim
        extractAmrClaim(claimsSet, builder);

        // Extract additional claims
        extractAdditionalClaims(claimsSet, builder);

        return builder.build();
    }

    /**
     * Builds standard OIDC claims from JWT claims set.
     *
     * @param claimsSet the JWT claims set
     * @return the builder with standard claims set
     */
    private IdTokenClaims.Builder buildStandardClaims(JWTClaimsSet claimsSet) {

        // Extract standard claims
        String aud = extractAudience(claimsSet);
        Long exp = extractExpirationTime(claimsSet);
        Long iat = extractIssuedAtTime(claimsSet);

        // Build the claims
        return IdTokenClaims.builder()
                .iss(claimsSet.getIssuer())
                .sub(claimsSet.getSubject())
                .aud(aud)
                .exp(exp)
                .iat(iat);
    }

    /**
     * Extracts the audience claim from the JWT claims set.
     *
     * @param claimsSet the JWT claims set
     * @return the audience string or null if not present
     */
    private String extractAudience(JWTClaimsSet claimsSet) {
        if (claimsSet.getAudience() != null && !claimsSet.getAudience().isEmpty()) {
            return claimsSet.getAudience().get(0);
        }
        return null;
    }

    /**
     * Extracts the expiration time claim from the JWT claims set.
     *
     * @param claimsSet the JWT claims set
     * @return the expiration time in seconds since epoch or null if not present
     */
    private Long extractExpirationTime(JWTClaimsSet claimsSet) {
        if (claimsSet.getExpirationTime() != null) {
            return claimsSet.getExpirationTime().getTime() / 1000;
        }
        return null;
    }

    /**
     * Extracts the issued at time claim from the JWT claims set.
     *
     * @param claimsSet the JWT claims set
     * @return the issued at time in seconds since epoch or null if not present
     */
    private Long extractIssuedAtTime(JWTClaimsSet claimsSet) {
        if (claimsSet.getIssueTime() != null) {
            return claimsSet.getIssueTime().getTime() / 1000;
        }
        return null;
    }

    /**
     * Extracts the auth_time claim.
     *
     * @param claimsSet the JWT claims set
     * @param builder the claims builder
     */
    private void extractAuthTime(JWTClaimsSet claimsSet, IdTokenClaims.Builder builder) {
        Object authTime = claimsSet.getClaim("auth_time");
        if (authTime instanceof Date) {
            builder.authTime(((Date) authTime).getTime() / 1000);
        } else if (authTime instanceof Long) {
            builder.authTime((Long) authTime);
        } else if (authTime instanceof Integer) {
            builder.authTime(((Integer) authTime).longValue());
        }
    }

    /**
     * Extracts optional string claims (nonce, acr, azp).
     *
     * @param claimsSet the JWT claims set
     * @param builder the claims builder
     * @throws IdTokenException if extraction fails
     */
    private void extractOptionalStringClaims(JWTClaimsSet claimsSet, IdTokenClaims.Builder builder) {
        try {
            String nonce = claimsSet.getStringClaim("nonce");
            if (nonce != null) {
                builder.nonce(nonce);
            }
            String acr = claimsSet.getStringClaim("acr");
            if (acr != null) {
                builder.acr(acr);
            }
            String azp = claimsSet.getStringClaim("azp");
            if (azp != null) {
                builder.azp(azp);
            }
        } catch (ParseException e) {
            throw new IdTokenException("Failed to extract string claims: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the amr (authentication methods references) claim.
     *
     * @param claimsSet the JWT claims set
     * @param builder the claims builder
     */
    private void extractAmrClaim(JWTClaimsSet claimsSet, IdTokenClaims.Builder builder) {
        Object amr = claimsSet.getClaim("amr");
        if (amr instanceof String[]) {
            builder.amr((String[]) amr);
        } else if (amr instanceof List<?> amrList) {
            String[] amrArray = amrList.toArray(new String[0]);
            builder.amr(amrArray);
        }
    }

    /**
     * Extracts additional claims that are not standard OIDC claims.
     *
     * @param claimsSet the JWT claims set
     * @param builder the claims builder
     */
    private void extractAdditionalClaims(JWTClaimsSet claimsSet, IdTokenClaims.Builder builder) {
        Map<String, Object> additionalClaims = new HashMap<>();
        for (String claimName : claimsSet.getClaims().keySet()) {
            if (!isStandardClaim(claimName)) {
                additionalClaims.put(claimName, claimsSet.getClaim(claimName));
            }
        }
        if (!additionalClaims.isEmpty()) {
            builder.additionalClaims(additionalClaims);
        }
    }

    /**
     * Checks if a claim is a standard OIDC claim.
     *
     * @param claimName the claim name
     * @return true if it's a standard claim
     */
    private boolean isStandardClaim(String claimName) {
        return claimName.equals("iss") || claimName.equals("sub") ||
               claimName.equals("aud") || claimName.equals("exp") ||
               claimName.equals("iat") || claimName.equals("auth_time") ||
               claimName.equals("nonce") || claimName.equals("acr") ||
               claimName.equals("amr") || claimName.equals("azp");
    }

    /**
     * Validates the issuer claim.
     *
     * @param actualIssuer the actual issuer from the token
     * @param expectedIssuer the expected issuer
     * @throws IdTokenException if validation fails
     */
    private void validateIssuer(String actualIssuer, String expectedIssuer) {
        if (actualIssuer == null || !actualIssuer.equals(expectedIssuer)) {
            throw new IdTokenException(String.format(
                    "Invalid issuer: expected '%s', got '%s'", expectedIssuer, actualIssuer));
        }
        logger.debug("Issuer validated: {}", actualIssuer);
    }

    /**
     * Validates the audience claim.
     *
     * @param actualAudience the actual audience from the token
     * @param expectedAudience the expected audience
     * @throws IdTokenException if validation fails
     */
    private void validateAudience(String actualAudience, String expectedAudience) {
        if (actualAudience == null || !actualAudience.equals(expectedAudience)) {
            throw new IdTokenException(String.format(
                    "Invalid audience: expected '%s', got '%s'", expectedAudience, actualAudience));
        }
        logger.debug("Audience validated: {}", actualAudience);
    }

    /**
     * Validates the expiration claim.
     *
     * @param exp the expiration time
     * @throws IdTokenException if validation fails
     */
    private void validateExpiration(Long exp) {
        if (exp == null) {
            throw new IdTokenException("Expiration claim (exp) is missing");
        }

        long now = Instant.now().getEpochSecond();
        if (now > exp + clockSkewSeconds) {
            throw new IdTokenException(String.format(
                    "Token expired at %d, current time is %d (with clock skew %d)", 
                    exp, now, clockSkewSeconds));
        }
        logger.debug("Expiration validated: {}", exp);
    }

    /**
     * Validates the issued at claim.
     *
     * @param iat the issued at time
     * @throws IdTokenException if validation fails
     */
    private void validateIssuedAt(Long iat) {
        if (iat == null) {
            throw new IdTokenException("Issued at claim (iat) is missing");
        }

        long now = Instant.now().getEpochSecond();
        if (iat > now + clockSkewSeconds) {
            throw new IdTokenException(String.format(
                    "Token issued in the future: %d, current time is %d (with clock skew %d)", 
                    iat, now, clockSkewSeconds));
        }
        logger.debug("Issued at validated: {}", iat);
    }

    /**
     * Validates the nonce claim.
     *
     * @param actualNonce the actual nonce from the token
     * @param expectedNonce the expected nonce
     * @throws IdTokenException if validation fails
     */
    private void validateNonce(String actualNonce, String expectedNonce) {
        if (actualNonce == null || !actualNonce.equals(expectedNonce)) {
            throw new IdTokenException(String.format(
                    "Invalid nonce: expected '%s', got '%s'", expectedNonce, actualNonce));
        }
        logger.debug("Nonce validated: {}", actualNonce);
    }

    /**
     * Gets the verification key.
     *
     * @return the verification key
     */
    public Object getVerificationKey() {
        return verificationKey;
    }

    /**
     * Gets the allowed clock skew in seconds.
     *
     * @return the clock skew
     */
    public long getClockSkewSeconds() {
        return clockSkewSeconds;
    }

}
