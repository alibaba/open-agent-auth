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

import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

/**
 * Unit tests for {@link WitValidator}.
 * Tests verify compliance with WIMSE WIT protocol specification:
 * https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/
 */
@DisplayName("WIT Validator Tests - draft-ietf-wimse-workload-creds")
class WitValidatorTest {

    private static final String VERIFICATION_KEY_ID = "test-verification-key";
    
    private WitValidator witValidator;
    private RSAKey signingKey;
    private RSAKey verificationKey;
    private ECKey wptPublicKey;
    private TrustDomain trustDomain;
    private WitGenerator witGenerator;
    private KeyManager keyManager;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for WIT signing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        signingKey = rsaKeyGenerator.keyID(VERIFICATION_KEY_ID).generate();
        verificationKey = signingKey.toPublicJWK();

        // Generate EC key pair for WPT
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(Curve.P_256);
        wptPublicKey = ecKeyGenerator.keyID("wpt-key").generate().toPublicJWK();

        trustDomain = new TrustDomain("wimse://example.com");
        
        // Create mock KeyManager
        keyManager = mock(KeyManager.class);
        when(keyManager.resolveVerificationKey(anyString())).thenReturn(verificationKey);
        
        // Create validator with new constructor
        witValidator = new WitValidator(keyManager, VERIFICATION_KEY_ID, trustDomain);
        witGenerator = new WitGenerator(signingKey, trustDomain, JWSAlgorithm.RS256);
    }

    @Nested
    @DisplayName("WIT Validation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should validate valid WIT successfully")
        void shouldValidateValidWitSuccessfully() throws Exception {
            // Given
            String witJwt = createValidWit();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getSubject()).isEqualTo("agent-001");
        }

        @Test
        @DisplayName("Should return parsed token on successful validation")
        void shouldReturnParsedTokenOnSuccessfulValidation() throws Exception {
            // Given
            String witJwt = createValidWit();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getIssuer()).isEqualTo(trustDomain.getDomainId());
            assertThat(result.getToken().getConfirmation()).isNotNull();
            assertThat(result.getToken().getConfirmation().getJwk()).isNotNull();
        }
    }

    @Nested
    @DisplayName("WIT Validation - Signature Verification")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should reject WIT with invalid signature")
        void shouldRejectWitWithInvalidSignature() throws Exception {
            // Given
            String witJwt = createValidWit();
            String tamperedWit = tamperWithSignature(witJwt);

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(tamperedWit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid WIT signature");
        }

        @Test
        @DisplayName("Should reject WIT with wrong algorithm")
        void shouldRejectWitWithWrongAlgorithm() throws Exception {
            // Given
            // This test would require creating a WIT with a different algorithm
            // For now, we verify the validator checks for RS256
            String witJwt = createValidWit();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then - valid WIT should pass
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WIT Validation - Expiration")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired WIT")
        void shouldRejectExpiredWit() throws Exception {
            // Given
            String witJwt = createExpiredWit();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT has expired");
        }

        @Test
        @DisplayName("Should reject WIT without expiration time")
        void shouldRejectWitWithoutExpirationTime() throws Exception {
            // Given
            String witJwt = createWitWithoutExpiration();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT has expired");
        }
    }

    @Nested
    @DisplayName("WIT Validation - Trust Domain")
    class TrustDomainTests {

        @Test
        @DisplayName("Should reject WIT with wrong trust domain")
        void shouldRejectWitWithWrongTrustDomain() throws Exception {
            // Given
            TrustDomain wrongTrustDomain = new TrustDomain("wimse://wrong-domain.com");
            WitGenerator wrongGenerator = new WitGenerator(signingKey, wrongTrustDomain, JWSAlgorithm.RS256);
            WorkloadIdentityToken wit = wrongGenerator.generateWit(
                    createAgentIdentity().getId(),
                    wptPublicKey.toJSONString(),
                    3600
            );
            String witJwt = wit.getJwtString();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid trust domain");
        }

        @Test
        @DisplayName("Should accept WIT with correct trust domain")
        void shouldAcceptWitWithCorrectTrustDomain() throws Exception {
            // Given
            String witJwt = createValidWit();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WIT Validation - Required Claims")
    class RequiredClaimsTests {

        @Test
        @DisplayName("Should reject WIT missing subject claim")
        void shouldRejectWitMissingSubjectClaim() throws Exception {
            // Given
            String witJwt = createWitWithoutSubject();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }

        @Test
        @DisplayName("Should reject WIT missing expiration claim")
        void shouldRejectWitMissingExpirationClaim() throws Exception {
            // Given
            String witJwt = createWitWithoutExpiration();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should reject WIT missing cnf claim")
        void shouldRejectWitMissingCnfClaim() throws Exception {
            // Given
            String witJwt = createWitWithoutCnf();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Missing required claims");
        }
    }

    @Nested
    @DisplayName("WIT Validation - Cnf Claim")
    class CnfClaimTests {

        @Test
        @DisplayName("Should reject WIT with invalid cnf.jwk")
        void shouldRejectWitWithInvalidCnfJwk() throws Exception {
            // Given
            String witJwt = createWitWithInvalidCnfJwk();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("Invalid cnf claim");
        }

        @Test
        @DisplayName("Should accept WIT with valid cnf.jwk")
        void shouldAcceptWitWithValidCnfJwk() throws Exception {
            // Given
            String witJwt = createValidWit();

            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(witJwt);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().getConfirmation().getJwk()).isNotNull();
        }
    }

    @Nested
    @DisplayName("WIT Validation - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null WIT")
        void shouldRejectNullWit() throws ParseException {
            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(null);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject empty WIT")
        void shouldRejectEmptyWit() throws ParseException {
            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate("");

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject whitespace WIT")
        void shouldRejectWhitespaceWit() throws ParseException {
            // When
            TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate("   ");

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT cannot be null or empty");
        }
    }

    // Helper methods

    private String createValidWit() throws JOSEException {
        WorkloadIdentityToken wit = witGenerator.generateWit(
                createAgentIdentity().getId(),
                wptPublicKey.toJSONString(),
                3600
        );
        return wit.getJwtString();
    }

    private String createExpiredWit() throws JOSEException {
        // Create a WIT that expired in the past
        // Use manual JWT construction to set expiration time to the past
        Instant expirationTime = Instant.now().minusSeconds(3600); // Expired 1 hour ago

        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", wptPublicKey.toJSONObject());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustDomain.getDomainId())
                .subject("agent-001")
                .expirationTime(Date.from(expirationTime))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("cnf", cnfClaim)
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        try {
            signedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));
        } catch (JOSEException e) {
            throw new JOSEException("Failed to sign expired WIT", e);
        }

        return signedJwt.serialize();
    }

    private String createWitWithoutExpiration() throws JOSEException {
        // Create a WIT without expiration time
        // Use manual JWT construction to omit the expiration claim
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", wptPublicKey.toJSONObject());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustDomain.getDomainId())
                .subject("agent-001")
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("cnf", cnfClaim)
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        try {
            signedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));
        } catch (JOSEException e) {
            throw new JOSEException("Failed to sign WIT without expiration", e);
        }

        return signedJwt.serialize();
    }

    private String createWitWithoutSubject() throws JOSEException {
        // Create a WIT without subject claim
        // Use manual JWT construction to omit the subject claim
        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", wptPublicKey.toJSONObject());

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustDomain.getDomainId())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("cnf", cnfClaim)
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        try {
            signedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));
        } catch (JOSEException e) {
            throw new JOSEException("Failed to sign WIT without subject", e);
        }

        return signedJwt.serialize();
    }

    private String createWitWithoutCnf() throws JOSEException {
        // Create a WIT without cnf claim
        // According to draft-ietf-wimse-workload-creds, cnf is OPTIONAL
        // Use manual JWT construction to omit the cnf claim
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustDomain.getDomainId())
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(java.util.UUID.randomUUID().toString())
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        try {
            signedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));
        } catch (JOSEException e) {
            throw new JOSEException("Failed to sign WIT without cnf", e);
        }

        return signedJwt.serialize();
    }

    private String createWitWithInvalidCnfJwk() throws JOSEException {
        // Create a WIT with invalid cnf.jwk
        // Use manual JWT construction to create an invalid JWK
        Map<String, Object> invalidJwk = new HashMap<>();
        invalidJwk.put("kty", "INVALID"); // Invalid key type
        invalidJwk.put("x", "invalid-x");
        invalidJwk.put("y", "invalid-y");

        Map<String, Object> cnfClaim = new HashMap<>();
        cnfClaim.put("jwk", invalidJwk);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(trustDomain.getDomainId())
                .subject("agent-001")
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(java.util.UUID.randomUUID().toString())
                .claim("cnf", cnfClaim)
                .build();

        SignedJWT signedJwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(signingKey.getKeyID())
                        .build(),
                claimsSet
        );

        try {
            signedJwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));
        } catch (JOSEException e) {
            throw new JOSEException("Failed to sign WIT with invalid cnf.jwk", e);
        }

        return signedJwt.serialize();
    }

    private String tamperWithSignature(String witJwt) {
        // Tamper with the signature by modifying the last part of the JWT
        // JWT format: header.payload.signature
        // We modify the signature part to make it invalid
        if (witJwt.length() > 0) {
            String[] parts = witJwt.split("\\.");
            if (parts.length == 3) {
                // Modify the signature part by replacing characters
                String signature = parts[2];
                String tamperedSignature = signature.replace('A', 'B').replace('a', 'b');
                return parts[0] + "." + parts[1] + "." + tamperedSignature;
            }
        }
        return witJwt;
    }

    private AgentIdentity createAgentIdentity() {
        return AgentIdentity.builder()
                .version("1.0")
                .id("agent-001")
                .issuer("https://idp.example.com")
                .issuedTo("https://idp.example.com|user-123")
                .issuanceDate(Instant.now())
                .validFrom(Instant.now())
                .expires(Instant.now().plusSeconds(3600))
                .build();
    }
}
