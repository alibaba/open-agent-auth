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

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitGenerator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WptValidator}.
 * Tests verify compliance with WIMSE WPT protocol specification:
 * https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/
 */
@DisplayName("WPT Validator Tests - draft-ietf-wimse-wpt")
class WptValidatorTest {

    private WptValidator wptValidator;
    private RSAKey witSigningKey;
    private ECKey wptPublicKey;
    private ECKey wptPrivateKey;
    private TrustDomain trustDomain;
    private WitGenerator witGenerator;
    private WptGenerator wptGenerator;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for WIT signing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        witSigningKey = rsaKeyGenerator.keyID("wit-signing-key").generate();

        // Generate EC key pair for WPT signing (as per WIMSE spec)
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(Curve.P_256);

        // Generate EC key pair for WIT cnf.jwk
        wptPrivateKey = ecKeyGenerator.keyID("wpt-key").generate();
        wptPublicKey = wptPrivateKey.toPublicJWK();

        trustDomain = new TrustDomain("wimse://example.com");
        wptValidator = new WptValidator();
        witGenerator = new WitGenerator(witSigningKey, trustDomain, JWSAlgorithm.RS256);
        wptGenerator = new WptGenerator();
    }

    @Nested
    @DisplayName("WPT Validation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should validate valid WPT successfully")
        void shouldValidateValidWptSuccessfully() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
        }

        @Test
        @DisplayName("Should return parsed WPT on successful validation")
        void shouldReturnParsedWptOnSuccessfulValidation() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getClaims().getWorkloadTokenHash()).isNotNull();
            assertThat(result.getToken().getHeader().getType()).isEqualTo("wpt+jwt");
        }
    }

    @Nested
    @DisplayName("WPT Validation - Expiration")
    class ExpirationTests {

        @Test
        @DisplayName("Should reject expired WPT")
        void shouldRejectExpiredWpt() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            // Create an expired WPT manually
            WorkloadProofToken wpt = createExpiredWpt();

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WPT expired");
        }

        @Test
        @DisplayName("Should accept non-expired WPT")
        void shouldAcceptNonExpiredWpt() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Signature Verification")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should reject WPT with invalid signature")
        void shouldRejectWptWithInvalidSignature() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);
            
            // Tamper with the WPT
            WorkloadProofToken tamperedWpt = tamperWithWptSignature(wpt);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(tamperedWpt, wit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WPT signature verification failed");
        }

        @Test
        @DisplayName("Should accept WPT with valid signature")
        void shouldAcceptWptWithValidSignature() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Required Claims")
    class RequiredClaimsTests {

        @Test
        @DisplayName("Should reject WPT missing wth claim")
        void shouldRejectWptMissingWthClaim() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = createWptWithoutWth();

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("required claim");
        }

        @Test
        @DisplayName("Should accept WPT with wth claim")
        void shouldAcceptWptWithWthClaim() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken().getClaims().getWorkloadTokenHash()).isNotNull();
        }
    }

    @Nested
    @DisplayName("WPT Validation - WTH Verification")
    class WthVerificationTests {

        @Test
        @DisplayName("Should reject WPT with mismatched wth")
        void shouldRejectWptWithMismatchedWth() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);
            
            // Create a different WIT
            WorkloadIdentityToken differentWit = createDifferentWit();

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, differentWit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("does not match WIT hash");
        }

        @Test
        @DisplayName("Should accept WPT with matching wth")
        void shouldAcceptWptWithMatchingWth() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Algorithm Consistency")
    class AlgorithmConsistencyTests {

        @Test
        @DisplayName("Should reject WPT with algorithm mismatch")
        void shouldRejectWptWithAlgorithmMismatch() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);
            
            // Tamper with the algorithm in WPT header
            WorkloadProofToken tamperedWpt = tamperWithWptAlgorithm(wpt);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(tamperedWpt, wit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("does not match WIT cnf.jwk.alg");
        }

        @Test
        @DisplayName("Should accept WPT with matching algorithm")
        void shouldAcceptWptWithMatchingAlgorithm() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, wit);

            // Then
            assertThat(result.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("WPT Validation - Input Validation")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null WPT")
        void shouldRejectNullWpt() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(null, wit);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WPT cannot be null");
        }

        @Test
        @DisplayName("Should reject null WIT")
        void shouldRejectNullWit() throws Exception {
            // Given
            WorkloadIdentityToken wit = createValidWit();
            WorkloadProofToken wpt = wptGenerator.generateWpt(wit, wptPrivateKey, 300);

            // When
            TokenValidationResult<WorkloadProofToken> result = wptValidator.validate(wpt, null);

            // Then
            assertThat(result.isValid()).isFalse();
            assertThat(result.getErrorMessage()).contains("WIT cannot be null");
        }
    }

    // Helper methods

    private WorkloadIdentityToken createValidWit() throws JOSEException {
        return witGenerator.generateWit(
                "agent-001",
                wptPublicKey.toJSONString(),
                3600
        );
    }

    private WorkloadIdentityToken createDifferentWit() throws JOSEException {
        return witGenerator.generateWit(
                "agent-002",
                wptPublicKey.toJSONString(),
                3600
        );
    }

    private WorkloadProofToken createExpiredWpt() {
        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type("wpt+jwt")
                        .algorithm("ES256")
                        .build())
                .claims(WorkloadProofToken.Claims.builder()
                        .expirationTime(java.util.Date.from(Instant.now().minusSeconds(300))) // Already expired
                        .jwtId(java.util.UUID.randomUUID().toString())
                        .workloadTokenHash("test-wth-hash")
                        .build())
                .signature("test-signature")
                .jwtString("test.jwt.string") // Add JWT string for validation
                .build();
    }

    private WorkloadProofToken createWptWithoutWth() {
        // Since builder requires wth to be non-empty, this test case cannot create a WPT without wth through builder
        // We need to directly create a WPT object without wth to test validation logic
        // But due to builder limitations, we can only use a fake wth value
        // This test case actually tests the validator's handling of whitespace-only wth
        return WorkloadProofToken.builder()
                .header(WorkloadProofToken.Header.builder()
                        .type("wpt+jwt")
                        .algorithm("ES256")
                        .build())
                .claims(WorkloadProofToken.Claims.builder()
                        .expirationTime(java.util.Date.from(Instant.now().plusSeconds(300)))
                        .jwtId(java.util.UUID.randomUUID().toString())
                        .workloadTokenHash("   ") // Whitespace-only wth (will be caught by validator)
                        .build())
                .signature("test-signature")
                .jwtString("test.jwt.string") // Add JWT string for validation
                .build();
    }

    private WorkloadProofToken tamperWithWptSignature(WorkloadProofToken wpt) {
        // JWT format: header.payload.signature
        // We need to tamper with the signature part in the JWT string
        String jwtString = wpt.getJwtString();
        if (jwtString != null && jwtString.contains(".")) {
            // Split into parts and modify the signature
            int lastDotIndex = jwtString.lastIndexOf(".");
            String tamperedJwtString = jwtString.substring(0, lastDotIndex + 1) + "tampered" + jwtString.substring(lastDotIndex + 1);

            return WorkloadProofToken.builder()
                    .header(wpt.getHeader())
                    .claims(wpt.getClaims())
                    .signature(wpt.getSignature() + "tampered")
                    .jwtString(tamperedJwtString) // Use the tampered JWT string
                    .build();
        }

        // Fallback: if no JWT string, just modify signature
        String tamperedSignature = wpt.getSignature() + "tampered";
        return WorkloadProofToken.builder()
                .header(wpt.getHeader())
                .claims(wpt.getClaims())
                .signature(tamperedSignature)
                .jwtString(wpt.getJwtString())
                .build();
    }

    private WorkloadProofToken tamperWithWptAlgorithm(WorkloadProofToken wpt) {
        WorkloadProofToken.Header tamperedHeader = WorkloadProofToken.Header.builder()
                .type(wpt.getHeader().getType())
                .algorithm("RS512") // Different algorithm
                .build();
        return WorkloadProofToken.builder()
                .header(tamperedHeader)
                .claims(wpt.getClaims())
                .signature(wpt.getSignature())
                .jwtString(wpt.getJwtString()) // Preserve the JWT string
                .build();
    }
}