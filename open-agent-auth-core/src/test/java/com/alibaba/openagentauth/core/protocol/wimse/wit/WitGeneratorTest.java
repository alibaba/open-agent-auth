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

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WitGenerator}.
 * Tests verify compliance with WIMSE WIT protocol specification:
 * https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/
 */
@DisplayName("WIT Generator Tests - draft-ietf-wimse-workload-creds")
class WitGeneratorTest {

    private RSAKey signingKey;
    private RSAKey verificationKey;
    private TrustDomain trustDomain;
    private WitGenerator witGenerator;
    private String workloadId;
    private ECKey wptPublicKey;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for WIT signing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        signingKey = rsaKeyGenerator.keyID("wit-signing-key").generate();
        verificationKey = signingKey.toPublicJWK();

        // Generate EC key pair for WPT (as per WIMSE spec recommendation)
        // Explicitly set algorithm to ES256 for EC P-256 keys
        ECKey wptKeyPair = new ECKeyGenerator(Curve.P_256)
                .algorithm(new JWSAlgorithm(JWSAlgorithm.ES256.getName()))
                .keyID("wpt-key")
                .generate();
        wptPublicKey = wptKeyPair.toPublicJWK();

        trustDomain = new TrustDomain("wimse://example.com");
        witGenerator = new WitGenerator(signingKey, trustDomain, JWSAlgorithm.RS256);

        // Initialize test workload ID
        workloadId = "agent-001";
    }

    @Nested
    @DisplayName("WIT Generation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should generate valid WIT with all required claims")
        void shouldGenerateValidWitWithRequiredClaims() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            assertThat(wit).isNotNull();
            assertThat(wit.getJwtString()).isNotNull();
            assertThat(wit.getJwtString()).isNotEmpty();

            // Verify required claims per draft-ietf-wimse-workload-creds
            assertThat(wit.getSubject()).isEqualTo(workloadId);
            assertThat(wit.getIssuer()).isEqualTo(trustDomain.getDomainId());
            assertThat(wit.getExpirationTime()).isNotNull();
            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getConfirmation().getJwk()).isNotNull();
            assertThat(wit.getJwtId()).isNotNull();
        }

        @Test
        @DisplayName("Should include cnf.jwk with alg field per spec")
        void shouldIncludeCnfJwkWithAlgField() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            // Verify cnf.jwk structure per RFC 7800
            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getConfirmation().getJwk()).isNotNull();
            assertThat(wit.getConfirmation().getJwk().getAlgorithm()).isNotNull();
            assertThat(wit.getConfirmation().getJwk().getAlgorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should set expiration time correctly")
        void shouldSetExpirationTimeCorrectly() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 7200;
            String wptPublicKeyJson = wptPublicKey.toJSONString();
            Instant beforeGeneration = Instant.now();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            Instant expirationTime = wit.getExpirationTime().toInstant();

            // JWT exp claim is NumericDate (seconds since epoch), so it has second-level precision
            // Truncate expected times to seconds for comparison
            Instant expectedMin = beforeGeneration.truncatedTo(ChronoUnit.SECONDS)
                    .plusSeconds(expirationSeconds);
            Instant expectedMax = beforeGeneration.truncatedTo(ChronoUnit.SECONDS)
                    .plusSeconds(expirationSeconds + 1);

            assertThat(expirationTime).isBetween(expectedMin, expectedMax);
        }

        @Test
        @DisplayName("Should generate unique jti for each WIT")
        void shouldGenerateUniqueJtiForEachWit() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit1 = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);
            WorkloadIdentityToken wit2 = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            assertThat(wit1.getJwtId()).isNotNull();
            assertThat(wit2.getJwtId()).isNotNull();
            assertThat(wit1.getJwtId()).isNotEqualTo(wit2.getJwtId());
        }

        @Test
        @DisplayName("Should be verifiable by WitValidator")
        void shouldBeVerifiableByWitValidator() throws Exception {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();
            String verificationKeyId = "test-verification-key";
            KeyManager mockKeyManager = mock(KeyManager.class);
            when(mockKeyManager.resolveVerificationKey(anyString())).thenReturn(verificationKey);
            WitValidator validator = new WitValidator(mockKeyManager, verificationKeyId, trustDomain);

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);
            String witJwt = wit.getJwtString();

            // Then
            var result = validator.validate(witJwt);
            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getSubject()).isEqualTo(workloadId);
        }
    }

    @Nested
    @DisplayName("WIT Generation - Parameter Validation")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when agentIdentity is null")
        void shouldThrowExceptionWhenAgentIdentityIsNull() {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When & Then
            assertThatThrownBy(() -> witGenerator.generateWit(null, wptPublicKeyJson, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Subject cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when wptPublicKey is null")
        void shouldThrowExceptionWhenWptPublicKeyIsNull() {
            // Given
            long expirationSeconds = 3600;

            // When & Then
            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, null, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT public key cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when wptPublicKey is empty")
        void shouldThrowExceptionWhenWptPublicKeyIsEmpty() {
            // Given
            long expirationSeconds = 3600;

            // When & Then
            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, "  ", expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT public key cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when wptPublicKey is invalid")
        void shouldThrowExceptionWhenWptPublicKeyIsInvalid() {
            // Given
            long expirationSeconds = 3600;
            String invalidPublicKey = "invalid-jwk-format";

            // When & Then
            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, invalidPublicKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invalid WPT public key format");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is zero")
        void shouldThrowExceptionWhenExpirationSecondsIsZero() {
            // Given
            long expirationSeconds = 0;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When & Then
            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is negative")
        void shouldThrowExceptionWhenExpirationSecondsIsNegative() {
            // Given
            long expirationSeconds = -100;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When & Then
            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }
    }

    @Nested
    @DisplayName("WIT Generation - Constructor Validation")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw exception when signingKey is null")
        void shouldThrowExceptionWhenSigningKeyIsNull() {
            // When & Then
            assertThatThrownBy(() -> new WitGenerator(null, trustDomain, JWSAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signing key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when trustDomain is null")
        void shouldThrowExceptionWhenTrustDomainIsNull() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new WitGenerator(signingKey, null, JWSAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Trust domain cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() throws JOSEException {
            // When & Then
            assertThatThrownBy(() -> new WitGenerator(signingKey, trustDomain, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Algorithm cannot be null");
        }
    }

    @Nested
    @DisplayName("WIT Generation - Protocol Compliance")
    class ProtocolComplianceTests {

        @Test
        @DisplayName("Should use correct media type 'wit+jwt'")
        void shouldUseCorrectMediaType() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            assertThat(wit.getHeader().getType()).isEqualTo("wit+jwt");
        }

        @Test
        @DisplayName("Should use correct algorithm RS256")
        void shouldUseCorrectAlgorithm() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            assertThat(wit.getHeader().getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should include subject as Workload Identifier")
        void shouldIncludeSubjectAsWorkloadIdentifier() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            assertThat(wit.getSubject()).isEqualTo(workloadId);
            assertThat(wit.getWorkloadIdentifier()).isEqualTo(workloadId);
        }

        @Test
        @DisplayName("Should support EC key for WPT verification")
        void shouldSupportEcKeyForWptVerification() throws JOSEException, ParseException {
            // Given
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            // When
            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            // Then
            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getConfirmation().getJwk()).isNotNull();
            assertThat(wit.getConfirmation().getJwk().getKeyType()).isEqualTo(Jwk.KeyType.EC);
        }
    }
}