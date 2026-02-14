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

import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WptSerializer}.
 * Tests verify that WorkloadProofToken objects can be correctly serialized
 * to JWT string representations.
 */
@DisplayName("WPT Serializer Tests")
class WptSerializerTest {

    private ECKey signingKey;
    private WorkloadProofToken testWpt;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate EC key pair for signing (ES256 uses P-256 curve)
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256);
        signingKey = ecKeyGenerator.keyID("test-key-id").generate();

        // Create test WPT
        testWpt = createTestWpt();
    }

    @Nested
    @DisplayName("Successful Serialization Tests")
    class SuccessfulSerializationTests {

        @Test
        @DisplayName("Should serialize WPT with required claims")
        void shouldSerializeWptWithRequiredClaims() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString).matches("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$");
        }

        @Test
        @DisplayName("Should produce valid JWT structure")
        void shouldProduceValidJwtStructure() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            String[] parts = jwtString.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(parts[0]).isNotEmpty(); // header
            assertThat(parts[1]).isNotEmpty(); // payload
            assertThat(parts[2]).isNotEmpty(); // signature
        }

        @Test
        @DisplayName("Should serialize WPT with audience")
        void shouldSerializeWptWithAudience() throws JOSEException {
            // Arrange
            WorkloadProofToken wptWithAudience = createTestWptWithAudience();

            // Act
            String jwtString = WptSerializer.serialize(wptWithAudience, new ECDSASigner(signingKey));

            // Assert
            assertThat(jwtString).isNotNull();
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"aud\":\"https://api.example.com\"");
        }

        @Test
        @DisplayName("Should serialize WPT with access token hash")
        void shouldSerializeWptWithAccessTokenHash() throws JOSEException {
            // Arrange
            WorkloadProofToken wptWithAth = createTestWptWithAccessTokenHash();

            // Act
            String jwtString = WptSerializer.serialize(wptWithAth, new ECDSASigner(signingKey));

            // Assert
            assertThat(jwtString).isNotNull();
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"ath\"");
        }

        @Test
        @DisplayName("Should serialize WPT with transaction token hash")
        void shouldSerializeWptWithTransactionTokenHash() throws JOSEException {
            // Arrange
            WorkloadProofToken wptWithTth = createTestWptWithTransactionTokenHash();

            // Act
            String jwtString = WptSerializer.serialize(wptWithTth, new ECDSASigner(signingKey));

            // Assert
            assertThat(jwtString).isNotNull();
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"tth\"");
        }

        @Test
        @DisplayName("Should serialize WPT with other token hashes")
        void shouldSerializeWptWithOtherTokenHashes() throws JOSEException {
            // Arrange
            WorkloadProofToken wptWithOth = createTestWptWithOtherTokenHashes();

            // Act
            String jwtString = WptSerializer.serialize(wptWithOth, new ECDSASigner(signingKey));

            // Assert
            assertThat(jwtString).isNotNull();
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"oth\"");
            assertThat(payload).contains("\"aoat\"");
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WPT is null")
        void shouldThrowExceptionWhenWptIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> WptSerializer.serialize(null, new ECDSASigner(signingKey)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WorkloadProofToken");
        }

        @Test
        @DisplayName("Should throw exception when signer is null")
        void shouldThrowExceptionWhenSignerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> WptSerializer.serialize(testWpt, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWSSigner");
        }
    }

    @Nested
    @DisplayName("JWT Claims Tests")
    class JwtClaimsTests {

        @Test
        @DisplayName("Should include expiration claim")
        void shouldIncludeExpirationClaim() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"exp\"");
        }

        @Test
        @DisplayName("Should include JWT ID claim")
        void shouldIncludeJwtIdClaim() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"jti\"");
        }

        @Test
        @DisplayName("Should include workload token hash claim")
        void shouldIncludeWorkloadTokenHashClaim() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"wth\"");
        }
    }

    @Nested
    @DisplayName("JWT Header Tests")
    class JwtHeaderTests {

        @Test
        @DisplayName("Should include algorithm in header")
        void shouldIncludeAlgorithmInHeader() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"alg\":\"ES256\"");
        }

        @Test
        @DisplayName("Should include type in header")
        void shouldIncludeTypeInHeader() throws JOSEException {
            // Act
            String jwtString = WptSerializer.serialize(testWpt, new ECDSASigner(signingKey));

            // Assert
            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"typ\":\"wpt+jwt\"");
        }
    }

    // Helper methods

    private WorkloadProofToken createTestWpt() {
        // Create header
        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type("wpt+jwt")
                .algorithm("ES256")
                .build();

        // Create claims
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .build();

        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createTestWptWithAudience() {
        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type("wpt+jwt")
                .algorithm("ES256")
                .build();

        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .audience("https://api.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .build();

        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createTestWptWithAccessTokenHash() {
        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type("wpt+jwt")
                .algorithm("ES256")
                .build();

        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .accessTokenHash("test-ath-hash")
                .build();

        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createTestWptWithTransactionTokenHash() {
        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type("wpt+jwt")
                .algorithm("ES256")
                .build();

        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .transactionTokenHash("test-tth-hash")
                .build();

        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createTestWptWithOtherTokenHashes() {
        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type("wpt+jwt")
                .algorithm("ES256")
                .build();

        Map<String, String> otherTokenHashes = Map.of("aoat", "test-aoat-hash");

        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .otherTokenHashes(otherTokenHashes)
                .build();

        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }
}
