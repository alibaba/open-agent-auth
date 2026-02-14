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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WitSerializer}.
 * Tests verify that WorkloadIdentityToken objects can be correctly serialized
 * to JWT string representations.
 */
@DisplayName("WIT Serializer Tests")
class WitSerializerTest {

    private RSAKey signingKey;
    private WorkloadIdentityToken testWit;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair for signing
        RSAKeyGenerator rsaKeyGenerator = new RSAKeyGenerator(2048);
        signingKey = rsaKeyGenerator.keyID("test-key-id").generate();

        // Create test WIT
        testWit = createTestWit();
    }

    @Nested
    @DisplayName("Successful Serialization Tests")
    class SuccessfulSerializationTests {

        @Test
        @DisplayName("Should serialize WIT with required claims")
        void shouldSerializeWitWithRequiredClaims() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString).matches("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$");
        }

        @Test
        @DisplayName("Should serialize WIT without key ID")
        void shouldSerializeWitWithoutKeyId() throws JOSEException {
            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), null);

            // Assert
            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }

        @Test
        @DisplayName("Should serialize WIT with empty key ID")
        void shouldSerializeWitWithEmptyKeyId() throws JOSEException {
            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), "");

            // Assert
            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
        }

        @Test
        @DisplayName("Should produce valid JWT structure")
        void shouldProduceValidJwtStructure() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String[] parts = jwtString.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(parts[0]).isNotEmpty(); // header
            assertThat(parts[1]).isNotEmpty(); // payload
            assertThat(parts[2]).isNotEmpty(); // signature
        }

        @Test
        @DisplayName("Should include key ID in header when provided")
        void shouldIncludeKeyIdInHeaderWhenProvided() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"kid\":\"test-key-id\"");
        }

        @Test
        @DisplayName("Should serialize WIT with confirmation claim")
        void shouldSerializeWitWithConfirmationClaim() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"cnf\"");
            assertThat(payload).contains("\"jwk\"");
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WIT is null")
        void shouldThrowExceptionWhenWitIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> WitSerializer.serialize(null, new RSASSASigner(signingKey), "key-id"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WorkloadIdentityToken");
        }

        @Test
        @DisplayName("Should throw exception when signer is null")
        void shouldThrowExceptionWhenSignerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> WitSerializer.serialize(testWit, null, "key-id"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWSSigner");
        }
    }

    @Nested
    @DisplayName("JWT Claims Tests")
    class JwtClaimsTests {

        @Test
        @DisplayName("Should include issuer claim")
        void shouldIncludeIssuerClaim() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"iss\":\"https://issuer.example.com\"");
        }

        @Test
        @DisplayName("Should include subject claim")
        void shouldIncludeSubjectClaim() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"sub\":\"workload-001\"");
        }

        @Test
        @DisplayName("Should include expiration claim")
        void shouldIncludeExpirationClaim() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"exp\"");
        }

        @Test
        @DisplayName("Should include JWT ID claim")
        void shouldIncludeJwtIdClaim() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"jti\"");
        }
    }

    @Nested
    @DisplayName("JWT Header Tests")
    class JwtHeaderTests {

        @Test
        @DisplayName("Should include algorithm in header")
        void shouldIncludeAlgorithmInHeader() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"alg\":\"RS256\"");
        }

        @Test
        @DisplayName("Should include type in header")
        void shouldIncludeTypeInHeader() throws JOSEException {
            // Arrange
            String keyId = "test-key-id";

            // Act
            String jwtString = WitSerializer.serialize(testWit, new RSASSASigner(signingKey), keyId);

            // Assert
            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"typ\":\"wit+jwt\"");
        }
    }

    // Helper methods

    private WorkloadIdentityToken createTestWit() throws JOSEException {
        // Create confirmation with EC JWK
        com.nimbusds.jose.jwk.ECKey ecKey = new ECKeyGenerator(
                com.nimbusds.jose.jwk.Curve.P_256)
                .keyID("wpt-key")
                .algorithm(JWSAlgorithm.ES256)
                .generate();
        
        Jwk jwk = Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .algorithm("ES256")
                .keyId("wpt-key")
                .curve(Jwk.Curve.P_256)
                .x(ecKey.getX().toString())
                .y(ecKey.getY().toString())
                .build();
        
        WorkloadIdentityToken.Claims.Confirmation confirmation = 
            WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(jwk)
                .build();

        // Create token header
        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm("RS256")
                .build();

        // Create claims
        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("https://issuer.example.com")
                .subject("workload-001")
                .expirationTime(new java.util.Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .confirmation(confirmation)
                .build();

        // Create WIT
        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.jwt.string")
                .build();
    }
}
