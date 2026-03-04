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
package com.alibaba.openagentauth.core.token;

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("TokenService Tests")
class TokenServiceTest {

    private TokenService tokenService;
    private JWK signingKey;
    private TrustDomain trustDomain;

    @BeforeEach
    void setUp() throws Exception {
        // Create a test RSA key
        signingKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        trustDomain = new TrustDomain("test-domain");
        tokenService = new TokenService(signingKey, trustDomain, JWSAlgorithm.RS256);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create TokenService instance with valid parameters")
        void shouldCreateTokenServiceInstanceWithValidParameters() {
            // Act
            TokenService service = new TokenService(signingKey, trustDomain, JWSAlgorithm.RS256);

            // Assert
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when signing key is null")
        void shouldThrowExceptionWhenSigningKeyIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new TokenService(null, trustDomain, JWSAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("WIT signing key");
        }

        @Test
        @DisplayName("Should throw exception when trust domain is null")
        void shouldThrowExceptionWhenTrustDomainIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new TokenService(signingKey, null, JWSAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Trust domain");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new TokenService(signingKey, trustDomain, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Algorithm");
        }
    }

    @Nested
    @DisplayName("GenerateWit Tests")
    class GenerateWitTests {

        @Test
        @DisplayName("Should generate WIT successfully")
        void shouldGenerateWitSuccessfully() throws JOSEException {
            // Arrange
            String subject = "workload-123";
            String wptPublicKey = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}";
            long expirationSeconds = 3600;

            // Act
            WorkloadIdentityToken wit = tokenService.generateWit(subject, wptPublicKey, expirationSeconds);

            // Assert
            assertThat(wit).isNotNull();
        }

        @Test
        @DisplayName("Should generate WIT as string successfully")
        void shouldGenerateWitAsStringSuccessfully() throws JOSEException {
            // Arrange
            String subject = "workload-123";
            String wptPublicKey = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}";
            long expirationSeconds = 3600;

            // Act
            String witString = tokenService.generateWitAsString(subject, wptPublicKey, expirationSeconds);

            // Assert
            assertThat(witString).isNotNull();
            assertThat(witString).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("GenerateWpt Tests")
    class GenerateWptTests {

        @Test
        @DisplayName("Should generate WPT successfully")
        void shouldGenerateWptSuccessfully() throws JOSEException {
            // Arrange
            String subject = "workload-123";
            String wptPublicKey = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}";
            WorkloadIdentityToken wit = tokenService.generateWit(subject, wptPublicKey, 3600);
            JWK wptPrivateKey = signingKey;
            long expirationSeconds = 300;

            // Act
            WorkloadProofToken wpt = tokenService.generateWpt(wit, wptPrivateKey, expirationSeconds);

            // Assert
            assertThat(wpt).isNotNull();
        }

        @Test
        @DisplayName("Should generate WPT as string successfully")
        void shouldGenerateWptAsStringSuccessfully() throws JOSEException {
            // Arrange
            String subject = "workload-123";
            String wptPublicKey = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}";
            WorkloadIdentityToken wit = tokenService.generateWit(subject, wptPublicKey, 3600);
            JWK wptPrivateKey = signingKey;
            long expirationSeconds = 300;

            // Act
            String wptString = tokenService.generateWptAsString(wit, wptPrivateKey, expirationSeconds);

            // Assert
            assertThat(wptString).isNotNull();
            assertThat(wptString).isNotEmpty();
        }

        @Test
        @DisplayName("Should generate WPT with AOAT binding successfully")
        void shouldGenerateWptWithAoatBindingSuccessfully() throws JOSEException {
            // Arrange
            String subject = "workload-123";
            String wptPublicKey = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}";
            WorkloadIdentityToken wit = tokenService.generateWit(subject, wptPublicKey, 3600);
            JWK wptPrivateKey = signingKey;
            long expirationSeconds = 300;
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            when(aoat.getJwtString()).thenReturn("test.aoat.jwt");

            // Act
            String wptString = tokenService.generateWptAsString(wit, wptPrivateKey, expirationSeconds, aoat);

            // Assert
            assertThat(wptString).isNotNull();
            assertThat(wptString).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("ValidateWpt Tests")
    class ValidateWptTests {

        @Test
        @DisplayName("Should validate WPT successfully")
        void shouldValidateWptSuccessfully() throws JOSEException {
            // Arrange
            String subject = "workload-123";
            String wptPublicKey = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\"}";
            WorkloadIdentityToken wit = tokenService.generateWit(subject, wptPublicKey, 3600);
            JWK wptPrivateKey = signingKey;
            WorkloadProofToken wpt = tokenService.generateWpt(wit, wptPrivateKey, 300);

            // Act
            TokenValidationResult<WorkloadProofToken> result = tokenService.validateWpt(wpt, wit);

            // Assert
            assertThat(result).isNotNull();
        }
    }

    @Nested
    @DisplayName("GetWitGenerator Tests")
    class GetWitGeneratorTests {

        @Test
        @DisplayName("Should return WIT generator")
        void shouldReturnWitGenerator() {
            // Act
            var generator = tokenService.getWitGenerator();

            // Assert
            assertThat(generator).isNotNull();
        }
    }

}