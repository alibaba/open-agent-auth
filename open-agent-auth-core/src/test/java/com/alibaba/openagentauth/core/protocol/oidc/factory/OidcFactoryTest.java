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
package com.alibaba.openagentauth.core.protocol.oidc.factory;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link OidcFactory.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * OidcFactory, including normal construction, method chaining,
 * required field validation, optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("OidcFactory.Builder Tests")
class OidcFactoryTest {

    private static final String ISSUER = "https://issuer.example";
    private static final String ALGORITHM = "RS256";
    private static final String USER_INFO_ENDPOINT = "https://issuer.example/userinfo";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build factory with all required fields")
        void shouldBuildFactoryWithAllRequiredFields() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // Then
            assertThat(factory).isNotNull();
            assertThat(factory.getIssuer()).isEqualTo(ISSUER);
            assertThat(factory.getAlgorithm()).isEqualTo(ALGORITHM);
        }

        @Test
        @DisplayName("Should build factory with all fields including optional")
        void shouldBuildFactoryWithAllFieldsIncludingOptional() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .userInfoEndpoint(USER_INFO_ENDPOINT)
                    .build();

            // Then
            assertThat(factory).isNotNull();
            assertThat(factory.getIssuer()).isEqualTo(ISSUER);
            assertThat(factory.getAlgorithm()).isEqualTo(ALGORITHM);
            assertThat(factory.getUserInfoEndpoint()).isEqualTo(USER_INFO_ENDPOINT);
        }

        @Test
        @DisplayName("Should use default algorithm when not set")
        void shouldUseDefaultAlgorithmWhenNotSet() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .build();

            // Then
            assertThat(factory).isNotNull();
            assertThat(factory.getAlgorithm()).isEqualTo("RS256");
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .userInfoEndpoint(USER_INFO_ENDPOINT)
                    .build();

            // Then
            assertThat(factory).isNotNull();
            assertThat(factory.getIssuer()).isEqualTo(ISSUER);
            assertThat(factory.getAlgorithm()).isEqualTo(ALGORITHM);
            assertThat(factory.getUserInfoEndpoint()).isEqualTo(USER_INFO_ENDPOINT);
        }
    }

    @Nested
    @DisplayName("Required Field Validation Tests")
    class RequiredFieldValidationTests {

        @Test
        @DisplayName("Should throw exception when issuer is null")
        void shouldThrowExceptionWhenIssuerIsNull() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When & Then
            assertThatThrownBy(() -> OidcFactory.builder()
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("issuer is required");
        }

        @Test
        @DisplayName("Should throw exception when issuer is empty")
        void shouldThrowExceptionWhenIssuerIsEmpty() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When & Then
            assertThatThrownBy(() -> OidcFactory.builder()
                    .issuer("")
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("issuer is required");
        }

        @Test
        @DisplayName("Should throw exception when signingKey is null")
        void shouldThrowExceptionWhenSigningKeyIsNull() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When & Then
            assertThatThrownBy(() -> OidcFactory.builder()
                    .issuer(ISSUER)
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("signingKey is required");
        }

        @Test
        @DisplayName("Should throw exception when verificationKey is null")
        void shouldThrowExceptionWhenVerificationKeyIsNull() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When & Then
            assertThatThrownBy(() -> OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .algorithm(ALGORITHM)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("verificationKey is required");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When & Then
            assertThatThrownBy(() -> OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("algorithm is required");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is empty")
        void shouldThrowExceptionWhenAlgorithmIsEmpty() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When & Then
            assertThatThrownBy(() -> OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("algorithm is required");
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional userInfoEndpoint field")
        void shouldAllowNullOptionalUserInfoEndpointField() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // Then
            assertThat(factory).isNotNull();
            assertThat(factory.getUserInfoEndpoint()).isNull();
        }

        @Test
        @DisplayName("Should set optional userInfoEndpoint field")
        void shouldSetOptionalUserInfoEndpointField() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .userInfoEndpoint(USER_INFO_ENDPOINT)
                    .build();

            // Then
            assertThat(factory).isNotNull();
            assertThat(factory.getUserInfoEndpoint()).isEqualTo(USER_INFO_ENDPOINT);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            // When
            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // Then
            assertThat(factory).isInstanceOf(OidcFactory.class);
            assertThat(factory.getIssuer()).isEqualTo(ISSUER);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            OidcFactory.Builder builder = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM);

            // When
            OidcFactory factory1 = builder.build();
            builder.issuer("different_issuer");
            OidcFactory factory2 = builder.build();

            // Then
            assertThat(factory1.getIssuer()).isEqualTo(ISSUER);
            assertThat(factory2.getIssuer()).isEqualTo("different_issuer");
        }
    }

    @Nested
    @DisplayName("Factory Method Tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("Should create IdTokenGenerator")
        void shouldCreateIdTokenGenerator() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // When
            var generator = factory.createIdTokenGenerator();

            // Then
            assertThat(generator).isNotNull();
        }

        @Test
        @DisplayName("Should create IdTokenValidator")
        void shouldCreateIdTokenValidator() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // When
            var validator = factory.createIdTokenValidator();

            // Then
            assertThat(validator).isNotNull();
        }

        @Test
        @DisplayName("Should create IdTokenValidator with custom clock skew")
        void shouldCreateIdTokenValidatorWithCustomClockSkew() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // When
            var validator = factory.createIdTokenValidator(30);

            // Then
            assertThat(validator).isNotNull();
        }

        @Test
        @DisplayName("Should create IdTokenBuilder")
        void shouldCreateIdTokenBuilder() throws NoSuchAlgorithmException {
            // Given
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

            OidcFactory factory = OidcFactory.builder()
                    .issuer(ISSUER)
                    .signingKey(keyPair.getPrivate())
                    .verificationKey(keyPair.getPublic())
                    .algorithm(ALGORITHM)
                    .build();

            // When
            var builder = factory.createIdTokenBuilder();

            // Then
            assertThat(builder).isNotNull();
        }
    }
}
