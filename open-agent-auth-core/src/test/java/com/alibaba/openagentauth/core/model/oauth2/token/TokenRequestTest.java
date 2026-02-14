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
package com.alibaba.openagentauth.core.model.oauth2.token;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TokenRequest.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * TokenRequest, including normal construction, method chaining,
 * required field validation, optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("TokenRequest.Builder Tests")
class TokenRequestTest {

    private static final String GRANT_TYPE = "authorization_code";
    private static final String CODE = "auth_code_12345";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String CLIENT_ID = "client_abc";
    private static final String CLIENT_SECRET = "secret_xyz";
    private static final String CLIENT_ASSERTION = "jwt_assertion";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build request with all required fields")
        void shouldBuildRequestWithAllRequiredFields() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getGrantType()).isEqualTo(GRANT_TYPE);
            assertThat(request.getCode()).isEqualTo(CODE);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should build request with all fields")
        void shouldBuildRequestWithAllFields() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .grantType(GRANT_TYPE)
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getGrantType()).isEqualTo(GRANT_TYPE);
            assertThat(request.getCode()).isEqualTo(CODE);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request.getClientSecret()).isEqualTo(CLIENT_SECRET);
        }

        @Test
        @DisplayName("Should build request with JWT assertion")
        void shouldBuildRequestWithJwtAssertion() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientAssertion(CLIENT_ASSERTION)
                    .clientAssertionType(CLIENT_ASSERTION_TYPE)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getClientAssertion()).isEqualTo(CLIENT_ASSERTION);
            assertThat(request.getClientAssertionType()).isEqualTo(CLIENT_ASSERTION_TYPE);
        }

        @Test
        @DisplayName("Should build request with additional parameters")
        void shouldBuildRequestWithAdditionalParameters() {
            // Given
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("custom_param", "custom_value");

            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .additionalParameters(additionalParams)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getAdditionalParameters()).isEqualTo(additionalParams);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .grantType(GRANT_TYPE)
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getGrantType()).isEqualTo(GRANT_TYPE);
            assertThat(request.getCode()).isEqualTo(CODE);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request.getClientSecret()).isEqualTo(CLIENT_SECRET);
        }
    }

    @Nested
    @DisplayName("Required Field Validation Tests")
    class RequiredFieldValidationTests {

        @Test
        @DisplayName("Should throw exception when code is null")
        void shouldThrowExceptionWhenCodeIsNull() {
            // When & Then
            assertThatThrownBy(() -> TokenRequest.builder()
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("code is required");
        }

        @Test
        @DisplayName("Should throw exception when code is empty")
        void shouldThrowExceptionWhenCodeIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code("")
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("code is required");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            // When & Then
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code(CODE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uri is required");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is empty")
        void shouldThrowExceptionWhenRedirectUriIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> TokenRequest.builder()
                    .code(CODE)
                    .redirectUri("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uri is required");
        }

        @Test
        @DisplayName("Should throw exception when grantType is not authorization_code")
        void shouldThrowExceptionWhenGrantTypeIsNotAuthorizationCode() {
            // When & Then
            assertThatThrownBy(() -> TokenRequest.builder()
                    .grantType("invalid_grant_type")
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("grant_type must be 'authorization_code'");
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getClientId()).isNull();
            assertThat(request.getClientSecret()).isNull();
            assertThat(request.getClientAssertion()).isNull();
            assertThat(request.getClientAssertionType()).isNull();
            assertThat(request.getAdditionalParameters()).isNull();
        }

        @Test
        @DisplayName("Should set optional clientId field")
        void shouldSetOptionalClientIdField() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            // Then
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should set optional clientSecret field")
        void shouldSetOptionalClientSecretField() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientSecret(CLIENT_SECRET)
                    .build();

            // Then
            assertThat(request.getClientSecret()).isEqualTo(CLIENT_SECRET);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request).isInstanceOf(TokenRequest.class);
            assertThat(request.getCode()).isEqualTo(CODE);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            TokenRequest.Builder builder = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI);

            // When
            TokenRequest request1 = builder.build();
            builder.code("different_code");
            TokenRequest request2 = builder.build();

            // Then
            assertThat(request1.getCode()).isEqualTo(CODE);
            assertThat(request2.getCode()).isEqualTo("different_code");
        }
    }

    @Nested
    @DisplayName("Utility Method Tests")
    class UtilityMethodTests {

        @Test
        @DisplayName("Should return true when using client_secret_post")
        void shouldReturnTrueWhenUsingClientSecretPost() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .build();

            // Then
            assertThat(request.usesClientSecretPost()).isTrue();
        }

        @Test
        @DisplayName("Should return false when not using client_secret_post")
        void shouldReturnFalseWhenNotUsingClientSecretPost() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request.usesClientSecretPost()).isFalse();
        }

        @Test
        @DisplayName("Should return true when using JWT assertion")
        void shouldReturnTrueWhenUsingJwtAssertion() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientAssertion(CLIENT_ASSERTION)
                    .clientAssertionType(CLIENT_ASSERTION_TYPE)
                    .build();

            // Then
            assertThat(request.usesJwtAssertion()).isTrue();
        }

        @Test
        @DisplayName("Should return false when not using JWT assertion")
        void shouldReturnFalseWhenNotUsingJwtAssertion() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request.usesJwtAssertion()).isFalse();
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // When
            TokenRequest request1 = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            TokenRequest request2 = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when codes differ")
        void shouldNotBeEqualWhenCodesDiffer() {
            // When
            TokenRequest request1 = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .build();

            TokenRequest request2 = TokenRequest.builder()
                    .code("different_code")
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request1).isNotEqualTo(request2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // When
            TokenRequest request = TokenRequest.builder()
                    .code(CODE)
                    .redirectUri(REDIRECT_URI)
                    .clientId(CLIENT_ID)
                    .build();

            // Then
            String toString = request.toString();
            assertThat(toString).contains("TokenRequest");
            assertThat(toString).contains(CODE);
            assertThat(toString).contains(REDIRECT_URI);
            assertThat(toString).contains(CLIENT_ID);
            assertThat(toString).contains("[PROTECTED]");
        }
    }
}
