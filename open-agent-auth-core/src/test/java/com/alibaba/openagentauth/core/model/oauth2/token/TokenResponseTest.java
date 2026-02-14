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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TokenResponse.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * TokenResponse, including normal construction, method chaining,
 * required field validation, optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("TokenResponse.Builder Tests")
class TokenResponseTest {

    private static final String ACCESS_TOKEN = "access_token_12345";
    private static final String TOKEN_TYPE = "Bearer";
    private static final Long EXPIRES_IN = 3600L;
    private static final String REFRESH_TOKEN = "refresh_token_67890";
    private static final String SCOPE = "read write";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build response with all required fields")
        void shouldBuildResponseWithAllRequiredFields() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo(TOKEN_TYPE);
        }

        @Test
        @DisplayName("Should build response with all fields")
        void shouldBuildResponseWithAllFields() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn(EXPIRES_IN)
                    .refreshToken(REFRESH_TOKEN)
                    .scope(SCOPE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo(TOKEN_TYPE);
            assertThat(response.getExpiresIn()).isEqualTo(EXPIRES_IN);
            assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(response.getScope()).isEqualTo(SCOPE);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn(EXPIRES_IN)
                    .refreshToken(REFRESH_TOKEN)
                    .scope(SCOPE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getTokenType()).isEqualTo(TOKEN_TYPE);
            assertThat(response.getExpiresIn()).isEqualTo(EXPIRES_IN);
            assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
            assertThat(response.getScope()).isEqualTo(SCOPE);
        }
    }

    @Nested
    @DisplayName("Required Field Validation Tests")
    class RequiredFieldValidationTests {

        @Test
        @DisplayName("Should throw exception when accessToken is null")
        void shouldThrowExceptionWhenAccessTokenIsNull() {
            // When & Then
            assertThatThrownBy(() -> TokenResponse.builder()
                    .tokenType(TOKEN_TYPE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("access_token is required");
        }

        @Test
        @DisplayName("Should throw exception when accessToken is empty")
        void shouldThrowExceptionWhenAccessTokenIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> TokenResponse.builder()
                    .accessToken("")
                    .tokenType(TOKEN_TYPE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("access_token is required");
        }

        @Test
        @DisplayName("Should throw exception when tokenType is null")
        void shouldThrowExceptionWhenTokenTypeIsNull() {
            // When & Then
            // Note: tokenType has default value "Bearer", so it cannot be null
            // This test verifies that setting tokenType to null explicitly will cause an exception
            assertThatThrownBy(() -> TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("token_type is required");
        }

        @Test
        @DisplayName("Should throw exception when tokenType is empty")
        void shouldThrowExceptionWhenTokenTypeIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("token_type is required");
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getExpiresIn()).isNull();
            assertThat(response.getRefreshToken()).isNull();
            assertThat(response.getScope()).isNull();
        }

        @Test
        @DisplayName("Should set optional expiresIn field")
        void shouldSetOptionalExpiresInField() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn(EXPIRES_IN)
                    .build();

            // Then
            assertThat(response.getExpiresIn()).isEqualTo(EXPIRES_IN);
        }

        @Test
        @DisplayName("Should set optional refreshToken field")
        void shouldSetOptionalRefreshTokenField() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .refreshToken(REFRESH_TOKEN)
                    .build();

            // Then
            assertThat(response.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
        }

        @Test
        @DisplayName("Should set optional scope field")
        void shouldSetOptionalScopeField() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .scope(SCOPE)
                    .build();

            // Then
            assertThat(response.getScope()).isEqualTo(SCOPE);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .build();

            // Then
            assertThat(response).isInstanceOf(TokenResponse.class);
            assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            TokenResponse.Builder builder = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE);

            // When
            TokenResponse response1 = builder.build();
            builder.accessToken("different_token");
            TokenResponse response2 = builder.build();

            // Then
            assertThat(response1.getAccessToken()).isEqualTo(ACCESS_TOKEN);
            assertThat(response2.getAccessToken()).isEqualTo("different_token");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // When
            TokenResponse response1 = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .build();

            TokenResponse response2 = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .build();

            // Then
            assertThat(response1).isEqualTo(response2);
            assertThat(response1.hashCode()).isEqualTo(response2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when accessTokens differ")
        void shouldNotBeEqualWhenAccessTokensDiffer() {
            // When
            TokenResponse response1 = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .build();

            TokenResponse response2 = TokenResponse.builder()
                    .accessToken("different_token")
                    .tokenType(TOKEN_TYPE)
                    .build();

            // Then
            assertThat(response1).isNotEqualTo(response2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // When
            TokenResponse response = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn(EXPIRES_IN)
                    .scope(SCOPE)
                    .build();

            // Then
            String toString = response.toString();
            assertThat(toString).contains("TokenResponse");
            assertThat(toString).contains(ACCESS_TOKEN);
            assertThat(toString).contains(TOKEN_TYPE);
            assertThat(toString).contains(String.valueOf(EXPIRES_IN));
            assertThat(toString).contains(SCOPE);
        }
    }
}
