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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AuthorizationResponse.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * AuthorizationResponse, including normal construction, method chaining,
 * required field validation, and error handling.
 * </p>
 */
@DisplayName("AuthorizationResponse.Builder Tests")
class AuthorizationResponseTest {

    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String AUTHORIZATION_CODE = "SplxlOBeZQQYbYS6WxSbIA";
    private static final String STATE = "xyz123";
    private static final String ERROR = "access_denied";
    private static final String ERROR_DESCRIPTION = "The resource owner denied the request";
    private static final String ERROR_URI = "https://example.com/errors/access_denied";

    @Nested
    @DisplayName("Success Response Tests")
    class SuccessResponseTests {

        @Test
        @DisplayName("Should build successful response with authorization code")
        void shouldBuildSuccessfulResponseWithAuthorizationCode() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .authorizationCode(AUTHORIZATION_CODE)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(response.getState()).isEqualTo(STATE);
            assertThat(response.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(response.getError()).isNull();
            assertThat(response.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should build successful response with minimal fields")
        void shouldBuildSuccessfulResponseWithMinimalFields() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .authorizationCode(AUTHORIZATION_CODE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getAuthorizationCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(response.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .authorizationCode(AUTHORIZATION_CODE)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(response.getAuthorizationCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(response.getState()).isEqualTo(STATE);
        }
    }

    @Nested
    @DisplayName("Error Response Tests")
    class ErrorResponseTests {

        @Test
        @DisplayName("Should build error response with error code")
        void shouldBuildErrorResponseWithErrorCode() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .error(ERROR)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getError()).isEqualTo(ERROR);
            assertThat(response.getState()).isEqualTo(STATE);
            assertThat(response.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(response.getAuthorizationCode()).isNull();
            assertThat(response.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should build error response with error description")
        void shouldBuildErrorResponseWithErrorDescription() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .error(ERROR)
                    .errorDescription(ERROR_DESCRIPTION)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getError()).isEqualTo(ERROR);
            assertThat(response.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
            assertThat(response.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should build error response with error URI")
        void shouldBuildErrorResponseWithErrorUri() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .error(ERROR)
                    .errorDescription(ERROR_DESCRIPTION)
                    .errorUri(ERROR_URI)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getError()).isEqualTo(ERROR);
            assertThat(response.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
            assertThat(response.getErrorUri()).isEqualTo(ERROR_URI);
            assertThat(response.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should support method chaining for error response")
        void shouldSupportMethodChainingForErrorResponse() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .error(ERROR)
                    .errorDescription(ERROR_DESCRIPTION)
                    .errorUri(ERROR_URI)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getError()).isEqualTo(ERROR);
            assertThat(response.getErrorDescription()).isEqualTo(ERROR_DESCRIPTION);
            assertThat(response.getErrorUri()).isEqualTo(ERROR_URI);
            assertThat(response.getState()).isEqualTo(STATE);
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should throw exception when neither code nor error is set")
        void shouldThrowExceptionWhenNeitherCodeNorErrorIsSet() {
            // When & Then
            assertThatThrownBy(() -> AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .state(STATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Either authorization code or error is required");
        }

        @Test
        @DisplayName("Should throw exception when both code and error are set")
        void shouldThrowExceptionWhenBothCodeAndErrorAreSet() {
            // When & Then
            assertThatThrownBy(() -> AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .authorizationCode(AUTHORIZATION_CODE)
                    .error(ERROR)
                    .state(STATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Cannot have both authorization code and error");
        }

        @Test
        @DisplayName("Should allow null redirect URI")
        void shouldAllowNullRedirectUri() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .authorizationCode(AUTHORIZATION_CODE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getRedirectUri()).isNull();
        }

        @Test
        @DisplayName("Should allow null state")
        void shouldAllowNullState() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .authorizationCode(AUTHORIZATION_CODE)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getState()).isNull();
        }

        @Test
        @DisplayName("Should allow null error description")
        void shouldAllowNullErrorDescription() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .error(ERROR)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getErrorDescription()).isNull();
        }

        @Test
        @DisplayName("Should allow null error URI")
        void shouldAllowNullErrorUri() {
            // When
            AuthorizationResponse response = AuthorizationResponse.builder()
                    .error(ERROR)
                    .build();

            // Then
            assertThat(response).isNotNull();
            assertThat(response.getErrorUri()).isNull();
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            AuthorizationResponse.Builder builder = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .authorizationCode(AUTHORIZATION_CODE)
                    .state(STATE);

            // When
            AuthorizationResponse response1 = builder.build();
            builder.authorizationCode("different_code");
            AuthorizationResponse response2 = builder.build();

            // Then
            assertThat(response1.getAuthorizationCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(response2.getAuthorizationCode()).isEqualTo("different_code");
        }

        @Test
        @DisplayName("Should return correct success status")
        void shouldReturnCorrectSuccessStatus() {
            // Given
            AuthorizationResponse successResponse = AuthorizationResponse.builder()
                    .authorizationCode(AUTHORIZATION_CODE)
                    .build();

            AuthorizationResponse errorResponse = AuthorizationResponse.builder()
                    .error(ERROR)
                    .build();

            // Then
            assertThat(successResponse.isSuccess()).isTrue();
            assertThat(errorResponse.isSuccess()).isFalse();
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            AuthorizationResponse response1 = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .authorizationCode(AUTHORIZATION_CODE)
                    .state(STATE)
                    .build();

            AuthorizationResponse response2 = AuthorizationResponse.builder()
                    .redirectUri(REDIRECT_URI)
                    .authorizationCode(AUTHORIZATION_CODE)
                    .state(STATE)
                    .build();

            // Then
            assertThat(response1).isEqualTo(response2);
            assertThat(response1.hashCode()).isEqualTo(response2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when fields differ")
        void shouldNotBeEqualWhenFieldsDiffer() {
            // Given
            AuthorizationResponse response1 = AuthorizationResponse.builder()
                    .authorizationCode(AUTHORIZATION_CODE)
                    .build();

            AuthorizationResponse response2 = AuthorizationResponse.builder()
                    .authorizationCode("different_code")
                    .build();

            // Then
            assertThat(response1).isNotEqualTo(response2);
        }
    }
}
