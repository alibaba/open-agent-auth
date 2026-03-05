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
package com.alibaba.openagentauth.framework.web.callback;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link OAuth2CallbackResult}.
 */
@DisplayName("OAuth2CallbackResult Tests")
class OAuth2CallbackResultTest {

    private static final String REDIRECT_URL = "https://example.com/callback?code=auth123";

    @Nested
    @DisplayName("redirect()")
    class Redirect {

        @Test
        @DisplayName("Should create successful redirect result")
        void shouldCreateSuccessfulRedirectResult() {
            // Act
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo(REDIRECT_URL);
            assertThat(result.getErrorResponse()).isNull();
            assertThat(result.getStatusCode()).isEqualTo(302);
        }

        @Test
        @DisplayName("Should create redirect result with empty URL")
        void shouldCreateRedirectResultWithEmptyUrl() {
            // Act
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect("");

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo("");
            assertThat(result.getStatusCode()).isEqualTo(302);
        }
    }

    @Nested
    @DisplayName("error()")
    class Error {

        @Test
        @DisplayName("Should create error result")
        void shouldCreateErrorResult() {
            // Arrange
            Map<String, String> errorResponse = Map.of(
                    "error", "access_denied",
                    "error_description", "User denied access"
            );

            // Act
            OAuth2CallbackResult result = OAuth2CallbackResult.error(400, errorResponse);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getRedirectUrl()).isNull();
            assertThat(result.getErrorResponse()).isEqualTo(errorResponse);
            assertThat(result.getStatusCode()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should create error result with empty error response")
        void shouldCreateErrorResultWithEmptyErrorResponse() {
            // Arrange
            Map<String, String> errorResponse = Map.of();

            // Act
            OAuth2CallbackResult result = OAuth2CallbackResult.error(500, errorResponse);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getRedirectUrl()).isNull();
            assertThat(result.getErrorResponse()).isEqualTo(errorResponse);
            assertThat(result.getStatusCode()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should create error result with null error response")
        void shouldCreateErrorResultWithNullErrorResponse() {
            // Act
            OAuth2CallbackResult result = OAuth2CallbackResult.error(500, null);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getRedirectUrl()).isNull();
            assertThat(result.getErrorResponse()).isNull();
            assertThat(result.getStatusCode()).isEqualTo(500);
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return success status")
        void shouldReturnSuccessStatus() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should return error status")
        void shouldReturnErrorStatus() {
            // Arrange
            Map<String, String> errorResponse = Map.of("error", "access_denied");
            OAuth2CallbackResult result = OAuth2CallbackResult.error(400, errorResponse);

            // Act & Assert
            assertThat(result.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should return redirect URL for success result")
        void shouldReturnRedirectUrlForSuccessResult() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result.getRedirectUrl()).isEqualTo(REDIRECT_URL);
        }

        @Test
        @DisplayName("Should return null redirect URL for error result")
        void shouldReturnNullRedirectUrlForErrorResult() {
            // Arrange
            Map<String, String> errorResponse = Map.of("error", "access_denied");
            OAuth2CallbackResult result = OAuth2CallbackResult.error(400, errorResponse);

            // Act & Assert
            assertThat(result.getRedirectUrl()).isNull();
        }

        @Test
        @DisplayName("Should return error response for error result")
        void shouldReturnErrorResponseForErrorResult() {
            // Arrange
            Map<String, String> errorResponse = Map.of("error", "access_denied");
            OAuth2CallbackResult result = OAuth2CallbackResult.error(400, errorResponse);

            // Act & Assert
            assertThat(result.getErrorResponse()).isEqualTo(errorResponse);
        }

        @Test
        @DisplayName("Should return null error response for success result")
        void shouldReturnNullErrorResponseForSuccessResult() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result.getErrorResponse()).isNull();
        }

        @Test
        @DisplayName("Should return status code for success result")
        void shouldReturnStatusCodeForSuccessResult() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result.getStatusCode()).isEqualTo(302);
        }

        @Test
        @DisplayName("Should return status code for error result")
        void shouldReturnStatusCodeForErrorResult() {
            // Arrange
            Map<String, String> errorResponse = Map.of("error", "access_denied");
            OAuth2CallbackResult result = OAuth2CallbackResult.error(401, errorResponse);

            // Act & Assert
            assertThat(result.getStatusCode()).isEqualTo(401);
        }
    }

    @Nested
    @DisplayName("equals() and hashCode()")
    class EqualsAndHashCode {

        @Test
        @DisplayName("Should be equal when all fields match using recursive comparison")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Arrange
            OAuth2CallbackResult result1 = OAuth2CallbackResult.redirect(REDIRECT_URL);
            OAuth2CallbackResult result2 = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result1).usingRecursiveComparison().isEqualTo(result2);
        }

        @Test
        @DisplayName("Should not be equal when URLs differ")
        void shouldNotBeEqualWhenUrlsDiffer() {
            // Arrange
            OAuth2CallbackResult result1 = OAuth2CallbackResult.redirect(REDIRECT_URL);
            OAuth2CallbackResult result2 = OAuth2CallbackResult.redirect("https://other.com/callback");

            // Act & Assert
            assertThat(result1).usingRecursiveComparison().isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should not be equal when success status differs")
        void shouldNotBeEqualWhenSuccessStatusDiffers() {
            // Arrange
            OAuth2CallbackResult result1 = OAuth2CallbackResult.redirect(REDIRECT_URL);
            Map<String, String> errorResponse = Map.of("error", "access_denied");
            OAuth2CallbackResult result2 = OAuth2CallbackResult.error(400, errorResponse);

            // Act & Assert
            assertThat(result1).usingRecursiveComparison().isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result).isEqualTo(result);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Arrange
            OAuth2CallbackResult result = OAuth2CallbackResult.redirect(REDIRECT_URL);

            // Act & Assert
            assertThat(result).isNotEqualTo("string");
        }
    }
}
