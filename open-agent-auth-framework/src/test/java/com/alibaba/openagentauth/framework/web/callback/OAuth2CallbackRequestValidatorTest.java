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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2CallbackRequestValidator}.
 */
@DisplayName("OAuth2CallbackRequestValidator Tests")
@ExtendWith(MockitoExtension.class)
class OAuth2CallbackRequestValidatorTest {

    private static final String CLIENT_ID = "test-client-id";

    @Mock
    private OAuth2CallbackRequest mockRequest;

    private OAuth2CallbackRequestValidator validator;

    @BeforeEach
    void setUp() {
        validator = new OAuth2CallbackRequestValidator();
    }

    @Nested
    @DisplayName("validate()")
    class Validate {

        @Test
        @DisplayName("Should validate successful callback with code")
        void shouldValidateSuccessfulCallbackWithCode() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(false);
            when(mockRequest.getCode()).thenReturn("auth-code-123");

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getError()).isNull();
            assertThat(result.getErrorDescription()).isNull();
            assertThat(result.getStatusCode()).isEqualTo(200);
        }

        @Test
        @DisplayName("Should return error when callback has error")
        void shouldReturnErrorWhenCallbackHasError() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(true);
            when(mockRequest.getErrorDescription()).thenReturn("User denied access");

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("User denied access");
            assertThat(result.getStatusCode()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should return error when code is missing")
        void shouldReturnErrorWhenCodeIsMissing() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(false);
            when(mockRequest.getCode()).thenReturn(null);

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("Missing authorization code");
            assertThat(result.getStatusCode()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should return error when code is empty")
        void shouldReturnErrorWhenCodeIsEmpty() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(false);
            when(mockRequest.getCode()).thenReturn("");

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("Missing authorization code");
            assertThat(result.getStatusCode()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should return error when clientId is null")
        void shouldReturnErrorWhenClientIdIsNull() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(false);
            when(mockRequest.getCode()).thenReturn("auth-code-123");

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, null);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("server_error");
            assertThat(result.getErrorDescription()).isEqualTo("Client ID not configured");
            assertThat(result.getStatusCode()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should return error when clientId is empty")
        void shouldReturnErrorWhenClientIdIsEmpty() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(false);
            when(mockRequest.getCode()).thenReturn("auth-code-123");

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, "");

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("server_error");
            assertThat(result.getErrorDescription()).isEqualTo("Client ID not configured");
            assertThat(result.getStatusCode()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should return default error description when error callback has no description")
        void shouldReturnDefaultErrorDescriptionWhenErrorCallbackHasNoDescription() {
            // Arrange
            when(mockRequest.hasError()).thenReturn(true);
            when(mockRequest.getErrorDescription()).thenReturn(null);

            // Act
            OAuth2CallbackRequestValidator.ValidationResult result = validator.validate(mockRequest, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("Authorization failed");
            assertThat(result.getStatusCode()).isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("ValidationResult")
    class ValidationResult {

        @Test
        @DisplayName("Should create successful validation result")
        void shouldCreateSuccessfulValidationResult() {
            // Act
            OAuth2CallbackRequestValidator.ValidationResult result =
                    OAuth2CallbackRequestValidator.ValidationResult.success();

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getError()).isNull();
            assertThat(result.getErrorDescription()).isNull();
            assertThat(result.getStatusCode()).isEqualTo(200);
        }

        @Test
        @DisplayName("Should create error validation result")
        void shouldCreateErrorValidationResult() {
            // Act
            OAuth2CallbackRequestValidator.ValidationResult result =
                    OAuth2CallbackRequestValidator.ValidationResult.error("invalid_request", "Error description", 400);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getError()).isEqualTo("invalid_request");
            assertThat(result.getErrorDescription()).isEqualTo("Error description");
            assertThat(result.getStatusCode()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should convert to error response map")
        void shouldConvertToErrorResponseMap() {
            // Arrange
            OAuth2CallbackRequestValidator.ValidationResult result =
                    OAuth2CallbackRequestValidator.ValidationResult.error("invalid_request", "Error description", 400);

            // Act
            Map<String, String> errorMap = result.toErrorResponseMap();

            // Assert
            assertThat(errorMap).isNotNull();
            assertThat(errorMap).hasSize(2);
            assertThat(errorMap.get("error")).isEqualTo("invalid_request");
            assertThat(errorMap.get("error_description")).isEqualTo("Error description");
        }

        @Test
        @DisplayName("Should return empty map for successful validation result")
        void shouldReturnEmptyMapForSuccessfulValidationResult() {
            // Arrange
            OAuth2CallbackRequestValidator.ValidationResult result =
                    OAuth2CallbackRequestValidator.ValidationResult.success();

            // Act
            Map<String, String> errorMap = result.toErrorResponseMap();

            // Assert
            assertThat(errorMap).isNotNull();
            assertThat(errorMap).isEmpty();
        }

        @Test
        @DisplayName("Should use default description when converting error response map")
        void shouldUseDefaultDescriptionWhenConvertingErrorResponseMap() {
            // Arrange
            OAuth2CallbackRequestValidator.ValidationResult result =
                    OAuth2CallbackRequestValidator.ValidationResult.error("invalid_request", null, 400);

            // Act
            Map<String, String> errorMap = result.toErrorResponseMap();

            // Assert
            assertThat(errorMap).isNotNull();
            assertThat(errorMap).hasSize(2);
            assertThat(errorMap.get("error")).isEqualTo("invalid_request");
            assertThat(errorMap.get("error_description")).isEqualTo("Authorization failed");
        }
    }
}
