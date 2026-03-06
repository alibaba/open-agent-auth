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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2ErrorCode;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2Exception;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.spring.web.model.OAuth2ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("OAuth2ExceptionHandler Unit Tests")
class OAuth2ExceptionHandlerTest {

    private OAuth2ExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new OAuth2ExceptionHandler();
    }

    @Nested
    @DisplayName("handleOAuth2Exception Method")
    class HandleOAuth2ExceptionTests {

        @Test
        @DisplayName("Should handle DcrException and return correct response")
        void shouldHandleDcrException() {
            DcrException exception = DcrException.invalidRedirectUri("Invalid redirect URI");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isEqualTo("invalid_redirect_uri");
            assertThat(response.getBody().getErrorDescription()).contains("Invalid redirect URI");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should handle DcrException with 401 status")
        void shouldHandleDcrExceptionWith401Status() {
            DcrException exception = DcrException.invalidClientId("Invalid client ID");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody().getError()).isEqualTo("invalid_client");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should handle DcrException with 403 status")
        void shouldHandleDcrExceptionWith403Status() {
            DcrException exception = DcrException.unapprovedClient("Client not approved");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(response.getBody().getError()).isEqualTo("unauthorized_client");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Should handle ParException with missing parameter")
        void shouldHandleParExceptionWithMissingParameter() {
            ParException exception = ParException.missingParameter("client_id");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody().getError()).isEqualTo("invalid_request");
            assertThat(response.getBody().getErrorDescription()).contains("Missing required parameter");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should handle ParException with authentication failed")
        void shouldHandleParExceptionWithAuthenticationFailed() {
            ParException exception = ParException.authenticationFailed("Invalid credentials");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody().getError()).isEqualTo("invalid_client");
            assertThat(response.getBody().getErrorDescription()).contains("Client authentication failed");
        }

        @Test
        @DisplayName("Should handle generic OAuth2Exception without RFC error code")
        void shouldHandleGenericOAuth2Exception() {
            OAuth2Exception exception = new OAuth2Exception(OAuth2ErrorCode.DCR_ERROR, "Generic error") {
            };

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody().getError()).isEqualTo("server_error");
            assertThat(response.getBody().getErrorDescription()).contains("Generic error");
        }

        @Test
        @DisplayName("Should handle OAuth2Exception with custom RFC error code")
        void shouldHandleOAuth2ExceptionWithCustomRfcErrorCode() {
            OAuth2Exception exception = new OAuth2Exception(
                    OAuth2RfcErrorCode.INVALID_SCOPE, OAuth2ErrorCode.DCR_ERROR, "Invalid scope"
            ) {
            };

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getError()).isEqualTo("invalid_scope");
            assertThat(response.getBody().getErrorDescription()).contains("Invalid scope");
        }
    }

    @Nested
    @DisplayName("handleFrameworkOAuth2TokenException Method")
    class HandleFrameworkOAuth2TokenExceptionTests {

        @Test
        @DisplayName("Should handle FrameworkOAuth2TokenException with invalid_request")
        void shouldHandleFrameworkExceptionWithInvalidRequest() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidRequest("Missing parameter");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isEqualTo("invalid_request");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Missing parameter");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should handle FrameworkOAuth2TokenException with invalid_client (401)")
        void shouldHandleFrameworkExceptionWithInvalidClient() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidClient("Invalid credentials");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody().getError()).isEqualTo("invalid_client");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Invalid credentials");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(401);
        }

        @Test
        @DisplayName("Should handle FrameworkOAuth2TokenException with invalid_grant")
        void shouldHandleFrameworkExceptionWithInvalidGrant() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidGrant("Expired token");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getError()).isEqualTo("invalid_grant");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Expired token");
        }

        @Test
        @DisplayName("Should handle FrameworkOAuth2TokenException with invalid_scope")
        void shouldHandleFrameworkExceptionWithInvalidScope() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidScope("Invalid scope");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getError()).isEqualTo("invalid_scope");
        }

        @Test
        @DisplayName("Should handle FrameworkOAuth2TokenException with unauthorized_client (403)")
        void shouldHandleFrameworkExceptionWithUnauthorizedClient() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.unauthorizedClient("Not authorized");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(response.getBody().getError()).isEqualTo("unauthorized_client");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(403);
        }

        @Test
        @DisplayName("Should handle FrameworkOAuth2TokenException with custom error code")
        void shouldHandleFrameworkExceptionWithCustomErrorCode() {
            FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                    "custom_error", "Custom error message"
            );

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getError()).isEqualTo("custom_error");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Custom error message");
        }
    }

    @Nested
    @DisplayName("handleIllegalArgumentException Method")
    class HandleIllegalArgumentExceptionTests {

        @Test
        @DisplayName("Should handle IllegalArgumentException and return invalid_request error")
        void shouldHandleIllegalArgumentException() {
            IllegalArgumentException exception = new IllegalArgumentException("Invalid parameter value");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleIllegalArgumentException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isEqualTo("invalid_request");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Invalid parameter value");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should handle IllegalArgumentException with null message")
        void shouldHandleIllegalArgumentExceptionWithNullMessage() {
            IllegalArgumentException exception = new IllegalArgumentException();

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleIllegalArgumentException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getError()).isEqualTo("invalid_request");
            assertThat(response.getBody().getErrorDescription()).isNull();
        }

        @Test
        @DisplayName("Should handle IllegalArgumentException with empty message")
        void shouldHandleIllegalArgumentExceptionWithEmptyMessage() {
            IllegalArgumentException exception = new IllegalArgumentException("");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleIllegalArgumentException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody().getError()).isEqualTo("invalid_request");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("");
        }
    }

    @Nested
    @DisplayName("handleUnexpectedException Method")
    class HandleUnexpectedExceptionTests {

        @Test
        @DisplayName("Should handle unexpected exception and return server_error")
        void shouldHandleUnexpectedException() {
            Exception exception = new RuntimeException("Unexpected error occurred");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleUnexpectedException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isEqualTo("server_error");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Internal server error");
            assertThat(response.getBody().getHttpStatus()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should handle NullPointerException as server_error")
        void shouldHandleNullPointerException() {
            NullPointerException exception = new NullPointerException("Null pointer");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleUnexpectedException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody().getError()).isEqualTo("server_error");
            assertThat(response.getBody().getErrorDescription()).isEqualTo("Internal server error");
        }

        @Test
        @DisplayName("Should handle custom exception as server_error")
        void shouldHandleCustomException() {
            class CustomException extends Exception {
                public CustomException(String message) {
                    super(message);
                }
            }
            CustomException exception = new CustomException("Custom error");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleUnexpectedException(exception);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody().getError()).isEqualTo("server_error");
        }
    }

    @Nested
    @DisplayName("Response Entity Validation")
    class ResponseEntityValidationTests {

        @Test
        @DisplayName("Should return ResponseEntity with correct structure for OAuth2Exception")
        void shouldReturnCorrectResponseEntityStructureForOAuth2Exception() {
            DcrException exception = DcrException.invalidRedirectUri("Test error");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleOAuth2Exception(exception);

            assertThat(response).isNotNull();
            assertThat(response.getStatusCode()).isNotNull();
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isNotBlank();
            assertThat(response.getHeaders()).isNotNull();
        }

        @Test
        @DisplayName("Should return ResponseEntity with correct structure for FrameworkException")
        void shouldReturnCorrectResponseEntityStructureForFrameworkException() {
            FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidRequest("Test error");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleFrameworkOAuth2TokenException(exception);

            assertThat(response).isNotNull();
            assertThat(response.getStatusCode()).isNotNull();
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isNotBlank();
        }

        @Test
        @DisplayName("Should return ResponseEntity with correct structure for IllegalArgumentException")
        void shouldReturnCorrectResponseEntityStructureForIllegalArgumentException() {
            IllegalArgumentException exception = new IllegalArgumentException("Test error");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleIllegalArgumentException(exception);

            assertThat(response).isNotNull();
            assertThat(response.getStatusCode()).isNotNull();
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isNotBlank();
        }

        @Test
        @DisplayName("Should return ResponseEntity with correct structure for unexpected exception")
        void shouldReturnCorrectResponseEntityStructureForUnexpectedException() {
            Exception exception = new Exception("Test error");

            ResponseEntity<OAuth2ErrorResponse> response = handler.handleUnexpectedException(exception);

            assertThat(response).isNotNull();
            assertThat(response.getStatusCode()).isNotNull();
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isNotBlank();
        }
    }
}
