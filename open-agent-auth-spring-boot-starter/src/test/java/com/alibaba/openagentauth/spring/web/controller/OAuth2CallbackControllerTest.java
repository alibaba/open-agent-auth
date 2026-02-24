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

import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackRequest;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackResult;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2CallbackController}.
 * <p>
 * This test class verifies the OAuth 2.0 callback endpoint functionality,
 * including successful callback handling and error scenarios.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2CallbackController Tests")
class OAuth2CallbackControllerTest {

    private static final String CODE = "authorization_code_123";
    private static final String STATE = "state_abc123";
    private static final String ERROR = "access_denied";
    private static final String ERROR_DESCRIPTION = "User denied access";
    private static final String CLIENT_ID = "test-client-id";
    private static final String REDIRECT_URL = "https://example.com/callback";

    @Mock
    private OAuth2CallbackService callbackService;

    @Mock
    private OpenAgentAuthProperties properties;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private OAuth2CallbackController controller;

    @BeforeEach
    void setUp() {
        lenient().when(request.getRequestURI()).thenReturn("/callback");
        // Update to use new architecture: capabilities.oauth2Client.callback
        lenient().when(properties.getCapabilities()).thenReturn(new CapabilitiesProperties());
        properties.getCapabilities().setOAuth2Client(new OAuth2ClientProperties());
        properties.getCapabilities().getOAuth2Client().setClientId(CLIENT_ID);
        properties.getCapabilities().getOAuth2Client().setCallback(new OAuth2ClientProperties.OAuth2ClientCallbackProperties());
    }

    @Nested
    @DisplayName("GET /callback - Success Scenarios")
    class SuccessScenarios {

        @Test
        @DisplayName("Should handle successful callback with authorization code")
        void shouldHandleSuccessfulCallbackWithAuthorizationCode() {
            // Arrange
            OAuth2CallbackRequest callbackRequest = new OAuth2CallbackRequest(CODE, STATE, null, null, request);
            OAuth2CallbackResult successResult = OAuth2CallbackResult.redirect(REDIRECT_URL);
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(successResult);

            // Act
            Object response = controller.callback(CODE, STATE, null, null, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(responseEntity.getHeaders().getLocation()).isNotNull();
            assertThat(responseEntity.getHeaders().getLocation().toString()).isEqualTo(REDIRECT_URL);
        }

        @Test
        @DisplayName("Should handle callback with all parameters")
        void shouldHandleCallbackWithAllParameters() {
            // Arrange
            OAuth2CallbackRequest callbackRequest = new OAuth2CallbackRequest(CODE, STATE, null, null, request);
            OAuth2CallbackResult successResult = OAuth2CallbackResult.redirect(REDIRECT_URL);
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(successResult);

            // Act
            Object response = controller.callback(CODE, STATE, null, null, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        }
    }

    @Nested
    @DisplayName("Error Scenarios")
    class ErrorScenarios {

        @Test
        @DisplayName("Should handle callback with error parameter")
        void shouldHandleCallbackWithErrorParameter() {
            // Arrange
            OAuth2CallbackRequest callbackRequest = new OAuth2CallbackRequest(null, STATE, ERROR, ERROR_DESCRIPTION, request);
            OAuth2CallbackResult errorResult = OAuth2CallbackResult.error(
                    400,
                    Map.of("error", ERROR, "error_description", ERROR_DESCRIPTION)
            );
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.callback(null, STATE, ERROR, ERROR_DESCRIPTION, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(responseEntity.getBody()).isInstanceOf(Map.class);
        }

        @Test
        @DisplayName("Should handle callback service error")
        void shouldHandleCallbackServiceError() {
            // Arrange
            OAuth2CallbackRequest callbackRequest = new OAuth2CallbackRequest(CODE, STATE, null, null, request);
            OAuth2CallbackResult errorResult = OAuth2CallbackResult.error(
                    500,
                    Map.of("error", "server_error", "error_description", "Internal server error")
            );
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.callback(CODE, STATE, null, null, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        @Test
        @DisplayName("Should return error when client ID is not configured")
        void shouldReturnErrorWhenClientIdIsNotConfigured() {
            // Arrange
            properties.getCapabilities().getOAuth2Client().setClientId(null);

            // Act
            Object response = controller.callback(CODE, STATE, null, null, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(responseEntity.getBody()).isInstanceOf(Map.class);
            Map<?, ?> body = (Map<?, ?>) responseEntity.getBody();
            assertThat(body.containsKey("error")).isTrue();
            assertThat(body.containsKey("error_description")).isTrue();
        }

        @Test
        @DisplayName("Should return error when client ID is empty")
        void shouldReturnErrorWhenClientIdIsEmpty() {
            // Arrange
            properties.getCapabilities().getOAuth2Client().setClientId("");

            // Act
            Object response = controller.callback(CODE, STATE, null, null, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            Map<?, ?> body = (Map<?, ?>) responseEntity.getBody();
            assertThat(body.containsKey("error")).isTrue();
        }
    }

    @Nested
    @DisplayName("Callback Request Building Tests")
    class CallbackRequestBuildingTests {

        @Test
        @DisplayName("Should build callback request with code and state")
        void shouldBuildCallbackRequestWithCodeAndState() {
            // Arrange
            OAuth2CallbackResult successResult = OAuth2CallbackResult.redirect(REDIRECT_URL);
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(successResult);

            // Act
            controller.callback(CODE, STATE, null, null, request);

            // Assert
            org.mockito.Mockito.verify(callbackService).handleCallback(
                    any(OAuth2CallbackRequest.class),
                    eq(CLIENT_ID)
            );
        }

        @Test
        @DisplayName("Should build callback request with error parameters")
        void shouldBuildCallbackRequestWithErrorParameters() {
            // Arrange
            OAuth2CallbackResult errorResult = OAuth2CallbackResult.error(
                    400,
                    Map.of("error", ERROR)
            );
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(errorResult);

            // Act
            controller.callback(null, STATE, ERROR, ERROR_DESCRIPTION, request);

            // Assert
            org.mockito.Mockito.verify(callbackService).handleCallback(
                    any(OAuth2CallbackRequest.class),
                    eq(CLIENT_ID)
            );
        }
    }

    @Nested
    @DisplayName("Response Conversion Tests")
    class ResponseConversionTests {

        @Test
        @DisplayName("Should convert success result to redirect response")
        void shouldConvertSuccessResultToRedirectResponse() {
            // Arrange
            OAuth2CallbackResult successResult = OAuth2CallbackResult.redirect(REDIRECT_URL);
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(successResult);

            // Act
            Object response = controller.callback(CODE, STATE, null, null, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.FOUND);
            assertThat(responseEntity.getHeaders().getLocation()).isNotNull();
        }

        @Test
        @DisplayName("Should convert error result to error response")
        void shouldConvertErrorResultToErrorResponse() {
            // Arrange
            Map<String, String> errorBody = Map.of("error", ERROR, "error_description", ERROR_DESCRIPTION);
            OAuth2CallbackResult errorResult = OAuth2CallbackResult.error(400, errorBody);
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.callback(null, STATE, ERROR, ERROR_DESCRIPTION, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(responseEntity.getBody()).isEqualTo(errorBody);
        }

        @Test
        @DisplayName("Should handle different HTTP status codes in error result")
        void shouldHandleDifferentHttpStatusCodesInErrorResult() {
            // Arrange
            Map<String, String> errorBody = Map.of("error", "unauthorized", "error_description", "Unauthorized");
            OAuth2CallbackResult errorResult = OAuth2CallbackResult.error(401, errorBody);
            when(callbackService.handleCallback(any(OAuth2CallbackRequest.class), anyString()))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.callback(null, STATE, ERROR, ERROR_DESCRIPTION, request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
    }
}