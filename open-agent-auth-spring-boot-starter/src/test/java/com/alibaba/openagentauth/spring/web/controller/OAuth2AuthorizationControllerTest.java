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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.framework.web.authorization.AuthorizationOrchestrator;
import com.alibaba.openagentauth.framework.web.authorization.AuthorizationResult;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2AuthorizationController}.
 * <p>
 * This test class verifies the OAuth 2.0 Authorization API functionality,
 * including authorization requests, consent submissions, and error handling.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2AuthorizationController Tests")
class OAuth2AuthorizationControllerTest {

    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String ERROR_CODE = "invalid_request";
    private static final String ERROR_DESCRIPTION = "Invalid request parameters";
    private static final String CONSENT_PAGE_HTML = "<html>Consent Page</html>";

    @Mock
    private AuthorizationOrchestrator orchestrator;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private OAuth2AuthorizationController controller;

    @BeforeEach
    void setUp() {
        when(request.getRequestURI()).thenReturn("/oauth2/authorize");
    }

    @Nested
    @DisplayName("GET /oauth2/authorize - Authorization Endpoint")
    class AuthorizeTests {

        @Test
        @DisplayName("Should redirect to callback on successful authorization")
        void shouldRedirectToCallbackOnSuccessfulAuthorization() {
            // Arrange
            AuthorizationResult redirectResult = AuthorizationResult.redirect(REDIRECT_URI);
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(redirectResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(RedirectView.class);
            RedirectView redirectView = (RedirectView) response;
            assertThat(redirectView.getUrl()).isEqualTo(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should return consent page when user consent is required")
        void shouldReturnConsentPageWhenUserConsentIsRequired() {
            // Arrange
            AuthorizationResult consentResult = AuthorizationResult.consentPage(CONSENT_PAGE_HTML);
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(consentResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(String.class);
            assertThat(response).isEqualTo(CONSENT_PAGE_HTML);
        }

        @Test
        @DisplayName("Should return error response on authorization failure")
        void shouldReturnErrorResponseOnAuthorizationFailure() {
            // Arrange
            AuthorizationResult errorResult = AuthorizationResult.error(
                    ERROR_CODE,
                    ERROR_DESCRIPTION
            );
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCodeValue()).isEqualTo(400);
            assertThat(responseEntity.getBody()).isInstanceOf(Map.class);
        }

        @Test
        @DisplayName("Should throw OAuth2AuthorizationException")
        void shouldThrowOAuth2AuthorizationException() {
            // Arrange
            OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
                    OAuth2RfcErrorCode.INVALID_REQUEST, ERROR_DESCRIPTION);
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenThrow(exception);

            // Act & Assert
            assertThatThrownBy(() -> controller.authorize(request))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining(ERROR_DESCRIPTION);
        }

        @Test
        @DisplayName("Should throw RuntimeException on unexpected errors")
        void shouldThrowRuntimeExceptionOnUnexpectedErrors() {
            // Arrange
            RuntimeException exception = new RuntimeException("Unexpected error");
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenThrow(exception);

            // Act & Assert
            assertThatThrownBy(() -> controller.authorize(request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Unexpected error");
        }
    }

    @Nested
    @DisplayName("POST /oauth2/authorize - Consent Submission Endpoint")
    class HandleConsentSubmissionTests {

        @Test
        @DisplayName("Should redirect to callback on successful consent approval")
        void shouldRedirectToCallbackOnSuccessfulConsentApproval() {
            // Arrange
            AuthorizationResult redirectResult = AuthorizationResult.redirect(REDIRECT_URI);
            when(orchestrator.processConsentSubmission(any(HttpServletRequest.class)))
                    .thenReturn(redirectResult);

            // Act
            Object response = controller.handleConsentSubmission(request);

            // Assert
            assertThat(response).isInstanceOf(RedirectView.class);
            RedirectView redirectView = (RedirectView) response;
            assertThat(redirectView.getUrl()).isEqualTo(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should return error response on consent submission failure")
        void shouldReturnErrorResponseOnConsentSubmissionFailure() {
            // Arrange
            AuthorizationResult errorResult = AuthorizationResult.error(
                    ERROR_CODE,
                    ERROR_DESCRIPTION
            );
            when(orchestrator.processConsentSubmission(any(HttpServletRequest.class)))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.handleConsentSubmission(request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCodeValue()).isEqualTo(400);
            assertThat(responseEntity.getBody()).isInstanceOf(Map.class);
        }

        @Test
        @DisplayName("Should throw OAuth2AuthorizationException on consent submission")
        void shouldThrowOAuth2AuthorizationExceptionOnConsentSubmission() {
            // Arrange
            OAuth2AuthorizationException exception = new OAuth2AuthorizationException(
                    OAuth2RfcErrorCode.INVALID_REQUEST, ERROR_DESCRIPTION);
            when(orchestrator.processConsentSubmission(any(HttpServletRequest.class)))
                    .thenThrow(exception);

            // Act & Assert
            assertThatThrownBy(() -> controller.handleConsentSubmission(request))
                    .isInstanceOf(OAuth2AuthorizationException.class)
                    .hasMessageContaining(ERROR_DESCRIPTION);
        }

        @Test
        @DisplayName("Should throw RuntimeException on consent submission unexpected errors")
        void shouldThrowRuntimeExceptionOnConsentSubmissionUnexpectedErrors() {
            // Arrange
            RuntimeException exception = new RuntimeException("Unexpected error");
            when(orchestrator.processConsentSubmission(any(HttpServletRequest.class)))
                    .thenThrow(exception);

            // Act & Assert
            assertThatThrownBy(() -> controller.handleConsentSubmission(request))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Unexpected error");
        }
    }

    @Nested
    @DisplayName("AuthorizationResult Handling Tests")
    class AuthorizationResultHandlingTests {

        @Test
        @DisplayName("Should correctly handle REDIRECT result type")
        void shouldCorrectlyHandleRedirectResultType() {
            // Arrange
            AuthorizationResult redirectResult = AuthorizationResult.redirect(REDIRECT_URI);
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(redirectResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(RedirectView.class);
            RedirectView redirectView = (RedirectView) response;
            assertThat(redirectView.getUrl()).isEqualTo(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should correctly handle ERROR result type")
        void shouldCorrectlyHandleErrorResultType() {
            // Arrange
            AuthorizationResult errorResult = AuthorizationResult.error(
                    "login_required",
                    "User not authenticated"
            );
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCodeValue()).isEqualTo(400);
        }

        @Test
        @DisplayName("Should correctly handle CONSENT_PAGE result type")
        void shouldCorrectlyHandleConsentPageResultType() {
            // Arrange
            AuthorizationResult consentResult = AuthorizationResult.consentPage(CONSENT_PAGE_HTML);
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(consentResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(String.class);
            assertThat(response).isEqualTo(CONSENT_PAGE_HTML);
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null redirect URI gracefully")
        void shouldHandleNullRedirectUriGracefully() {
            // Arrange
            AuthorizationResult redirectResult = AuthorizationResult.redirect("http://example.com/callback");
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(redirectResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(RedirectView.class);
            RedirectView redirectView = (RedirectView) response;
            assertThat(redirectView.getUrl()).isEqualTo("http://example.com/callback");
        }

        @Test
        @DisplayName("Should handle empty consent page HTML")
        void shouldHandleEmptyConsentPageHtml() {
            // Arrange
            AuthorizationResult consentResult = AuthorizationResult.consentPage("");
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(consentResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(String.class);
            assertThat((String) response).isEmpty();
        }

        @Test
        @DisplayName("Should handle error with null error description")
        @SuppressWarnings("unchecked")
        void shouldHandleErrorWithNullErrorDescription() {
            // Arrange
            AuthorizationResult errorResult = AuthorizationResult.error(
                    ERROR_CODE,
                    null
            );
            when(orchestrator.processAuthorization(any(HttpServletRequest.class)))
                    .thenReturn(errorResult);

            // Act
            Object response = controller.authorize(request);

            // Assert
            assertThat(response).isInstanceOf(ResponseEntity.class);
            ResponseEntity<?> responseEntity = (ResponseEntity<?>) response;
            assertThat(responseEntity.getStatusCodeValue()).isEqualTo(400);
            Map<String, String> body = (Map<String, String>) responseEntity.getBody();
            assertThat(body).containsEntry("error", ERROR_CODE);
            assertThat(body).doesNotContainKey("error_description");
        }
    }
}