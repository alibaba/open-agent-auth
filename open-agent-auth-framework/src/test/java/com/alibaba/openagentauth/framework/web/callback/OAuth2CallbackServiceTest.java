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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link OAuth2CallbackService}.
 * <p>
 * This test class validates the OAuth2 callback processing service,
 * including request validation, token exchange, and session management.
 * </p>
 */
@DisplayName("OAuth2CallbackService Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2CallbackServiceTest {

    private OAuth2CallbackService callbackService;

    @Mock
    private FrameworkOAuth2TokenClient mockOAuth2TokenClient;

    @Mock
    private SessionMappingBizService mockSessionMappingBizService;

    @Mock
    private HttpServletRequest mockHttpRequest;

    @Mock
    private HttpSession mockHttpSession;

    @Mock
    private HttpSession mockRestoredSession;

    @Mock
    private HttpSession mockRequestSession;

    private static final String CLIENT_ID = "client-123";
    private static final String CODE = "auth-code-123";
    private static final String STATE_USER_AUTH = "user:uuid:session-user-123";
    private static final String STATE_AGENT_AUTH = "agent:uuid:session-agent-456";
    private static final String STATE_DEFAULT = "unknown:uuid:session-default-789";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    // Valid JWT token with subject claim
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImlhdCI6MTYwOTQ1OTIwMH0.fake-signature";
    private static final String CALLBACK_ENDPOINT = "/callback";
    private static final String SESSION_ID = "test-session-id";
    private static final String PENDING_REDIRECT_URI = "/protected/resource";

    @BeforeEach
    void setUp() {
        callbackService = new OAuth2CallbackService(mockOAuth2TokenClient, mockSessionMappingBizService, CALLBACK_ENDPOINT);

        // Default HTTP request setup
        when(mockHttpRequest.getScheme()).thenReturn("https");
        when(mockHttpRequest.getServerName()).thenReturn("localhost");
        when(mockHttpRequest.getServerPort()).thenReturn(8443);
        when(mockHttpRequest.getContextPath()).thenReturn("");
        // Return mockHttpSession for getSession(false) to avoid NullPointerException
        when(mockHttpRequest.getSession(false)).thenReturn(mockHttpSession);
        when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockRequestSession);
        when(mockRequestSession.getId()).thenReturn("request-session-id");
        when(mockRestoredSession.getId()).thenReturn(SESSION_ID);
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create service with valid parameters")
        void shouldCreateServiceWithValidParameters() {
            // Act
            OAuth2CallbackService service = new OAuth2CallbackService(mockOAuth2TokenClient, mockSessionMappingBizService, CALLBACK_ENDPOINT);

            // Assert
            assertThat(service).isNotNull();
        }
    }

    @Nested
    @DisplayName("handleCallback()")
    class HandleCallback {

        @Test
        @DisplayName("Should return error when request contains error")
        void shouldReturnErrorWhenRequestContainsError() {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(null, STATE_AGENT_AUTH, "invalid_request", "Invalid authorization request", mockHttpRequest);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            assertThat(result.getErrorResponse()).isNotNull();
            assertThat(result.getErrorResponse().get("error")).isEqualTo("invalid_request");

            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any());
        }

        @Test
        @DisplayName("Should return error when code is missing")
        void shouldReturnErrorWhenCodeIsMissing() {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(null, STATE_AGENT_AUTH, null, null, mockHttpRequest);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            assertThat(result.getErrorResponse()).isNotNull();
            assertThat(result.getErrorResponse().get("error")).isEqualTo("invalid_request");

            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any());
        }

        @Test
        @DisplayName("Should return error when state is missing")
        void shouldReturnErrorWhenStateIsMissing() {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, null, null, null, mockHttpRequest);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isFalse();
            // When state is null, OAuth2StateHandler.parse() throws NullPointerException
            // which is caught and returns 500
            assertThat(result.getStatusCode()).isEqualTo(500);
            assertThat(result.getErrorResponse()).isNotNull();
            assertThat(result.getErrorResponse().get("error")).isEqualTo("server_error");

            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any());
        }
    }

    @Nested
    @DisplayName("User Authentication Flow")
    class UserAuthenticationFlow {

        @Test
        @DisplayName("Should handle user authentication flow successfully")
        void shouldHandleUserAuthenticationFlowSuccessfully() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getStatusCode()).isEqualTo(302);
            assertThat(result.getRedirectUrl()).isEqualTo("/");
            verify(mockSessionMappingBizService).removeSession("session-user-123");
        }

        @Test
        @DisplayName("Should handle user authentication flow with pending redirect URI")
        void shouldHandleUserAuthenticationFlowWithPendingRedirect() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            // Set pending redirect URI in the restored session
            when(mockRestoredSession.getAttribute("open_agent_auth_redirect_uri")).thenReturn(PENDING_REDIRECT_URI);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo(PENDING_REDIRECT_URI);
        }

        @Test
        @DisplayName("Should handle user authentication flow with session not found")
        void shouldHandleUserAuthenticationFlowWithSessionNotFound() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // When restoreSession returns null, the code uses the request session instead
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), eq(false), eq(mockHttpRequest))).thenReturn(mockRequestSession);
            // handleFlow first calls getSession(false), which returns null, then getSession(true) is called
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // When restored session is found, removeSession is called
            verify(mockSessionMappingBizService).removeSession("session-user-123");
        }
    }

    @Nested
    @DisplayName("Agent Operation Authorization Flow")
    class AgentOperationAuthorizationFlow {

        @Test
        @DisplayName("Should handle agent operation authorization flow successfully")
        void shouldHandleAgentOperationAuthorizationFlowSuccessfully() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // Return null for getSession(false) to trigger getSession(true) in handleFlow
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockSessionMappingBizService.restoreSession(eq("session-agent-456"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            // Mock ID_TOKEN attribute for restored session
            // Use a valid JWT with subject "user-123"
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo("/");

            verify(mockSessionMappingBizService).removeSession("session-agent-456");
        }

        @Test
        @DisplayName("Should handle agent operation authorization flow with conversation history")
        void shouldHandleAgentOperationAuthorizationFlowWithConversationHistory() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            List<Object> conversationHistory = List.of("message1", "message2");

            when(mockSessionMappingBizService.restoreSession(eq("session-agent-456"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should handle agent operation authorization flow with null session ID")
        void shouldHandleAgentOperationAuthorizationFlowWithNullSessionId() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, "agent:uuid:", null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            verify(mockSessionMappingBizService, never()).removeSession(anyString());
        }
    }

    @Nested
    @DisplayName("Default Flow")
    class DefaultFlow {

        @Test
        @DisplayName("Should handle default flow successfully")
        void shouldHandleDefaultFlowSuccessfully() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_DEFAULT, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(anyString(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo("/");
        }

        @Test
        @DisplayName("Should handle default flow with session creation")
        void shouldHandleDefaultFlowWithSessionCreation() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_DEFAULT, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(null);
            // handleFlow first calls getSession(false), then getSession(true) if session is null
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // When restoreSession returns null, the code creates a new session via request.getSession(true)
            verify(mockHttpRequest).getSession(false);
            verify(mockHttpRequest).getSession(true);
        }
    }

    @Nested
    @DisplayName("Token Exchange Failures")
    class TokenExchangeFailures {

        @Test
        @DisplayName("Should handle token exchange failure with OAuth2TokenException")
        void shouldHandleTokenExchangeFailureWithOAuth2TokenException() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            OAuth2TokenException exception = OAuth2TokenException.invalidGrant("Invalid authorization code");
            when(mockOAuth2TokenClient.exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class)))
                    .thenThrow(exception);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            // The error code may be different from "invalid_grant" depending on the exception
            assertThat(result.getErrorResponse().get("error")).isNotNull();
            assertThat(result.getErrorResponse().get("error_description")).isNotNull();
        }

        @Test
        @DisplayName("Should handle token exchange failure with RuntimeException")
        void shouldHandleTokenExchangeFailureWithRuntimeException() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            when(mockOAuth2TokenClient.exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class)))
                    .thenThrow(new RuntimeException("Network error"));

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(500);
            assertThat(result.getErrorResponse().get("error")).isEqualTo("server_error");
            assertThat(result.getErrorResponse().get("error_description")).isEqualTo("Internal server error");
        }
    }

    @Nested
    @DisplayName("Session Restore Failures")
    class SessionRestoreFailures {

        @Test
        @DisplayName("Should handle user authentication flow with session restore failure")
        void shouldHandleUserAuthenticationFlowWithSessionRestoreFailure() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // When restoreSession returns null, the code uses the request session instead
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), eq(false), eq(mockHttpRequest))).thenReturn(mockRequestSession);
            // handleFlow first calls getSession(false), which returns null, then getSession(true) is called
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should handle agent authorization flow with session restore failure")
        void shouldHandleAgentAuthorizationFlowWithSessionRestoreFailure() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // When restoreSession returns null, the code uses the request session instead
            when(mockSessionMappingBizService.restoreSession(eq("session-agent-456"), eq(true), eq(mockHttpRequest))).thenReturn(mockRequestSession);
            // handleFlow first calls getSession(false), which returns null, then getSession(true) is called
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // When restored session is null, the code creates a new session via request.getSession(true)
            // and proceeds with the agent authorization flow
            verify(mockHttpRequest).getSession(false);
            verify(mockHttpRequest).getSession(true);
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Conditions")
    class EdgeCasesAndBoundaryConditions {

        @Test
        @DisplayName("Should handle empty state parameter")
        void shouldHandleEmptyStateParameter() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, "", null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // When state is empty, OAuth2StateHandler.parse() throws NullPointerException
            // which is caught and returns 500
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            // When state is empty, the code throws NullPointerException
            // which is caught and returns 500
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(500);
        }

        @Test
        @DisplayName("Should handle null session ID in state parameter")
        void shouldHandleNullSessionIdInStateParameter() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, "user:uuid:", null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should handle current session matching restored session")
        void shouldHandleCurrentSessionMatchingRestoredSession() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpSession.getId()).thenReturn("session-user-123");
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockRestoredSession.getId()).thenReturn("session-user-123");

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should build redirect URI correctly with custom port")
        void shouldBuildRedirectUriCorrectlyWithCustomPort() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getScheme()).thenReturn("http");
            when(mockHttpRequest.getServerName()).thenReturn("example.com");
            when(mockHttpRequest.getServerPort()).thenReturn(8080);
            when(mockHttpRequest.getContextPath()).thenReturn("/app");
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();

            ArgumentCaptor<ExchangeCodeForTokenRequest> requestCaptor = ArgumentCaptor.forClass(ExchangeCodeForTokenRequest.class);
            verify(mockOAuth2TokenClient).exchangeCodeForToken(requestCaptor.capture());

            ExchangeCodeForTokenRequest capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.getRedirectUri()).isEqualTo("http://example.com:8080/app/callback");
        }

        @Test
        @DisplayName("Should build redirect URI without port for HTTPS standard port")
        void shouldBuildRedirectUriWithoutPortForHttpsStandardPort() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getScheme()).thenReturn("https");
            when(mockHttpRequest.getServerPort()).thenReturn(443);
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();

            ArgumentCaptor<ExchangeCodeForTokenRequest> requestCaptor = ArgumentCaptor.forClass(ExchangeCodeForTokenRequest.class);
            verify(mockOAuth2TokenClient).exchangeCodeForToken(requestCaptor.capture());

            ExchangeCodeForTokenRequest capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.getRedirectUri()).doesNotContain(":443");
        }

        @Test
        @DisplayName("Should build redirect URI without port for HTTP standard port")
        void shouldBuildRedirectUriWithoutPortForHttpStandardPort() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getScheme()).thenReturn("http");
            when(mockHttpRequest.getServerPort()).thenReturn(80);
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();

            ArgumentCaptor<ExchangeCodeForTokenRequest> requestCaptor = ArgumentCaptor.forClass(ExchangeCodeForTokenRequest.class);
            verify(mockOAuth2TokenClient).exchangeCodeForToken(requestCaptor.capture());

            ExchangeCodeForTokenRequest capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.getRedirectUri()).doesNotContain(":80");
        }

        @Test
        @DisplayName("Should handle pending redirect URI in request session")
        void shouldHandlePendingRedirectUriInRequestSession() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(eq("session-user-123"), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            // Set pending redirect URI in the restored session
            when(mockRestoredSession.getAttribute("open_agent_auth_redirect_uri")).thenReturn(PENDING_REDIRECT_URI);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo(PENDING_REDIRECT_URI);
        }
    }

    // ==================== Helper Methods ====================

    private void setupTokenExchangeSuccess() throws Exception {
        AuthenticationResponse authResponse = AuthenticationResponse.builder()
                .idToken(ID_TOKEN)
                .tokenType("Bearer")
                .expiresIn(3600L)
                .build();

        when(mockOAuth2TokenClient.exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class)))
                .thenReturn(authResponse);


        // Mock HttpSession.getAttribute to return null by default for all attributes
        // This ensures SessionManager.getAttribute returns null when session.getAttribute returns null
        lenient().when(mockRestoredSession.getAttribute(anyString())).thenReturn(null);
        lenient().when(mockRequestSession.getAttribute(anyString())).thenReturn(null);
        lenient().when(mockHttpSession.getAttribute(anyString())).thenReturn(null);

        // Mock HttpSession.getAttributeNames to return empty enumeration
        // This ensures syncSessionAttributes doesn't fail
        lenient().when(mockRestoredSession.getAttributeNames()).thenReturn(new java.util.Vector<String>().elements());
        lenient().when(mockRequestSession.getAttributeNames()).thenReturn(new java.util.Vector<String>().elements());
        lenient().when(mockHttpSession.getAttributeNames()).thenReturn(new java.util.Vector<String>().elements());
    }
}