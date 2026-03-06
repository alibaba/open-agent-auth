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

import com.alibaba.openagentauth.core.model.oauth2.authorization.OAuth2AuthorizationRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.nimbusds.jose.JOSEException;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.core.model.oauth2.authorization.OAuth2AuthorizationRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
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

import java.time.Instant;
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
    private Agent mockAgent;

    @Mock
    private SessionMappingBizService mockSessionMappingBizService;

    @Mock
    private OAuth2AuthorizationRequestStorage mockAuthorizationRequestStorage;

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
    // Updated state constants to be opaque values instead of "user:uuid" / "agent:uuid" format
    private static final String STATE_USER_AUTH = "opaque-state-user-auth";
    private static final String STATE_AGENT_AUTH = "opaque-state-agent-auth";
    private static final String STATE_DEFAULT = "opaque-state-unknown";
    private static final String REDIRECT_URI = "http://localhost:8080/callback";
    // Valid JWT token with subject claim
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImlhdCI6MTYwOTQ1OTIwMH0.fake-signature";
    private static final String AOAT_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudC1vcC1hdXRoIiwiaWF0IjoxNjA5NDU5MjAwfQ.fake-signature";
    private static final String CALLBACK_ENDPOINT = "/callback";
    private static final String SESSION_ID = "test-session-id";
    private static final String PENDING_REDIRECT_URI = "/protected/resource";

    @BeforeEach
    void setUp() {
        // Mock repository to return appropriate authorization requests for each state
        when(mockAuthorizationRequestStorage.remove(STATE_USER_AUTH))
                .thenReturn(OAuth2AuthorizationRequest.builder()
                        .state(STATE_USER_AUTH)
                        .flowType(OAuth2AuthorizationRequest.FlowType.USER_AUTHENTICATION)
                        .build());
        when(mockAuthorizationRequestStorage.remove(STATE_AGENT_AUTH))
                .thenReturn(OAuth2AuthorizationRequest.builder()
                        .state(STATE_AGENT_AUTH)
                        .flowType(OAuth2AuthorizationRequest.FlowType.AGENT_OPERATION_AUTH)
                        .build());
        when(mockAuthorizationRequestStorage.remove(STATE_DEFAULT))
                .thenReturn(null); // Unknown state returns null

        // Construct callbackService with 5 parameters including mockAuthorizationRequestStorage
        callbackService = new OAuth2CallbackService(
                mockOAuth2TokenClient,
                mockAgent,
                mockSessionMappingBizService,
                mockAuthorizationRequestStorage,
                CALLBACK_ENDPOINT);

        // Default HTTP request setup
        when(mockHttpRequest.getScheme()).thenReturn("https");
        when(mockHttpRequest.getServerName()).thenReturn("localhost");
        when(mockHttpRequest.getServerPort()).thenReturn(8443);
        when(mockHttpRequest.getContextPath()).thenReturn("");
        // Return mockHttpSession for getSession(false) to avoid NullPointerException
        when(mockHttpRequest.getSession(false)).thenReturn(mockHttpSession);
        when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);
        when(mockHttpRequest.getSession(anyBoolean())).thenReturn(mockRequestSession);
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create service with three-parameter constructor (without Agent)")
        void shouldCreateServiceWithThreeParameterConstructor() {
            // Act
            OAuth2CallbackService service = new OAuth2CallbackService(mockOAuth2TokenClient, mockSessionMappingBizService, CALLBACK_ENDPOINT);

            // Assert
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should create service with four-parameter constructor (with Agent)")
        void shouldCreateServiceWithFourParameterConstructor() {
            // Act
            OAuth2CallbackService service = new OAuth2CallbackService(mockOAuth2TokenClient, mockAgent, mockSessionMappingBizService, CALLBACK_ENDPOINT);

            // Assert
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should create service with null Agent via four-parameter constructor")
        void shouldCreateServiceWithNullAgent() {
            // Act
            OAuth2CallbackService service = new OAuth2CallbackService(mockOAuth2TokenClient, null, mockSessionMappingBizService, CALLBACK_ENDPOINT);

            // Assert
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should create service with five-parameter constructor (with Repository)")
        void shouldCreateServiceWithFiveParameterConstructor() {
            // Act
            OAuth2CallbackService service = new OAuth2CallbackService(
                    mockOAuth2TokenClient,
                    mockAgent,
                    mockSessionMappingBizService,
                    mockAuthorizationRequestStorage,
                    CALLBACK_ENDPOINT);

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
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getStatusCode()).isEqualTo(302);
            assertThat(result.getRedirectUrl()).isEqualTo("/");
            // Verify authentication status is set directly on request session
            verify(mockRequestSession).setAttribute(eq("id_token"), eq(ID_TOKEN));
        }

        @Test
        @DisplayName("Should handle user authentication flow with pending redirect URI")
        void shouldHandleUserAuthenticationFlowWithPendingRedirect() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);
            // Set pending redirect URI in the request session
            when(mockRequestSession.getAttribute("open_agent_auth_redirect_uri")).thenReturn(PENDING_REDIRECT_URI);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo(PENDING_REDIRECT_URI);
        }

        @Test
        @DisplayName("Should pass correct parameters to FrameworkOAuth2TokenClient.exchangeCodeForToken")
        void shouldPassCorrectParametersToTokenClient() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            callbackService.handleCallback(request, CLIENT_ID);

            // Assert - verify the ExchangeCodeForTokenRequest passed to token client
            ArgumentCaptor<ExchangeCodeForTokenRequest> requestCaptor = ArgumentCaptor.forClass(ExchangeCodeForTokenRequest.class);
            verify(mockOAuth2TokenClient).exchangeCodeForToken(requestCaptor.capture());

            ExchangeCodeForTokenRequest capturedRequest = requestCaptor.getValue();
            assertThat(capturedRequest.getCode()).isEqualTo(CODE);
            assertThat(capturedRequest.getRedirectUri()).isEqualTo("https://localhost:8443/callback");
            assertThat(capturedRequest.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(capturedRequest.getState()).isEqualTo(STATE_USER_AUTH);
        }

        @Test
        @DisplayName("Should handle user authentication flow with session creation")
        void shouldHandleUserAuthenticationFlowWithSessionCreation() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // handleFlow first calls getSession(false), which returns null, then getSession(true) is called
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // Verify session was created
            verify(mockHttpRequest).getSession(false);
            verify(mockHttpRequest).getSession(true);
            // Verify authentication status is set on request session
            verify(mockRequestSession).setAttribute(eq("id_token"), eq(ID_TOKEN));
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
            setupAgentTokenExchangeSuccess();
            // Return null for getSession(false) to trigger getSession(true) in handleFlow
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            // sessionId is null (state format is "agent:uuid" without sessionId),
            // so restoreOrCreateSession will create a new session via request.getSession(true)
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo("/");

            // sessionId is null after refactoring, so removeSession should NOT be called
            verify(mockSessionMappingBizService, never()).removeSession(any());
            verify(mockAgent).handleAuthorizationCallback(any(AuthorizationResponse.class));
            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class));
        }

        @Test
        @DisplayName("Should handle agent operation authorization flow with conversation history")
        void shouldHandleAgentOperationAuthorizationFlowWithConversationHistory() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            setupAgentTokenExchangeSuccess();
            List<Object> conversationHistory = List.of("message1", "message2");

            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            verify(mockAgent).handleAuthorizationCallback(any(AuthorizationResponse.class));
            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class));
        }

        @Test
        @DisplayName("Should handle agent operation authorization flow with null session ID")
        void shouldHandleAgentOperationAuthorizationFlowWithNullSessionId() throws Exception {
            // Arrange - use a dedicated opaque state and mock repository to return AGENT_OPERATION_AUTH with null sessionId
            String stateWithNullSession = "opaque-state-agent-null-session";
            when(mockAuthorizationRequestStorage.remove(stateWithNullSession))
                    .thenReturn(OAuth2AuthorizationRequest.builder()
                            .state(stateWithNullSession)
                            .flowType(OAuth2AuthorizationRequest.FlowType.AGENT_OPERATION_AUTH)
                            .sessionId(null)
                            .build());
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, stateWithNullSession, null, null, mockHttpRequest);
            setupAgentTokenExchangeSuccess();
            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            verify(mockSessionMappingBizService, never()).removeSession(anyString());
            verify(mockAgent).handleAuthorizationCallback(any(AuthorizationResponse.class));
            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class));
        }

        @Test
        @DisplayName("Should pass correct parameters to Agent.handleAuthorizationCallback")
        void shouldPassCorrectParametersToAgentHandleAuthorizationCallback() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            setupAgentTokenExchangeSuccess();
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            callbackService.handleCallback(request, CLIENT_ID);

            // Assert - verify the AuthorizationResponse passed to Agent
            ArgumentCaptor<AuthorizationResponse> authResponseCaptor = ArgumentCaptor.forClass(AuthorizationResponse.class);
            verify(mockAgent).handleAuthorizationCallback(authResponseCaptor.capture());

            AuthorizationResponse capturedResponse = authResponseCaptor.getValue();
            assertThat(capturedResponse.getAuthorizationCode()).isEqualTo(CODE);
            assertThat(capturedResponse.getRedirectUri()).isEqualTo("https://localhost:8443/callback");
            assertThat(capturedResponse.getState()).isEqualTo(STATE_AGENT_AUTH);
        }

        @Test
        @DisplayName("Should handle AOAT with null expiration time using default value")
        void shouldHandleAoatWithNullExpirationTime() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);

            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            when(aoat.getJwtString()).thenReturn(AOAT_JWT);
            when(aoat.getExpirationTime()).thenReturn(null);

            when(mockAgent.handleAuthorizationCallback(any(AuthorizationResponse.class)))
                    .thenReturn(aoat);

            lenient().when(mockRestoredSession.getAttribute(anyString())).thenReturn(null);
            lenient().when(mockRequestSession.getAttribute(anyString())).thenReturn(null);
            lenient().when(mockHttpSession.getAttribute(anyString())).thenReturn(null);
            lenient().when(mockRestoredSession.getAttributeNames()).thenReturn(new java.util.Vector<String>().elements());
            lenient().when(mockRequestSession.getAttributeNames()).thenReturn(new java.util.Vector<String>().elements());
            lenient().when(mockHttpSession.getAttributeNames()).thenReturn(new java.util.Vector<String>().elements());

            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockSessionMappingBizService.restoreSession(isNull(), anyBoolean(), eq(mockHttpRequest))).thenReturn(mockRestoredSession);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert - should succeed with default expiration
            assertThat(result.isSuccess()).isTrue();
            assertThat(result.getRedirectUrl()).isEqualTo("/");
            verify(mockAgent).handleAuthorizationCallback(any(AuthorizationResponse.class));
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
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

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
            // handleFlow first calls getSession(false), then getSession(true) if session is null
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // When session is null, the code creates a new session via request.getSession(true)
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

        @Test
        @DisplayName("Should return error when Agent is not configured for agent auth flow")
        void shouldReturnErrorWhenAgentNotConfiguredForAgentAuthFlow() {
            // Arrange - use five-parameter constructor with null Agent but with mock repository
            OAuth2CallbackService serviceWithoutAgent = new OAuth2CallbackService(
                    mockOAuth2TokenClient,
                    null,
                    mockSessionMappingBizService,
                    mockAuthorizationRequestStorage,
                    CALLBACK_ENDPOINT);
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);

            // Act
            OAuth2CallbackResult result = serviceWithoutAgent.handleCallback(request, CLIENT_ID);

            // Assert - should fail with OAuth2TokenException (server_error)
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            assertThat(result.getErrorResponse().get("error")).isNotNull();
            assertThat(result.getErrorResponse().get("error_description")).asString()
                    .contains("Agent is not configured");

            // Verify Agent was never called (it's null)
            verify(mockAgent, never()).handleAuthorizationCallback(any(AuthorizationResponse.class));
            // Verify user auth token client was never called (this is agent flow)
            verify(mockOAuth2TokenClient, never()).exchangeCodeForToken(any(ExchangeCodeForTokenRequest.class));
        }

        @Test
        @DisplayName("Should handle Agent throwing RuntimeException during agent auth flow")
        void shouldHandleAgentThrowingRuntimeExceptionDuringAgentAuthFlow() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            when(mockAgent.handleAuthorizationCallback(any(AuthorizationResponse.class)))
                    .thenThrow(new RuntimeException("Agent internal error"));

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert - RuntimeException in performAgentAuthTokenExchange is wrapped as OAuth2TokenException(server_error)
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            assertThat(result.getErrorResponse().get("error")).isNotNull();
            assertThat(result.getErrorResponse().get("error_description")).asString()
                    .contains("Failed to exchange code for AOAT");
        }

        @Test
        @DisplayName("Should propagate OAuth2TokenException from Agent during agent auth flow")
        void shouldPropagateOAuth2TokenExceptionFromAgentDuringAgentAuthFlow() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            OAuth2TokenException tokenException = OAuth2TokenException.invalidGrant("Authorization code expired");
            when(mockAgent.handleAuthorizationCallback(any(AuthorizationResponse.class)))
                    .thenThrow(tokenException);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert - OAuth2TokenException should be propagated directly
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            assertThat(result.getErrorResponse().get("error")).isNotNull();
            assertThat(result.getErrorResponse().get("error_description")).asString()
                    .contains("Authorization code expired");
        }

        @Test
        @DisplayName("Should handle Agent throwing JOSEException when AOAT jwtString is empty")
        void shouldHandleAgentThrowingJoseExceptionForEmptyJwtString() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
            when(aoat.getJwtString()).thenThrow(new JOSEException("AOAT JWT string is not available"));
            when(mockAgent.handleAuthorizationCallback(any(AuthorizationResponse.class)))
                    .thenReturn(aoat);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert - JOSEException is caught and wrapped as server_error
            assertThat(result.isSuccess()).isFalse();
            assertThat(result.getStatusCode()).isEqualTo(400);
            assertThat(result.getErrorResponse().get("error")).isNotNull();
        }
    }

    @Nested
    @DisplayName("Session Restore Failures")
    class SessionRestoreFailures {

        @Test
        @DisplayName("Should handle user authentication flow with session creation")
        void shouldHandleUserAuthenticationFlowWithSessionCreation() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            // handleFlow first calls getSession(false), which returns null, then getSession(true) is called
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // Verify session was created
            verify(mockHttpRequest).getSession(false);
            verify(mockHttpRequest).getSession(true);
        }

        @Test
        @DisplayName("Should handle agent authorization flow with session creation")
        void shouldHandleAgentAuthorizationFlowWithSessionCreation() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_AGENT_AUTH, null, null, mockHttpRequest);
            setupAgentTokenExchangeSuccess();
            // handleFlow first calls getSession(false), which returns null, then getSession(true) is called
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
            // When session is null, the code creates a new session via request.getSession(true)
            // in both restoreOrCreateSession and handleAgentOperationAuthorizationFlow
            verify(mockHttpRequest).getSession(false);
            verify(mockHttpRequest, atLeast(1)).getSession(true);
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
            // Mock repository to return null for empty state (unknown/expired state)
            when(mockAuthorizationRequestStorage.remove("")).thenReturn(null);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert - empty state cannot be resolved from repository, callback returns error
            assertThat(result.isSuccess()).isFalse();
        }

        @Test
        @DisplayName("Should handle state parameter with only flow type")
        void shouldHandleStateParameterWithOnlyFlowType() throws Exception {
            // Arrange
            // Mock repository to return USER_AUTHENTICATION for "user:uuid" state
            when(mockAuthorizationRequestStorage.remove("user:uuid"))
                    .thenReturn(OAuth2AuthorizationRequest.builder()
                            .state("user:uuid")
                            .flowType(OAuth2AuthorizationRequest.FlowType.USER_AUTHENTICATION)
                            .build());
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, "user:uuid", null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

            // Act
            OAuth2CallbackResult result = callbackService.handleCallback(request, CLIENT_ID);

            // Assert
            assertThat(result.isSuccess()).isTrue();
        }

        @Test
        @DisplayName("Should handle user authentication flow successfully")
        void shouldHandleUserAuthenticationFlowSuccessfully() throws Exception {
            // Arrange
            OAuth2CallbackRequest request = new OAuth2CallbackRequest(CODE, STATE_USER_AUTH, null, null, mockHttpRequest);
            setupTokenExchangeSuccess();
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

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
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

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
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

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
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);

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
            when(mockHttpRequest.getSession(false)).thenReturn(null);
            when(mockHttpRequest.getSession(true)).thenReturn(mockRequestSession);
            // Set pending redirect URI in the request session
            when(mockRequestSession.getAttribute("open_agent_auth_redirect_uri")).thenReturn(PENDING_REDIRECT_URI);

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

    private void setupAgentTokenExchangeSuccess() throws Exception {
        AgentOperationAuthToken aoat = mock(AgentOperationAuthToken.class);
        when(aoat.getJwtString()).thenReturn(AOAT_JWT);
        when(aoat.getExpirationTime()).thenReturn(Instant.now().plusSeconds(3600));

        when(mockAgent.handleAuthorizationCallback(any(AuthorizationResponse.class)))
                .thenReturn(aoat);

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