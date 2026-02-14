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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TraditionalAuthorizationFlowStrategy}.
 * <p>
 * This test class validates traditional OAuth 2.0 authorization flow functionality including:
 * </p>
 * <ul>
 *   <li>Traditional request support detection</li>
 *   <li>Request parsing and context building</li>
 *   <li>Request validation</li>
 *   <li>Authorization code issuance</li>
 *   <li>Error handling</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("TraditionalAuthorizationFlowStrategy Tests")
@ExtendWith(MockitoExtension.class)
class TraditionalAuthorizationFlowStrategyTest {

    private static final String CLIENT_ID = "client-123";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String SCOPE = "openid profile";
    private static final String STATE = "test-state-456";
    private static final String RESPONSE_TYPE = "code";
    private static final String SUBJECT = "user-789";
    private static final String AUTHORIZATION_CODE = "auth-code-xyz";

    @Mock
    private OAuth2AuthorizationServer authorizationServer;

    @Mock
    private HttpServletRequest request;

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create strategy with valid authorizationServer")
        void shouldCreateStrategyWithValidAuthorizationServer() {
            // Act
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);

            // Assert
            assertThat(strategy).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when authorizationServer is null")
        void shouldThrowExceptionWhenAuthorizationServerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new TraditionalAuthorizationFlowStrategy(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("authorizationServer");
        }
    }

    @Nested
    @DisplayName("supports()")
    class SupportsTests {

        @Test
        @DisplayName("Should return true when all required parameters are present")
        void shouldReturnTrueWhenAllRequiredParametersArePresent() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isTrue();
        }

        @Test
        @DisplayName("Should return false when request_uri parameter is present")
        void shouldReturnFalseWhenRequestUriParameterIsPresent() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn("urn:ietf:params:oauth:request_uri:abc123");

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }

        @Test
        @DisplayName("Should return false when response_type parameter is null")
        void shouldReturnFalseWhenResponseTypeParameterIsNull() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn(null);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }

        @Test
        @DisplayName("Should return false when client_id parameter is null")
        void shouldReturnFalseWhenClientIdParameterIsNull() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(null);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }

        @Test
        @DisplayName("Should return false when redirect_uri parameter is null")
        void shouldReturnFalseWhenRedirectUriParameterIsNull() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(null);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }

        @Test
        @DisplayName("Should return false when all required parameters are missing")
        void shouldReturnFalseWhenAllRequiredParametersAreMissing() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }
    }

    @Nested
    @DisplayName("parseRequest()")
    class ParseRequestTests {

        @Test
        @DisplayName("Should parse request with all parameters")
        void shouldParseRequestWithAllParameters() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);
            when(request.getParameter("scope")).thenReturn(SCOPE);
            when(request.getParameter("state")).thenReturn(STATE);

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getFlowType()).isEqualTo("TRADITIONAL");
            assertThat(context.getResponseType()).isEqualTo(RESPONSE_TYPE);
            assertThat(context.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(context.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(context.getScope()).isEqualTo(SCOPE);
            assertThat(context.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should parse request with null scope")
        void shouldParseRequestWithNullScope() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);
            when(request.getParameter("scope")).thenReturn(null);
            when(request.getParameter("state")).thenReturn(STATE);

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getScope()).isNull();
        }

        @Test
        @DisplayName("Should parse request with null state")
        void shouldParseRequestWithNullState() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);
            when(request.getParameter("scope")).thenReturn(SCOPE);
            when(request.getParameter("state")).thenReturn(null);

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getState()).isNull();
        }

        @Test
        @DisplayName("Should parse request with empty scope")
        void shouldParseRequestWithEmptyScope() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);
            when(request.getParameter("scope")).thenReturn("");
            when(request.getParameter("state")).thenReturn(STATE);

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getScope()).isEqualTo("");
        }
    }

    @Nested
    @DisplayName("validateRequest()")
    class ValidateRequestTests {

        @Test
        @DisplayName("Should validate valid request with code response_type")
        void shouldValidateValidRequestWithCodeResponseType() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("code")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .build();

            // Act
            strategy.validateRequest(context);

            // Assert - no exception thrown
        }

        @Test
        @DisplayName("Should throw exception when response_type is not code")
        void shouldThrowExceptionWhenResponseTypeIsNotCode() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("token")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .build();

            // Act & Assert
            assertThatThrownBy(() -> strategy.validateRequest(context))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .hasMessageContaining("Only 'code' response_type is supported");
        }

        @Test
        @DisplayName("Should throw exception with correct error code")
        void shouldThrowExceptionWithCorrectErrorCode() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("token")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .build();

            // Act & Assert
            assertThatThrownBy(() -> strategy.validateRequest(context))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> {
                    OAuth2AuthorizationException oauthEx = (OAuth2AuthorizationException) ex;
                    assertThat(oauthEx.getRfcErrorCode()).isEqualTo(OAuth2RfcErrorCode.UNSUPPORTED_RESPONSE_TYPE.getValue());
                });
        }

        @Test
        @DisplayName("Should throw exception when response_type is null")
        void shouldThrowExceptionWhenResponseTypeIsNull() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType(null)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .build();

            // Act & Assert
            assertThatThrownBy(() -> strategy.validateRequest(context))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .hasMessageContaining("Only 'code' response_type is supported");
        }

        @Test
        @DisplayName("Should throw exception when response_type is empty")
        void shouldThrowExceptionWhenResponseTypeIsEmpty() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .build();

            // Act & Assert
            assertThatThrownBy(() -> strategy.validateRequest(context))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .hasMessageContaining("Only 'code' response_type is supported");
        }
    }

    @Nested
    @DisplayName("issueCode()")
    class IssueCodeTests {

        @Test
        @DisplayName("Should issue authorization code successfully")
        void shouldIssueAuthorizationCodeSuccessfully() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("code")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope(SCOPE)
                .state(STATE)
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .subject(SUBJECT)
                .scope(SCOPE)
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            when(authorizationServer.authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, SCOPE))
                .thenReturn(authCode);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(result.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(result.getState()).isEqualTo(STATE);

            verify(authorizationServer).authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, SCOPE);
        }

        @Test
        @DisplayName("Should issue authorization code with null scope")
        void shouldIssueAuthorizationCodeWithNullScope() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("code")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope(null)
                .state(STATE)
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .subject(SUBJECT)
                .scope("")
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            when(authorizationServer.authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, ""))
                .thenReturn(authCode);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(AUTHORIZATION_CODE);

            verify(authorizationServer).authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, "");
        }

        @Test
        @DisplayName("Should issue authorization code with null state")
        void shouldIssueAuthorizationCodeWithNullState() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("code")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope(SCOPE)
                .state(null)
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .subject(SUBJECT)
                .scope(SCOPE)
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            when(authorizationServer.authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, SCOPE))
                .thenReturn(authCode);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(result.getState()).isNull();
        }

        @Test
        @DisplayName("Should issue authorization code with empty scope")
        void shouldIssueAuthorizationCodeWithEmptyScope() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType("code")
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope("")
                .state(STATE)
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .subject(SUBJECT)
                .scope("")
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            when(authorizationServer.authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, ""))
                .thenReturn(authCode);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(AUTHORIZATION_CODE);

            verify(authorizationServer).authorize(SUBJECT, CLIENT_ID, REDIRECT_URI, "");
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle whitespace in parameters")
        void shouldHandleWhitespaceInParameters() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn("  code  ");
            when(request.getParameter("client_id")).thenReturn("  client-123  ");
            when(request.getParameter("redirect_uri")).thenReturn("  https://client.example.com/callback  ");

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isTrue();
        }

        @Test
        @DisplayName("Should handle special characters in redirect_uri")
        void shouldHandleSpecialCharactersInRedirectUri() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("request_uri")).thenReturn(null);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn("https://client.example.com/callback?param=value&other=123");

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isTrue();
        }

        @Test
        @DisplayName("Should handle multiple scopes")
        void shouldHandleMultipleScopes() {
            // Arrange
            TraditionalAuthorizationFlowStrategy strategy = new TraditionalAuthorizationFlowStrategy(
                authorizationServer);
            when(request.getParameter("response_type")).thenReturn(RESPONSE_TYPE);
            when(request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(request.getParameter("redirect_uri")).thenReturn(REDIRECT_URI);
            when(request.getParameter("scope")).thenReturn("openid profile email");

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context.getScope()).isEqualTo("openid profile email");
        }
    }
}
