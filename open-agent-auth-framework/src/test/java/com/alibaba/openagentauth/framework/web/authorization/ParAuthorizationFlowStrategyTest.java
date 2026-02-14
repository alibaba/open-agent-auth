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
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
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
 * Unit tests for {@link ParAuthorizationFlowStrategy}.
 * <p>
 * This test class validates PAR authorization flow functionality including:
 * </p>
 * <ul>
 *   <li>PAR request support detection</li>
 *   <li>Request parsing and context building</li>
 *   <li>Request validation</li>
 *   <li>Authorization code issuance</li>
 *   <li>Error handling</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("ParAuthorizationFlowStrategy Tests")
@ExtendWith(MockitoExtension.class)
class ParAuthorizationFlowStrategyTest {

    private static final String REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc123";
    private static final String STATE = "test-state-456";
    private static final String SUBJECT = "user-789";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String AUTHORIZATION_CODE = "auth-code-xyz";

    @Mock
    private OAuth2AuthorizationServer authorizationServer;

    @Mock
    private OAuth2ParServer parServer;

    @Mock
    private HttpServletRequest request;

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create strategy with valid parameters")
        void shouldCreateStrategyWithValidParameters() {
            // Act
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);

            // Assert
            assertThat(strategy).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when authorizationServer is null")
        void shouldThrowExceptionWhenAuthorizationServerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new ParAuthorizationFlowStrategy(null, parServer))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("authorizationServer");
        }

        @Test
        @DisplayName("Should throw exception when parServer is null")
        void shouldThrowExceptionWhenParServerIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new ParAuthorizationFlowStrategy(authorizationServer, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("parServer");
        }
    }

    @Nested
    @DisplayName("supports()")
    class SupportsTests {

        @Test
        @DisplayName("Should return true when request_uri parameter is present")
        void shouldReturnTrueWhenRequestUriParameterIsPresent() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn(REQUEST_URI);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isTrue();
        }

        @Test
        @DisplayName("Should return false when request_uri parameter is null")
        void shouldReturnFalseWhenRequestUriParameterIsNull() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn(null);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }

        @Test
        @DisplayName("Should return false when request_uri parameter is blank")
        void shouldReturnFalseWhenRequestUriParameterIsBlank() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn("   ");

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isFalse();
        }

        @Test
        @DisplayName("Should return false when request_uri parameter is empty string")
        void shouldReturnFalseWhenRequestUriParameterIsEmptyString() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn("");

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
        @DisplayName("Should parse request with request_uri and state")
        void shouldParseRequestWithRequestUriAndState() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn(REQUEST_URI);
            when(request.getParameter("state")).thenReturn(STATE);

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getFlowType()).isEqualTo("PAR");
            assertThat(context.getRequestUri()).isEqualTo(REQUEST_URI);
            assertThat(context.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should parse request with request_uri and null state")
        void shouldParseRequestWithRequestUriAndNullState() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn(REQUEST_URI);
            when(request.getParameter("state")).thenReturn(null);

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getFlowType()).isEqualTo("PAR");
            assertThat(context.getRequestUri()).isEqualTo(REQUEST_URI);
            assertThat(context.getState()).isNull();
        }

        @Test
        @DisplayName("Should parse request with request_uri and empty state")
        void shouldParseRequestWithRequestUriAndEmptyState() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn(REQUEST_URI);
            when(request.getParameter("state")).thenReturn("");

            // Act
            AuthorizationRequestContext context = strategy.parseRequest(request);

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getFlowType()).isEqualTo("PAR");
            assertThat(context.getRequestUri()).isEqualTo(REQUEST_URI);
            assertThat(context.getState()).isEqualTo("");
        }
    }

    @Nested
    @DisplayName("validateRequest()")
    class ValidateRequestTests {

        @Test
        @DisplayName("Should validate valid request")
        void shouldValidateValidRequest() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state(STATE)
                .build();
            when(authorizationServer.validateRequest(REQUEST_URI)).thenReturn(true);

            // Act
            strategy.validateRequest(context);

            // Assert - no exception thrown
            verify(authorizationServer).validateRequest(REQUEST_URI);
        }

        @Test
        @DisplayName("Should throw exception when request_uri is invalid")
        void shouldThrowExceptionWhenRequestUriIsInvalid() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state(STATE)
                .build();
            when(authorizationServer.validateRequest(REQUEST_URI)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> strategy.validateRequest(context))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .hasMessageContaining("Invalid or expired request_uri");
        }

        @Test
        @DisplayName("Should throw exception with correct error code")
        void shouldThrowExceptionWithCorrectErrorCode() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state(STATE)
                .build();
            when(authorizationServer.validateRequest(REQUEST_URI)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> strategy.validateRequest(context))
                .isInstanceOf(OAuth2AuthorizationException.class)
                .satisfies(ex -> {
                    OAuth2AuthorizationException oauthEx = (OAuth2AuthorizationException) ex;
                    assertThat(oauthEx.getRfcErrorCode()).isEqualTo(OAuth2RfcErrorCode.INVALID_REQUEST.getValue());
                });
        }
    }

    @Nested
    @DisplayName("issueCode()")
    class IssueCodeTests {

        @Test
        @DisplayName("Should issue authorization code successfully")
        void shouldIssueAuthorizationCodeSuccessfully() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state(STATE)
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId("client-123")
                .redirectUri(REDIRECT_URI)
                .requestUri(REQUEST_URI)
                .state(STATE)
                .subject(SUBJECT)
                .scope("openid profile")
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            ParRequest parRequest = createMockParRequest();

            when(authorizationServer.authorize(REQUEST_URI, SUBJECT)).thenReturn(authCode);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(result.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(result.getState()).isEqualTo(STATE);

            verify(authorizationServer).authorize(REQUEST_URI, SUBJECT);
            verify(parServer).retrieveRequest(REQUEST_URI);
        }

        @Test
        @DisplayName("Should issue authorization code with null par request state")
        void shouldIssueAuthorizationCodeWithNullParRequestState() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state(null)
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId("client-123")
                .redirectUri(REDIRECT_URI)
                .requestUri(REQUEST_URI)
                .state(null)
                .subject(SUBJECT)
                .scope("openid profile")
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            ParRequest parRequest = createMockParRequestWithNullState();

            when(authorizationServer.authorize(REQUEST_URI, SUBJECT)).thenReturn(authCode);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getCode()).isEqualTo(AUTHORIZATION_CODE);
            assertThat(result.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(result.getState()).isNull();
        }

        @Test
        @DisplayName("Should issue authorization code with different par request state")
        void shouldIssueAuthorizationCodeWithDifferentParRequestState() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(REQUEST_URI)
                .state("context-state")
                .build();

            AuthorizationCode authCode = AuthorizationCode.builder()
                .code(AUTHORIZATION_CODE)
                .clientId("client-123")
                .redirectUri(REDIRECT_URI)
                .requestUri(REQUEST_URI)
                .state(STATE)
                .subject(SUBJECT)
                .scope("openid profile")
                .issuedAt(java.time.Instant.now())
                .expiresAt(java.time.Instant.now().plusSeconds(600))
                .build();
            ParRequest parRequest = createMockParRequest();

            when(authorizationServer.authorize(REQUEST_URI, SUBJECT)).thenReturn(authCode);
            when(parServer.retrieveRequest(REQUEST_URI)).thenReturn(parRequest);

            // Act
            AuthorizationCodeResult result = strategy.issueCode(context, SUBJECT);

            // Assert
            assertThat(result).isNotNull();
            assertThat(result.getState()).isEqualTo(STATE); // Should use PAR request state
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle whitespace in request_uri parameter")
        void shouldHandleWhitespaceInRequestUriParameter() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            when(request.getParameter("request_uri")).thenReturn("  urn:ietf:params:oauth:request_uri:abc123  ");

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isTrue();
        }

        @Test
        @DisplayName("Should handle special characters in request_uri")
        void shouldHandleSpecialCharactersInRequestUri() {
            // Arrange
            ParAuthorizationFlowStrategy strategy = new ParAuthorizationFlowStrategy(
                authorizationServer, parServer);
            String specialRequestUri = "urn:ietf:params:oauth:request_uri:abc-123_xyz.456";
            when(request.getParameter("request_uri")).thenReturn(specialRequestUri);

            // Act
            boolean supports = strategy.supports(request);

            // Assert
            assertThat(supports).isTrue();
        }
    }

    /**
     * Helper method to create a mock ParRequest.
     */
    private ParRequest createMockParRequest() {
        return ParRequest.builder()
            .responseType("code")
            .clientId("client-123")
            .redirectUri(REDIRECT_URI)
            .scope("openid profile")
            .state(STATE)
            .build();
    }

    /**
     * Helper method to create a mock ParRequest with null state.
     */
    private ParRequest createMockParRequestWithNullState() {
        return ParRequest.builder()
            .responseType("code")
            .clientId("client-123")
            .redirectUri(REDIRECT_URI)
            .scope("openid profile")
            .state(null)
            .build();
    }
}
