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
package com.alibaba.openagentauth.framework.web.interceptor;

import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.atLeast;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AgentAuthenticationInterceptor}.
 * <p>
 * This test class validates authentication interception functionality including:
 * </p>
 * <ul>
 *   <li>Authentication check for protected resources</li>
 *   <li>Excluded path matching with wildcards</li>
 *   <li>Session management and state handling</li>
 *   <li>OAuth2 authorization flow initiation</li>
 *   <li>CSRF protection with state parameter</li>
 *   <li>Redirect URI construction</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("AgentAuthenticationInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class AgentAuthenticationInterceptorTest {

    private static final String AUTHORIZATION_URL = "https://agent-idp.example.com/authorize";
    private static final String SESSION_ID = "test-session-123";
    private static final String STATE = "test-state-456";

    @Mock
    private AgentAapExecutor agentAapExecutor;

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private HttpSession session;

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create interceptor with valid parameters")
        void shouldCreateInterceptorWithValidParameters() {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback", "/public/**");

            // Act
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with null excluded paths")
        void shouldCreateInterceptorWithNullExcludedPaths() {
            // Act
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, null);

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with empty excluded paths")
        void shouldCreateInterceptorWithEmptyExcludedPaths() {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();

            // Act
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("preHandle() - Authentication Check")
    class AuthenticationCheckTests {

        @Test
        @DisplayName("Should allow access when user is authenticated")
        void shouldAllowAccessWhenUserIsAuthenticated() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(SessionAttributes.AUTHENTICATED_USER.getKey())).thenReturn("user-123");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }

        @Test
        @DisplayName("Should redirect to login when user is not authenticated")
        void shouldRedirectToLoginWhenUserIsNotAuthenticated() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(AUTHORIZATION_URL);
        }

        @Test
        @DisplayName("Should create new session when session does not exist")
        void shouldCreateNewSessionWhenSessionDoesNotExist() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(request, atLeast(1)).getSession(true);
            verify(response).sendRedirect(AUTHORIZATION_URL);
        }

        @Test
        @DisplayName("Should not redirect when session is null and path is excluded")
        void shouldNotRedirectWhenSessionIsNullAndPathIsExcluded() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/callback");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }
    }

    @Nested
    @DisplayName("preHandle() - Excluded Paths")
    class ExcludedPathsTests {

        @Test
        @DisplayName("Should allow access to exact excluded path")
        void shouldAllowAccessToExactExcludedPath() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/callback");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }

        @Test
        @DisplayName("Should allow access to path matching wildcard pattern")
        void shouldAllowAccessToPathMatchingWildcardPattern() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/public/**");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/public/css/style.css");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }

        @Test
        @DisplayName("Should allow access to path matching single level wildcard")
        void shouldAllowAccessToPathMatchingSingleLevelWildcard() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/api/*");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/api/v1");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }

        @Test
        @DisplayName("Should allow access to path matching question mark wildcard")
        void shouldAllowAccessToPathMatchingQuestionMarkWildcard() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/file?.txt");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/file1.txt");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }

        @Test
        @DisplayName("Should redirect when path is not in excluded paths")
        void shouldRedirectWhenPathIsNotInExcludedPaths() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback", "/public/**");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(AUTHORIZATION_URL);
        }
    }

    @Nested
    @DisplayName("preHandle() - OAuth2 Authorization Flow")
    class OAuth2FlowTests {

        @Test
        @DisplayName("Should build correct redirect URI with https and default port")
        void shouldBuildCorrectRedirectUriWithHttpsAndDefaultPort() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");
            when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            interceptor.preHandle(request, response);

            // Assert
            ArgumentCaptor<InitiateAuthorizationRequest> captor = ArgumentCaptor.forClass(InitiateAuthorizationRequest.class);
            verify(agentAapExecutor).initiateUserAuthentication(captor.capture());
            assertThat(captor.getValue().getRedirectUri()).isEqualTo("https://example.com/app/callback");
        }

        @Test
        @DisplayName("Should build correct redirect URI with http and custom port")
        void shouldBuildCorrectRedirectUriWithHttpAndCustomPort() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("localhost");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            interceptor.preHandle(request, response);

            // Assert
            ArgumentCaptor<InitiateAuthorizationRequest> captor = ArgumentCaptor.forClass(InitiateAuthorizationRequest.class);
            verify(agentAapExecutor).initiateUserAuthentication(captor.capture());
            assertThat(captor.getValue().getRedirectUri()).isEqualTo("http://localhost:8080/callback");
        }

        @Test
        @DisplayName("Should generate state parameter with user flow type")
        void shouldGenerateStateParameterWithUserFlowType() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            interceptor.preHandle(request, response);

            // Assert
            ArgumentCaptor<InitiateAuthorizationRequest> captor = ArgumentCaptor.forClass(InitiateAuthorizationRequest.class);
            verify(agentAapExecutor).initiateUserAuthentication(captor.capture());
            String state = captor.getValue().getState();
            // State is now an opaque URL-safe Base64 value (32 bytes, 43 characters)
            assertThat(state).isNotNull();
            assertThat(state).isNotEmpty();
            assertThat(state).doesNotContain(":");
            assertThat(state).hasSize(43);
        }

        @Test
        @DisplayName("Should store state in session for CSRF protection")
        void shouldStoreStateInSessionForCsrfProtection() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            interceptor.preHandle(request, response);

            // Assert
            ArgumentCaptor<String> stateCaptor = ArgumentCaptor.forClass(String.class);
            verify(session).setAttribute(eq(SessionAttributes.OAUTH_STATE.getKey()), stateCaptor.capture());
            String storedState = stateCaptor.getValue();
            // The state parameter stored in session is now an opaque value
            assertThat(storedState).isNotNull();
            assertThat(storedState).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Path Pattern Matching")
    class PathPatternMatchingTests {

        @Test
        @DisplayName("Should match exact path pattern")
        void shouldMatchExactPathPattern() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/callback");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should not match exact path pattern when paths differ")
        void shouldNotMatchExactPathPatternWhenPathsDiffer() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/callback/other");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should match double wildcard pattern")
        void shouldMatchDoubleWildcardPattern() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/public/**");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/public/a/b/c");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should match double wildcard pattern at root")
        void shouldMatchDoubleWildcardPatternAtRoot() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/public/**");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/public");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should match single wildcard pattern")
        void shouldMatchSingleWildcardPattern() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/api/*");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/api/v1");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should not match single wildcard pattern for multi-level path")
        void shouldNotMatchSingleWildcardPatternForMultiLevelPath() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/api/*");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/api/v1/users");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should match question mark pattern")
        void shouldMatchQuestionMarkPattern() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/file?.txt");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/file1.txt");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should not match question mark pattern for multiple characters")
        void shouldNotMatchQuestionMarkPatternForMultipleCharacters() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/file?.txt");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/file12.txt");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should match prefix pattern")
        void shouldMatchPrefixPattern() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/static/");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/static/css/style.css");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should not match prefix pattern without trailing slash")
        void shouldNotMatchPrefixPatternWithoutTrailingSlash() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/static");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/static/css/style.css");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
        }
    }

    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle empty request URI")
        void shouldHandleEmptyRequestUri() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(AUTHORIZATION_URL);
        }

        @Test
        @DisplayName("Should handle null session ID")
        void shouldHandleNullSessionId() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should handle multiple excluded paths")
        void shouldHandleMultipleExcludedPaths() throws IOException {
            // Arrange
            List<String> excludedPaths = Arrays.asList("/callback", "/public/**", "/api/v1/*");
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/api/v1/users");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(anyString());
        }

        @Test
        @DisplayName("Should handle context path in redirect URI")
        void shouldHandleContextPathInRedirectUri() throws IOException {
            // Arrange
            List<String> excludedPaths = new ArrayList<>();
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor, excludedPaths);

            when(request.getRequestURI()).thenReturn("/protected/resource");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/myapp");
            lenient().when(agentAapExecutor.initiateUserAuthentication(any(InitiateAuthorizationRequest.class))).thenReturn(AUTHORIZATION_URL);

            // Act
            interceptor.preHandle(request, response);

            // Assert
            ArgumentCaptor<InitiateAuthorizationRequest> captor = ArgumentCaptor.forClass(InitiateAuthorizationRequest.class);
            verify(agentAapExecutor).initiateUserAuthentication(captor.capture());
            assertThat(captor.getValue().getRedirectUri()).isEqualTo("https://example.com/myapp/callback");
        }
    }
}