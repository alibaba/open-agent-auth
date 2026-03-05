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
package com.alibaba.openagentauth.framework.web;

import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserAuthenticationInterceptor}.
 *
 * @since 1.0
 */
@DisplayName("UserAuthenticationInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class UserAuthenticationInterceptorTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private TestableUserAuthenticationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new TestableUserAuthenticationInterceptor(
            List.of("/login", "/callback", "/public/**")
        );
    }

    /**
     * Testable subclass that exposes protected methods for testing.
     */
    static class TestableUserAuthenticationInterceptor extends UserAuthenticationInterceptor {

        public TestableUserAuthenticationInterceptor(List<String> excludedPaths) {
            super(excludedPaths);
        }

        @Override
        protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
            // Default implementation for testing
            return "https://idp.example.com/login?state=" + state;
        }

        public boolean testMatchesPattern(String pattern, String path) {
            return matchesPattern(pattern, path);
        }

        public String testGenerateState() {
            return generateState();
        }
    }

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create interceptor with valid parameters")
        void shouldCreateInterceptorWithValidParameters() {
            // Act & Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with null excluded paths")
        void shouldCreateInterceptorWithNullExcludedPaths() {
            // Act
            UserAuthenticationInterceptor interceptor = new UserAuthenticationInterceptor(null);

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("preHandle(HttpServletRequest, HttpServletResponse)")
    class PreHandle {

        @Test
        @DisplayName("Should allow access for excluded path")
        void shouldAllowAccessForExcludedPath() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/login");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(any());
        }

        @Test
        @DisplayName("Should allow access for wildcard excluded path")
        void shouldAllowAccessForWildcardExcludedPath() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/public/css/style.css");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(any());
        }

        @Test
        @DisplayName("Should redirect unauthenticated user")
        void shouldRedirectUnauthenticatedUser() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("localhost");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getQueryString()).thenReturn(null);

            // Create a test interceptor that returns a login URL
            UserAuthenticationInterceptor testInterceptor = new UserAuthenticationInterceptor(
                List.of("/login")
            ) {
                @Override
                protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
                    return "https://idp.example.com/login?state=" + state;
                }
            };

            // Act
            boolean result = testInterceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(any());
        }

        @Test
        @DisplayName("Should save original request URL to session before redirecting")
        void shouldSaveOriginalRequestUrlToSessionBeforeRedirecting() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/admin");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("localhost");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getQueryString()).thenReturn(null);

            UserAuthenticationInterceptor testInterceptor = new UserAuthenticationInterceptor(
                List.of("/login")
            ) {
                @Override
                protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
                    return "https://idp.example.com/login?state=" + state;
                }
            };

            // Act
            try (MockedStatic<SessionManager> mockedSessionManager = mockStatic(SessionManager.class)) {
                testInterceptor.preHandle(request, response);

                // Assert - verify REDIRECT_URI was saved to session
                mockedSessionManager.verify(() ->
                        SessionManager.setAttribute(eq(session), eq(SessionAttributes.REDIRECT_URI), any(String.class)));
            }
        }

        @Test
        @DisplayName("Should allow access for authenticated user")
        void shouldAllowAccessForAuthenticatedUser() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute("authenticated_user")).thenReturn("user123");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
            verify(response, never()).sendRedirect(any());
        }

        @Test
        @DisplayName("Should send unauthorized error when no login URL available")
        void shouldSendUnauthorizedErrorWhenNoLoginUrlAvailable() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("localhost");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getQueryString()).thenReturn(null);

            // Create a test interceptor that returns null for login URL
            UserAuthenticationInterceptor testInterceptor = new UserAuthenticationInterceptor(
                List.of("/login")
            ) {
                @Override
                protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
                    return null; // Return null to test error handling
                }
            };

            // Act
            boolean result = testInterceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
        }
    }

    @Nested
    @DisplayName("authenticate(HttpServletRequest)")
    class Authenticate {

        @Test
        @DisplayName("Should return null for null request")
        void shouldReturnNullForNullRequest() {
            // Act
            String result = interceptor.authenticate(null);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should return null when no session exists")
        void shouldReturnNullWhenNoSessionExists() {
            // Arrange
            when(request.getSession(false)).thenReturn(null);

            // Act
            String result = interceptor.authenticate(request);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should return authenticated user from session")
        void shouldReturnAuthenticatedUserFromSession() {
            // Arrange
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute("authenticated_user")).thenReturn("user123");

            // Act
            String result = interceptor.authenticate(request);

            // Assert
            assertThat(result).isEqualTo("user123");
        }

        @Test
        @DisplayName("Should return null when user not authenticated")
        void shouldReturnNullWhenUserNotAuthenticated() {
            // Arrange
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute("authenticated_user")).thenReturn(null);

            // Act
            String result = interceptor.authenticate(request);

            // Assert
            assertThat(result).isNull();
        }

        @Test
        @DisplayName("Should return null when session has no authenticated user attribute")
        void shouldReturnNullWhenSessionHasNoAuthenticatedUserAttribute() {
            // Arrange
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute("authenticated_user")).thenReturn(null);

            // Act
            String result = interceptor.authenticate(request);

            // Assert
            assertThat(result).isNull();
        }
    }

    @Nested
    @DisplayName("getLoginUrl(HttpServletRequest)")
    class GetLoginUrl {

        @Test
        @DisplayName("Should generate login URL with state parameter")
        void shouldGenerateLoginUrlWithStateParameter() {
            // Arrange
            when(request.getSession(true)).thenReturn(session);

            // Create a test interceptor that returns a login URL
            UserAuthenticationInterceptor testInterceptor = new UserAuthenticationInterceptor(
                List.of("/login")
            ) {
                @Override
                protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
                    return "https://idp.example.com/login?state=" + state;
                }
            };

            // Act
            String loginUrl = testInterceptor.getLoginUrl(request);

            // Assert
            assertThat(loginUrl).isNotNull();
            assertThat(loginUrl).contains("state=user:");
            // State format is now "user:{random}" without sessionId
            assertThat(loginUrl).doesNotContain("session123");
        }

        @Test
        @DisplayName("Should set OAuth state in session")
        void shouldSetOAuthStateInSession() {
            // Arrange
            when(request.getSession(true)).thenReturn(session);

            // Create a test interceptor
            UserAuthenticationInterceptor testInterceptor = new UserAuthenticationInterceptor(
                List.of("/login")
            ) {
                @Override
                protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
                    return "https://idp.example.com/login";
                }
            };

            // Act
            try (MockedStatic<SessionManager> mockedSessionManager = mockStatic(SessionManager.class)) {
                testInterceptor.getLoginUrl(request);

                // Assert - Use eq() for all arguments
                mockedSessionManager.verify(() -> SessionManager.setAttribute(eq(session), eq(SessionAttributes.OAUTH_STATE), any()));
            }
        }
    }

    @Nested
    @DisplayName("matchesPattern(String, String)")
    class MatchesPattern {

        @Test
        @DisplayName("Should match exact path")
        void shouldMatchExactPath() {
            // Act
            boolean result = interceptor.testMatchesPattern("/login", "/login");

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should not match different path")
        void shouldNotMatchDifferentPath() {
            // Act
            boolean result = interceptor.testMatchesPattern("/login", "/logout");

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should match wildcard at end of segment")
        void shouldMatchWildcardAtEndOfSegment() {
            // Act
            boolean result = interceptor.testMatchesPattern("/public/*", "/public/css");

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should match double wildcard for multiple segments")
        void shouldMatchDoubleWildcardForMultipleSegments() {
            // Act
            boolean result = interceptor.testMatchesPattern("/public/**", "/public/css/style.css");

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should match double wildcard for single segment")
        void shouldMatchDoubleWildcardForSingleSegment() {
            // Act
            boolean result = interceptor.testMatchesPattern("/public/**", "/public/css");

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should match double wildcard with prefix only")
        void shouldMatchDoubleWildcardWithPrefixOnly() {
            // Act
            boolean result = interceptor.testMatchesPattern("/public/**", "/public");

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should match question mark wildcard")
        void shouldMatchQuestionMarkWildcard() {
            // Act
            boolean result = interceptor.testMatchesPattern("/api/v?/users", "/api/v1/users");

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should not match question mark wildcard with wrong length")
        void shouldNotMatchQuestionMarkWildcardWithWrongLength() {
            // Act
            boolean result = interceptor.testMatchesPattern("/api/v?/users", "/api/v12/users");

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should match double wildcard in middle")
        void shouldMatchDoubleWildcardInMiddle() {
            // Act
            boolean result = interceptor.testMatchesPattern("/public/**/images", "/public/css/images");

            // Assert
            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("generateState()")
    class GenerateState {

        @Test
        @DisplayName("Should generate unique state")
        void shouldGenerateUniqueState() {
            // Act
            String state1 = interceptor.testGenerateState();
            String state2 = interceptor.testGenerateState();

            // Assert
            assertThat(state1).isNotNull();
            assertThat(state2).isNotNull();
            assertThat(state1).isNotEqualTo(state2);
        }

        @Test
        @DisplayName("Should generate non-empty state")
        void shouldGenerateNonEmptyState() {
            // Act
            String state = interceptor.testGenerateState();

            // Assert
            assertThat(state).isNotEmpty();
        }
    }
}
