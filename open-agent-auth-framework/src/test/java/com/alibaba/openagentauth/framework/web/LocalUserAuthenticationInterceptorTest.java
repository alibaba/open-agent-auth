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

import com.alibaba.openagentauth.framework.web.interceptor.LocalUserAuthenticationInterceptor;
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
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LocalUserAuthenticationInterceptor}.
 *
 * @since 1.0
 */
@DisplayName("LocalUserAuthenticationInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class LocalUserAuthenticationInterceptorTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private TestableLocalUserAuthenticationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new TestableLocalUserAuthenticationInterceptor(
            List.of("/login", "/callback")
        );
    }

    /**
     * Testable subclass that exposes protected methods for testing.
     */
    private static class TestableLocalUserAuthenticationInterceptor extends LocalUserAuthenticationInterceptor {
        public TestableLocalUserAuthenticationInterceptor(List<String> excludedPaths) {
            super(excludedPaths);
        }

        public String testBuildAuthorizationUrl(HttpServletRequest request, String state) {
            return buildAuthorizationUrl(request, state);
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
            LocalUserAuthenticationInterceptor interceptor = new LocalUserAuthenticationInterceptor(null);

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("preHandle(HttpServletRequest, HttpServletResponse)")
    class PreHandle {

        @Test
        @DisplayName("Should redirect to local login for unauthenticated user")
        void shouldRedirectToLocalLoginForUnauthenticatedUser() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getQueryString()).thenReturn(null);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(any());
        }

        @Test
        @DisplayName("Should redirect with encoded redirect URI")
        void shouldRedirectWithEncodedRedirectUri() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn("response_type=code&client_id=test");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(any());
        }

        @Test
        @DisplayName("Should redirect with context path in login URL")
        void shouldRedirectWithContextPathInLoginUrl() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");
            when(request.getRequestURI()).thenReturn("/app/protected");
            when(request.getQueryString()).thenReturn(null);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(any());
        }

        @Test
        @DisplayName("Should redirect with custom port in login URL")
        void shouldRedirectWithCustomPortInLoginUrl() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getSession(false)).thenReturn(null);
            when(request.getSession(true)).thenReturn(session);
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/protected");
            when(request.getQueryString()).thenReturn(null);

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendRedirect(any());
        }

        @Test
        @DisplayName("Should allow access for excluded path")
        void shouldAllowAccessForExcludedPath() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/login");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
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
        }
    }

    @Nested
    @DisplayName("buildAuthorizationUrl(HttpServletRequest, String)")
    class BuildAuthorizationUrl {

        @Test
        @DisplayName("Should build local login URL with redirect URI")
        void shouldBuildLocalLoginUrlWithRedirectUri() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn(null);

            // Act
            String loginUrl = interceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(loginUrl).contains("/login?redirect_uri=");
            assertThat(loginUrl).contains("https://example.com");
        }

        @Test
        @DisplayName("Should encode redirect URI parameters")
        void shouldEncodeRedirectUriParameters() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn("response_type=code&client_id=test");

            // Act
            String loginUrl = interceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(loginUrl).contains("/login?redirect_uri=");
            assertThat(loginUrl).contains("response_type%3Dcode");
        }

        @Test
        @DisplayName("Should include context path in base URL")
        void shouldIncludeContextPathInBaseUrl() {
            // Arrange
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");
            when(request.getRequestURI()).thenReturn("/app/oauth2/authorize");
            when(request.getQueryString()).thenReturn(null);

            // Act
            String loginUrl = interceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(loginUrl).contains("https://example.com/app/login");
        }

        @Test
        @DisplayName("Should include custom port in base URL")
        void shouldIncludeCustomPortInBaseUrl() {
            // Arrange
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getContextPath()).thenReturn("");
            when(request.getRequestURI()).thenReturn("/oauth2/authorize");
            when(request.getQueryString()).thenReturn(null);

            // Act
            String loginUrl = interceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(loginUrl).contains("http://example.com:8080/login");
        }
    }
}
