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

import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UserLoginController}.
 * <p>
 * This test class verifies the user authentication and login/logout functionality,
 * including login page display, form submission, and logout operations.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserLoginController Tests")
class UserLoginControllerTest {

    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "password123";
    private static final String SUBJECT = "user123";
    private static final String NAME = "Test User";
    private static final String EMAIL = "test@example.com";
    private static final String REDIRECT_URI = "/oauth2/authorize?client_id=test";

    @Mock
    private UserRegistry userRegistry;

    @Mock
    private SessionMappingBizService sessionMappingBizService;

    @Mock
    private HttpSession session;

    @Mock
    private HttpSession originalSession;

    @Mock
    private HttpServletRequest request;

    @Mock
    private RedirectAttributes redirectAttributes;

    @InjectMocks
    private UserLoginController controller;

    @BeforeEach
    void setUp() {
        lenient().when(session.getId()).thenReturn("session123");
        lenient().when(session.getAttribute(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            // Return null by default for any session attribute
            return null;
        });
    }

    @Nested
    @DisplayName("GET /login - Login Page")
    class LoginPageTests {

        @Test
        @DisplayName("Should display login page with redirect URI from session")
        void shouldDisplayLoginPageWithRedirectUriFromSession() {
            // Arrange
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(REDIRECT_URI);

            // Act
            String viewName = controller.loginPage(null, mock(org.springframework.ui.Model.class), session);

            // Assert
            assertThat(viewName).isEqualTo("login");
            verify(session).getAttribute(SessionAttributes.REDIRECT_URI.getKey());
        }

        @Test
        @DisplayName("Should display login page with redirect URI from parameter")
        void shouldDisplayLoginPageWithRedirectUriFromParameter() {
            // Arrange
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(null);

            // Act
            String viewName = controller.loginPage(REDIRECT_URI, mock(org.springframework.ui.Model.class), session);

            // Assert
            assertThat(viewName).isEqualTo("login");
        }

        @Test
        @DisplayName("Should display login page without redirect URI")
        void shouldDisplayLoginPageWithoutRedirectUri() {
            // Arrange
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(null);

            // Act
            String viewName = controller.loginPage(null, mock(org.springframework.ui.Model.class), session);

            // Assert
            assertThat(viewName).isEqualTo("login");
        }

        @Test
        @DisplayName("Should handle null session gracefully")
        void shouldHandleNullSessionGracefully() {
            // Act
            String viewName = controller.loginPage(REDIRECT_URI, mock(org.springframework.ui.Model.class), null);

            // Assert
            assertThat(viewName).isEqualTo("login");
        }
    }

    @Nested
    @DisplayName("POST /login - Login Form Submission")
    class LoginSubmissionTests {

        @Test
        @DisplayName("Should login successfully and redirect to session redirect URI")
        void shouldLoginSuccessfullyAndRedirectToSessionRedirectUri() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenReturn(SUBJECT);
            when(userRegistry.getName(USERNAME)).thenReturn(NAME);
            when(userRegistry.getEmail(USERNAME)).thenReturn(EMAIL);
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(REDIRECT_URI);
            when(sessionMappingBizService.restoreSession(anyString(), anyBoolean(), any(HttpServletRequest.class))).thenReturn(null);

            // Act
            RedirectView redirectView = controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo(REDIRECT_URI);
            verify(session).setAttribute(SessionAttributes.AUTHENTICATED_USER.getKey(), SUBJECT);
            verify(session).removeAttribute(SessionAttributes.REDIRECT_URI.getKey());
        }

        @Test
        @DisplayName("Should login successfully and redirect to parameter redirect URI")
        void shouldLoginSuccessfullyAndRedirectToParameterRedirectUri() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenReturn(SUBJECT);
            when(userRegistry.getName(USERNAME)).thenReturn(NAME);
            when(userRegistry.getEmail(USERNAME)).thenReturn(EMAIL);
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(null);
            when(sessionMappingBizService.restoreSession(anyString(), anyBoolean(), any(HttpServletRequest.class))).thenReturn(null);

            // Act
            RedirectView redirectView = controller.login(USERNAME, PASSWORD, session, redirectAttributes, REDIRECT_URI, request);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo(REDIRECT_URI);
            verify(session).setAttribute(SessionAttributes.AUTHENTICATED_USER.getKey(), SUBJECT);
        }

        @Test
        @DisplayName("Should login successfully and redirect to home page when no redirect URI")
        void shouldLoginSuccessfullyAndRedirectToHomePageWhenNoRedirectUri() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenReturn(SUBJECT);
            when(userRegistry.getName(USERNAME)).thenReturn(NAME);
            when(userRegistry.getEmail(USERNAME)).thenReturn(EMAIL);
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(null);
            when(sessionMappingBizService.restoreSession(anyString(), anyBoolean(), any(HttpServletRequest.class))).thenReturn(null);

            // Act
            RedirectView redirectView = controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo("/");
            verify(session).setAttribute(SessionAttributes.AUTHENTICATED_USER.getKey(), SUBJECT);
        }

        @Test
        @DisplayName("Should restore original session and use its redirect URI")
        void shouldRestoreOriginalSessionAndUseItsRedirectUri() throws Exception {
            // Arrange
            String originalRedirectUri = "/oauth2/authorize?client_id=original";
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenReturn(SUBJECT);
            when(userRegistry.getName(USERNAME)).thenReturn(NAME);
            when(userRegistry.getEmail(USERNAME)).thenReturn(EMAIL);
            when(sessionMappingBizService.restoreSession(anyString(), eq(false), any(HttpServletRequest.class))).thenReturn(originalSession);
            when(originalSession.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(originalRedirectUri);

            // Act
            RedirectView redirectView = controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo(originalRedirectUri);
            verify(originalSession).setAttribute(SessionAttributes.AUTHENTICATED_USER.getKey(), SUBJECT);
            verify(originalSession).removeAttribute(SessionAttributes.REDIRECT_URI.getKey());
            verify(sessionMappingBizService).removeSession(anyString());
        }

        @Test
        @DisplayName("Should fail login with invalid credentials")
        void shouldFailLoginWithInvalidCredentials() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenThrow(new RuntimeException("Invalid credentials"));

            // Act
            RedirectView redirectView = controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo("/login");
            verify(redirectAttributes).addFlashAttribute("error", "Invalid username or password");
            verify(session, never()).setAttribute(anyString(), any());
        }

        @Test
        @DisplayName("Should handle authentication exception gracefully")
        void shouldHandleAuthenticationExceptionGracefully() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenThrow(new RuntimeException("Authentication failed"));

            // Act
            RedirectView redirectView = controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo("/login");
            verify(redirectAttributes).addFlashAttribute("error", "Invalid username or password");
        }
    }

    @Nested
    @DisplayName("GET /oauth2/logout - Logout")
    class LogoutTests {

        @Test
        @DisplayName("Should logout successfully and invalidate session")
        void shouldLogoutSuccessfullyAndInvalidateSession() {
            // Arrange
            when(session.getAttribute(SessionAttributes.AUTHENTICATED_USER.getKey())).thenReturn(SUBJECT);

            // Act
            RedirectView redirectView = controller.logout(session);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo("/login");
            verify(session).invalidate();
        }

        @Test
        @DisplayName("Should logout even when no authenticated user")
        void shouldLogoutEvenWhenNoAuthenticatedUser() {
            // Arrange
            when(session.getAttribute(SessionAttributes.AUTHENTICATED_USER.getKey())).thenReturn(null);

            // Act
            RedirectView redirectView = controller.logout(session);

            // Assert
            assertThat(redirectView.getUrl()).isEqualTo("/login");
            verify(session).invalidate();
        }
    }

    @Nested
    @DisplayName("GET / - Home Page")
    class HomePageTests {

        @Test
        @DisplayName("Should redirect to home page when authenticated")
        void shouldRedirectToHomePageWhenAuthenticated() {
            // Arrange
            when(session.getAttribute(SessionAttributes.AUTHENTICATED_USER.getKey())).thenReturn(SUBJECT);

            // Act
            String viewName = controller.home(session);

            // Assert
            assertThat(viewName).isEqualTo("home");
        }

        @Test
        @DisplayName("Should redirect to login page when not authenticated")
        void shouldRedirectToLoginPageWhenNotAuthenticated() {
            // Arrange
            when(session.getAttribute(SessionAttributes.AUTHENTICATED_USER.getKey())).thenReturn(null);

            // Act
            String viewName = controller.home(session);

            // Assert
            assertThat(viewName).isEqualTo("redirect:/login");
        }
    }

    @Nested
    @DisplayName("Session Management Tests")
    class SessionManagementTests {

        @Test
        @DisplayName("Should store user information in session after successful login")
        void shouldStoreUserInformationInSessionAfterSuccessfulLogin() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenReturn(SUBJECT);
            when(userRegistry.getName(USERNAME)).thenReturn(NAME);
            when(userRegistry.getEmail(USERNAME)).thenReturn(EMAIL);
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(null);
            when(sessionMappingBizService.restoreSession(anyString(), anyBoolean(), any(HttpServletRequest.class))).thenReturn(null);

            // Act
            controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            verify(session).setAttribute(SessionAttributes.AUTHENTICATED_USER.getKey(), SUBJECT);
        }

        @Test
        @DisplayName("Should not store password in session")
        void shouldNotStorePasswordInSession() throws Exception {
            // Arrange
            when(userRegistry.authenticate(USERNAME, PASSWORD)).thenReturn(SUBJECT);
            when(userRegistry.getName(USERNAME)).thenReturn(NAME);
            when(userRegistry.getEmail(USERNAME)).thenReturn(EMAIL);
            when(session.getAttribute(SessionAttributes.REDIRECT_URI.getKey())).thenReturn(null);
            when(sessionMappingBizService.restoreSession(anyString(), anyBoolean(), any(HttpServletRequest.class))).thenReturn(null);

            // Act
            controller.login(USERNAME, PASSWORD, session, redirectAttributes, null, request);

            // Assert
            verify(session).setAttribute(SessionAttributes.AUTHENTICATED_USER.getKey(), SUBJECT);
            // Password should not be stored in session
            // Verify that only AUTHENTICATED_USER was set, not password
            verify(session, never()).setAttribute(anyString(), eq(PASSWORD));
        }
    }
}
