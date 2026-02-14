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
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import jakarta.servlet.http.HttpSession;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OidcUserInfoController}.
 * <p>
 * This test class verifies the OIDC UserInfo endpoint functionality,
 * including user information retrieval and authentication validation.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OidcUserInfoController Tests")
class OidcUserInfoControllerTest {

    private static final String SUBJECT = "user123";
    private static final String USERNAME = "testuser";
    private static final String NAME = "Test User";
    private static final String EMAIL = "test@example.com";

    @Mock
    private UserRegistry userRegistry;

    @Mock
    private SessionManager sessionManager;

    @Mock
    private HttpSession session;

    @InjectMocks
    private OidcUserInfoController controller;

    @BeforeEach
    void setUp() {
        // Default mock setup
        lenient().when(userRegistry.getName(SUBJECT)).thenReturn(NAME);
        lenient().when(userRegistry.getEmail(SUBJECT)).thenReturn(EMAIL);
    }

    @Nested
    @DisplayName("GET /oauth2/userinfo - Success Scenarios")
    class SuccessScenarios {

        @Test
        @DisplayName("Should return user info when authenticated")
        void shouldReturnUserInfoWhenAuthenticated() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("sub", SUBJECT);
            assertThat(response.getBody()).containsEntry("name", NAME);
            assertThat(response.getBody()).containsEntry("email", EMAIL);
            assertThat(response.getBody()).containsEntry("preferred_username", SUBJECT);
        }

        @Test
        @DisplayName("Should return username as name when name is null")
        void shouldReturnUsernameAsNameWhenNameIsNull() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);
            when(userRegistry.getName(SUBJECT)).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("name", SUBJECT);
        }

        @Test
        @DisplayName("Should include all standard OIDC claims")
        void shouldIncludeAllStandardOidcClaims() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            Map<String, Object> userInfo = response.getBody();
            assertThat(userInfo).containsKeys("sub", "name", "email", "preferred_username");
        }
    }

    @Nested
    @DisplayName("GET /oauth2/userinfo - Error Handling")
    class ErrorHandling {

        @Test
        @DisplayName("Should return 401 when user is not authenticated")
        void shouldReturn401WhenUserIsNotAuthenticated() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", "invalid_token");
            assertThat(response.getBody()).containsEntry("error_description", "User not authenticated");
        }

        @Test
        @DisplayName("Should return 500 when unexpected error occurs")
        void shouldReturn500WhenUnexpectedErrorOccurs() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER))
                    .thenThrow(new RuntimeException("Unexpected error"));

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", "server_error");
            assertThat(response.getBody()).containsEntry("error_description", "Internal server error");
        }

        @Test
        @DisplayName("Should handle user registry exception gracefully")
        void shouldHandleUserRegistryExceptionGracefully() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);
            when(userRegistry.getName(SUBJECT)).thenThrow(new RuntimeException("Registry error"));

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).containsEntry("error", "server_error");
        }
    }

    @Nested
    @DisplayName("UserInfo Response Format Tests")
    class ResponseFormatTests {

        @Test
        @DisplayName("Should return response in correct JSON format")
        void shouldReturnResponseInCorrectJsonFormat() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isInstanceOf(Map.class);
        }

        @Test
        @DisplayName("Should have correct subject claim format")
        void shouldHaveCorrectSubjectClaimFormat() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsEntry("sub", SUBJECT);
        }

        @Test
        @DisplayName("Should handle null email gracefully")
        void shouldHandleNullEmailGracefully() {
            // Arrange
            when(sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER)).thenReturn(SUBJECT);
            when(userRegistry.getEmail(SUBJECT)).thenReturn(null);

            // Act
            ResponseEntity<Map<String, Object>> response = controller.userinfo(session);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).containsEntry("email", null);
        }
    }
}
