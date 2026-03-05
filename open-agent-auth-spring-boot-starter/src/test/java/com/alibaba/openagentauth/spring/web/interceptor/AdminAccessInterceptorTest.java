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
package com.alibaba.openagentauth.spring.web.interceptor;

import com.alibaba.openagentauth.spring.autoconfigure.properties.AdminProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AdminAccessInterceptor}.
 * <p>
 * Tests the Spring MVC interceptor that enforces access control on admin endpoints.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AdminAccessInterceptor Tests")
class AdminAccessInterceptorTest {

    private static final String AUTHENTICATED_USER_KEY = "authenticated_user";

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    private AdminProperties.AccessControlProperties accessControlProperties;

    @BeforeEach
    void setUp() {
        accessControlProperties = new AdminProperties.AccessControlProperties();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw NullPointerException when accessControlProperties is null")
        void shouldThrowNullPointerExceptionWhenAccessControlPropertiesIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new AdminAccessInterceptor(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("accessControlProperties must not be null");
        }

        @Test
        @DisplayName("Should create interceptor successfully with valid properties")
        void shouldCreateInterceptorSuccessfullyWithValidProperties() {
            // Arrange
            accessControlProperties.setEnabled(true);
            accessControlProperties.setAllowedSessionSubjects(List.of("admin"));

            // Act
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("preHandle() Tests - Access Control Disabled")
    class AccessControlDisabledTests {

        @Test
        @DisplayName("Should allow all requests when access control is disabled")
        void shouldAllowAllRequestsWhenAccessControlIsDisabled() throws Exception {
            // Arrange
            accessControlProperties.setEnabled(false);
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isTrue();
        }
    }

    @Nested
    @DisplayName("preHandle() Tests - Access Control Enabled")
    class AccessControlEnabledTests {

        @BeforeEach
        void setUp() {
            accessControlProperties.setEnabled(true);
        }

        @Test
        @DisplayName("Should deny request when no session exists")
        void shouldDenyRequestWhenNoSessionExists() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of("admin"));
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(null);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Authentication required");
        }

        @Test
        @DisplayName("Should deny request when session has no authenticated user")
        void shouldDenyRequestWhenSessionHasNoAuthenticatedUser() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of("admin"));
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn(null);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Authentication required");
        }

        @Test
        @DisplayName("Should deny request when authenticated user is not a string")
        void shouldDenyRequestWhenAuthenticatedUserIsNotAString() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of("admin"));
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn(123);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Authentication required");
        }

        @Test
        @DisplayName("Should deny request when authenticated user is blank")
        void shouldDenyRequestWhenAuthenticatedUserIsBlank() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of("admin"));
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn("   ");

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Authentication required");
        }

        @Test
        @DisplayName("Should allow request when authenticated user is in allowed list")
        void shouldAllowRequestWhenAuthenticatedUserIsInAllowedList() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of("admin", "operator"));
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn("admin");

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should deny request when authenticated user is not in allowed list")
        void shouldDenyRequestWhenAuthenticatedUserIsNotInAllowedList() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of("admin", "operator"));
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn("user1");

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Insufficient privileges");
        }

        @Test
        @DisplayName("Should deny all requests when allowed list is empty (fail-closed)")
        void shouldDenyAllRequestsWhenAllowedListIsEmpty() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(List.of());
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn("admin");

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Insufficient privileges");
        }

        @Test
        @DisplayName("Should deny request when allowed list is null (fail-closed)")
        void shouldDenyRequestWhenAllowedListIsNull() throws Exception {
            // Arrange
            accessControlProperties.setAllowedSessionSubjects(null);
            AdminAccessInterceptor interceptor = new AdminAccessInterceptor(accessControlProperties);
            when(request.getSession(false)).thenReturn(session);
            when(session.getAttribute(AUTHENTICATED_USER_KEY)).thenReturn("admin");

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
            verify(response).sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Insufficient privileges");
        }
    }
}
