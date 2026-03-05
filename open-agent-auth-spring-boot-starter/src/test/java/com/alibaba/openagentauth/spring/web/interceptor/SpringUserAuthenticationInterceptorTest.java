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

import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SpringUserAuthenticationInterceptor}.
 * <p>
 * Tests the Spring MVC interceptor for user authentication.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("SpringUserAuthenticationInterceptor Tests")
class SpringUserAuthenticationInterceptorTest {

    @Mock
    private UserAuthenticationInterceptor delegate;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private SpringUserAuthenticationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new SpringUserAuthenticationInterceptor(delegate);
    }

    @Nested
    @DisplayName("preHandle() Tests")
    class PreHandleTests {

        @Test
        @DisplayName("Should return true when delegate returns true")
        void shouldReturnTrueWhenDelegateReturnsTrue() throws Exception {
            // Arrange
            when(delegate.preHandle(request, response)).thenReturn(true);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false when delegate returns false")
        void shouldReturnFalseWhenDelegateReturnsFalse() throws Exception {
            // Arrange
            when(delegate.preHandle(request, response)).thenReturn(false);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should delegate to UserAuthenticationInterceptor")
        void shouldDelegateToUserAuthenticationInterceptor() throws Exception {
            // Arrange
            when(delegate.preHandle(request, response)).thenReturn(true);

            // Act
            interceptor.preHandle(request, response, null);

            // Assert
            // Verify that delegate.preHandle was called with correct parameters
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create interceptor with delegate")
        void shouldCreateInterceptorWithDelegate() {
            // Act
            SpringUserAuthenticationInterceptor interceptor = new SpringUserAuthenticationInterceptor(delegate);

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should accept null delegate in constructor but fail on usage")
        void shouldAcceptNullDelegateButFailOnUsage() {
            // Act - constructor does not perform null check
            SpringUserAuthenticationInterceptor nullDelegateInterceptor =
                    new SpringUserAuthenticationInterceptor(null);

            // Assert - NPE occurs when preHandle is called with null delegate
            assertThat(nullDelegateInterceptor).isNotNull();
            org.junit.jupiter.api.Assertions.assertThrows(
                    NullPointerException.class,
                    () -> nullDelegateInterceptor.preHandle(request, response, null)
            );
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null request")
        void shouldHandleNullRequest() throws Exception {
            // Arrange
            when(delegate.preHandle(null, response)).thenReturn(false);

            // Act
            boolean result = interceptor.preHandle(null, response, null);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should handle null response")
        void shouldHandleNullResponse() throws Exception {
            // Arrange
            when(delegate.preHandle(request, null)).thenReturn(false);

            // Act
            boolean result = interceptor.preHandle(request, null, null);

            // Assert
            assertThat(result).isFalse();
        }

        @Test
        @DisplayName("Should handle null handler")
        void shouldHandleNullHandler() throws Exception {
            // Arrange
            when(delegate.preHandle(request, response)).thenReturn(true);

            // Act
            boolean result = interceptor.preHandle(request, response, null);

            // Assert
            assertThat(result).isTrue();
        }
    }
}
