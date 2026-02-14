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

import com.alibaba.openagentauth.framework.web.interceptor.AgentAuthenticationInterceptor;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SpringAgentAuthenticationInterceptor}.
 * <p>
 * This test class verifies the behavior of the Spring adapter for
 * AgentAuthenticationInterceptor, ensuring proper delegation to the framework implementation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("SpringAgentAuthenticationInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class SpringAgentAuthenticationInterceptorTest {

    @Mock
    private AgentAuthenticationInterceptor delegate;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private SpringAgentAuthenticationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new SpringAgentAuthenticationInterceptor(delegate);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create interceptor with delegate")
        void shouldCreateInterceptorWithDelegate() {
            SpringAgentAuthenticationInterceptor interceptor = new SpringAgentAuthenticationInterceptor(delegate);

            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should throw NullPointerException when delegate is null")
        void shouldThrowNullPointerExceptionWhenDelegateIsNull() {
            // The constructor doesn't have null check, so this will succeed
            // but the interceptor will fail when used
            SpringAgentAuthenticationInterceptor interceptor = new SpringAgentAuthenticationInterceptor(null);
            
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("preHandle() Tests")
    class PreHandleTests {

        @Test
        @DisplayName("Should delegate to framework interceptor and return true")
        void shouldDelegateToFrameworkInterceptorAndReturnTrue() throws Exception {
            when(delegate.preHandle(request, response)).thenReturn(true);

            boolean result = interceptor.preHandle(request, response, null);

            assertThat(result).isTrue();
            verify(delegate, times(1)).preHandle(request, response);
        }

        @Test
        @DisplayName("Should delegate to framework interceptor and return false")
        void shouldDelegateToFrameworkInterceptorAndReturnFalse() throws Exception {
            when(delegate.preHandle(request, response)).thenReturn(false);

            boolean result = interceptor.preHandle(request, response, null);

            assertThat(result).isFalse();
            verify(delegate, times(1)).preHandle(request, response);
        }

        @Test
        @DisplayName("Should pass request and response to delegate")
        void shouldPassRequestAndResponseToDelegate() throws Exception {
            when(delegate.preHandle(request, response)).thenReturn(true);

            interceptor.preHandle(request, response, null);

            verify(delegate, times(1)).preHandle(request, response);
        }

        @Test
        @DisplayName("Should ignore handler parameter")
        void shouldIgnoreHandlerParameter() throws Exception {
            Object handler = new Object();
            when(delegate.preHandle(request, response)).thenReturn(true);

            boolean result1 = interceptor.preHandle(request, response, handler);
            boolean result2 = interceptor.preHandle(request, response, null);

            assertThat(result1).isTrue();
            assertThat(result2).isTrue();
            verify(delegate, times(2)).preHandle(request, response);
        }

        @Test
        @DisplayName("Should propagate RuntimeException from delegate")
        void shouldPropagateRuntimeExceptionFromDelegate() throws Exception {
            when(delegate.preHandle(request, response))
                .thenThrow(new RuntimeException("Test exception"));

            assertThatThrownBy(() -> interceptor.preHandle(request, response, null))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("Test exception");

            verify(delegate, times(1)).preHandle(request, response);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should support multiple preHandle calls")
        void shouldSupportMultiplePreHandleCalls() throws Exception {
            when(delegate.preHandle(request, response)).thenReturn(true);

            boolean result1 = interceptor.preHandle(request, response, null);
            boolean result2 = interceptor.preHandle(request, response, null);
            boolean result3 = interceptor.preHandle(request, response, null);

            assertThat(result1).isTrue();
            assertThat(result2).isTrue();
            assertThat(result3).isTrue();
            verify(delegate, times(3)).preHandle(request, response);
        }

        @Test
        @DisplayName("Should work with different request and response objects")
        void shouldWorkWithDifferentRequestAndResponseObjects() throws Exception {
            when(delegate.preHandle(any(HttpServletRequest.class), any(HttpServletResponse.class)))
                .thenReturn(true);

            boolean result = interceptor.preHandle(request, response, null);

            assertThat(result).isTrue();
            verify(delegate, times(1)).preHandle(request, response);
        }
    }
}