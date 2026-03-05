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

import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
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

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AgentAuthenticationInterceptor}.
 *
 * @since 1.0
 */
@DisplayName("AgentAuthenticationInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class AgentAuthenticationInterceptorTest {

    @Mock
    private AgentAapExecutor agentAapExecutor;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private AgentAuthenticationInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new AgentAuthenticationInterceptor(
            agentAapExecutor,
            List.of("/login", "/callback", "/public/**")
        );
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
            AgentAuthenticationInterceptor interceptor = new AgentAuthenticationInterceptor(
                agentAapExecutor,
                null
            );

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("preHandle(HttpServletRequest, HttpServletResponse)")
    class PreHandle {

        @Test
        @DisplayName("Should delegate to AgentUserIdpUserAuthInterceptor")
        void shouldDelegateToAgentUserIdpUserAuthInterceptor() throws IOException {
            // Arrange
            when(request.getRequestURI()).thenReturn("/login");

            // Act
            boolean result = interceptor.preHandle(request, response);

            // Assert
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should throw runtime exception on error")
        void shouldThrowRuntimeExceptionOnError() {
            // Arrange
            when(request.getRequestURI()).thenThrow(new RuntimeException("Test error"));

            // Act & Assert
            assertThatThrownBy(() -> interceptor.preHandle(request, response))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Authentication check failed");
        }
    }
}