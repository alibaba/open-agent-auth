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
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.web.interceptor.AgentUserIdpUserAuthInterceptor;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AgentUserIdpUserAuthInterceptor}.
 *
 * @since 1.0
 */
@DisplayName("AgentUserIdpUserAuthInterceptor Tests")
@ExtendWith(MockitoExtension.class)
class AgentUserIdpUserAuthInterceptorTest {

    @Mock
    private AgentAapExecutor agentAapExecutor;

    @Mock
    private SessionMappingBizService sessionMappingBizService;

    @Mock
    private HttpServletRequest request;

    private AgentUserIdpUserAuthInterceptor interceptor;

    @BeforeEach
    void setUp() {
        interceptor = new AgentUserIdpUserAuthInterceptor(
            sessionMappingBizService,
            List.of("/login", "/callback"),
            agentAapExecutor
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
    }

    @Nested
    @DisplayName("buildAuthorizationUrl(HttpServletRequest, String)")
    class BuildAuthorizationUrl {

        @Test
        @DisplayName("Should build authorization URL using AgentAapExecutor")
        void shouldBuildAuthorizationUrlUsingAgentAapExecutor() {
            // Arrange
            TestableAgentUserIdpUserAuthInterceptor testableInterceptor = 
                new TestableAgentUserIdpUserAuthInterceptor(
                    sessionMappingBizService,
                    List.of("/login", "/callback"),
                    agentAapExecutor
                );
            
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("");
            when(agentAapExecutor.initiateUserAuth(any(InitiateAuthorizationRequest.class)))
                .thenReturn("https://agent-idp.example.com/authorize?code=test123");

            // Act
            String authUrl = testableInterceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            assertThat(authUrl).isEqualTo("https://agent-idp.example.com/authorize?code=test123");
            verify(agentAapExecutor).initiateUserAuth(any(InitiateAuthorizationRequest.class));
        }

        @Test
        @DisplayName("Should build redirect URI with context path")
        void shouldBuildRedirectUriWithContextPath() {
            // Arrange
            TestableAgentUserIdpUserAuthInterceptor testableInterceptor = 
                new TestableAgentUserIdpUserAuthInterceptor(
                    sessionMappingBizService,
                    List.of("/login", "/callback"),
                    agentAapExecutor
                );
            
            when(request.getScheme()).thenReturn("https");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(443);
            when(request.getContextPath()).thenReturn("/app");
            when(agentAapExecutor.initiateUserAuth(any(InitiateAuthorizationRequest.class)))
                .thenReturn("https://agent-idp.example.com/authorize");

            // Act
            String authUrl = testableInterceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            verify(agentAapExecutor).initiateUserAuth(any(InitiateAuthorizationRequest.class));
        }

        @Test
        @DisplayName("Should build redirect URI with custom port")
        void shouldBuildRedirectUriWithCustomPort() {
            // Arrange
            TestableAgentUserIdpUserAuthInterceptor testableInterceptor = 
                new TestableAgentUserIdpUserAuthInterceptor(
                    sessionMappingBizService,
                    List.of("/login", "/callback"),
                    agentAapExecutor
                );
            
            when(request.getScheme()).thenReturn("http");
            when(request.getServerName()).thenReturn("example.com");
            when(request.getServerPort()).thenReturn(8080);
            when(request.getContextPath()).thenReturn("");
            when(agentAapExecutor.initiateUserAuth(any(InitiateAuthorizationRequest.class)))
                .thenReturn("https://agent-idp.example.com/authorize");

            // Act
            String authUrl = testableInterceptor.testBuildAuthorizationUrl(request, "test-state");

            // Assert
            verify(agentAapExecutor).initiateUserAuth(any(InitiateAuthorizationRequest.class));
        }
    }

    /**
     * Testable subclass that exposes protected methods for testing.
     */
    private static class TestableAgentUserIdpUserAuthInterceptor extends AgentUserIdpUserAuthInterceptor {
        public TestableAgentUserIdpUserAuthInterceptor(
                SessionMappingBizService sessionMappingBizService,
                List<String> excludedPaths,
                AgentAapExecutor agentAapExecutor) {
            super(sessionMappingBizService, excludedPaths, agentAapExecutor);
        }

        public String testBuildAuthorizationUrl(HttpServletRequest request, String state) {
            return buildAuthorizationUrl(request, state);
        }
    }
}
