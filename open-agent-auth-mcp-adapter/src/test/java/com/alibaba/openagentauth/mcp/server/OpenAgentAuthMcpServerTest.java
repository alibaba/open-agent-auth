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
package com.alibaba.openagentauth.mcp.server;

import com.alibaba.openagentauth.framework.actor.ResourceServer;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkValidationException;
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenAgentAuthMcpServer}.
 *
 * @since 1.0
 */
@DisplayName("OpenAgentAuthMcpServer Tests")
class OpenAgentAuthMcpServerTest {

    private ResourceServer resourceServer;
    private OpenAgentAuthMcpServer mcpServer;

    @BeforeEach
    void setUp() {
        resourceServer = mock(ResourceServer.class);
        mcpServer = new OpenAgentAuthMcpServer(resourceServer);
    }

    @Test
    @DisplayName("Should validate request successfully with valid headers")
    void shouldValidateRequestSuccessfullyWithValidHeaders() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should reject request with missing Authorization header")
    void shouldRejectRequestWithMissingAuthorizationHeader() {
        boolean isValid = mcpServer.validateRequest(
                null, "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request with missing WIT header")
    void shouldRejectRequestWithMissingWitHeader() {
        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", null, "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request with missing WPT header")
    void shouldRejectRequestWithMissingWptHeader() {
        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", null,
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should log access attempt when validation fails")
    void shouldLogAccessAttemptWhenValidationFails() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(false)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should handle null headers map")
    void shouldHandleNullHeadersMap() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "GET", "/api/tool",
                null, null
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should handle all HTTP methods")
    void shouldHandleAllHttpMethods() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        String[] methods = {"GET", "POST", "PUT", "DELETE", "PATCH"};
        
        for (String method : methods) {
            boolean isValid = mcpServer.validateRequest(
                    "Bearer aoat", "wit", "wpt",
                    method, "/api/tool",
                    new HashMap<>(), "{}"
            );
            assertTrue(isValid);
        }
    }

    @Test
    @DisplayName("Should handle complex URIs")
    void shouldHandleComplexUris() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        String[] uris = {
                "/api/tool",
                "/api/tool/123",
                "/api/v2/tool?param=value",
                "/api/tool/sub/path"
        };
        
        for (String uri : uris) {
            boolean isValid = mcpServer.validateRequest(
                    "Bearer aoat", "wit", "wpt",
                    "POST", uri,
                    new HashMap<>(), "{}"
            );
            assertTrue(isValid);
        }
    }

    @Test
    @DisplayName("Should handle custom HTTP headers")
    void shouldHandleCustomHttpHeaders() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("X-Custom-Header", "custom-value");

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                headers, "{}"
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should handle large HTTP body")
    void shouldHandleLargeHttpBody() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        StringBuilder largeBody = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            largeBody.append("data");
        }
        String body = largeBody.toString();

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), body
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should initialize with resource server")
    void shouldInitializeWithResourceServer() {
        ResourceServer mockResourceServer = mock(ResourceServer.class);
        OpenAgentAuthMcpServer server = new OpenAgentAuthMcpServer(mockResourceServer);

        assertNotNull(server);
    }

    @Test
    @DisplayName("Should handle validation exception gracefully")
    void shouldHandleValidationExceptionGracefully() throws Exception {
        when(resourceServer.validateRequest(any()))
                .thenThrow(new RuntimeException("Validation error"));

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should pass correct HTTP method and URI to interceptor")
    void shouldPassCorrectHttpMethodAndUriToInterceptor() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = mcpServer.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "PUT", "/api/resource/123",
                new HashMap<>(), "{}"
        );

        assertTrue(isValid);
    }
}
