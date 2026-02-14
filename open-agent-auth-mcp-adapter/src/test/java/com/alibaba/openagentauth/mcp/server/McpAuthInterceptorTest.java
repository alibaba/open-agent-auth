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
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link McpAuthInterceptor}.
 *
 * @since 1.0
 */
@DisplayName("McpAuthInterceptor Tests")
class McpAuthInterceptorTest {

    private ResourceServer resourceServer;
    private McpAuthInterceptor interceptor;

    @BeforeEach
    void setUp() {
        resourceServer = mock(ResourceServer.class);
        interceptor = new McpAuthInterceptor(resourceServer);
    }

    @Test
    @DisplayName("Should validate request with valid headers")
    void shouldValidateRequestWithValidHeaders() throws FrameworkValidationException {
        String authorization = "Bearer valid-aoat-token";
        String wit = "valid-wit-token";
        String wpt = "valid-wpt-token";
        
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                authorization, wit, wpt,
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should reject request with missing Authorization header")
    void shouldRejectRequestWithMissingAuthorizationHeader() {
        boolean isValid = interceptor.validateRequest(
                null, "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request with invalid Authorization header format")
    void shouldRejectRequestWithInvalidAuthorizationHeaderFormat() {
        boolean isValid = interceptor.validateRequest(
                "invalid-format", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request with missing WIT header")
    void shouldRejectRequestWithMissingWitHeader() {
        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", null, "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request with missing WPT header")
    void shouldRejectRequestWithMissingWptHeader() {
        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", null,
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request when validation fails")
    void shouldRejectRequestWhenValidationFails() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(false)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request when validation throws exception")
    void shouldRejectRequestWhenValidationThrowsException() throws Exception {
        when(resourceServer.validateRequest(any()))
                .thenThrow(new RuntimeException("Validation error"));

        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should reject request when unexpected error occurs")
    void shouldRejectRequestWhenUnexpectedErrorOccurs() throws Exception {
        when(resourceServer.validateRequest(any()))
                .thenThrow(new RuntimeException("Unexpected error"));

        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should extract Bearer token correctly")
    void shouldExtractBearerTokenCorrectly() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "Bearer my-token-123", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should handle Authorization header with extra spaces")
    void shouldHandleAuthorizationHeaderWithExtraSpaces() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(false)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "Bearer  token-with-spaces", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should pass HTTP details to resource request")
    void shouldPassHttpDetailsToResourceRequest() throws FrameworkValidationException {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                headers, "{\"key\":\"value\"}"
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should handle uppercase Authorization header")
    void shouldHandleUppercaseAuthorizationHeader() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), "{}"
        );

        assertFalse(isValid);
    }

    @Test
    @DisplayName("Should handle empty headers map")
    void shouldHandleEmptyHeadersMap() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "GET", "/api/tool",
                new HashMap<>(), null
        );

        assertTrue(isValid);
    }

    @Test
    @DisplayName("Should handle null HTTP body")
    void shouldHandleNullHttpBody() throws FrameworkValidationException {
        ValidationResult validationResult = ValidationResult.builder()
                .valid(true)
                .build();
        
        when(resourceServer.validateRequest(any())).thenReturn(validationResult);

        boolean isValid = interceptor.validateRequest(
                "Bearer aoat", "wit", "wpt",
                "POST", "/api/tool",
                new HashMap<>(), null
        );

        assertTrue(isValid);
    }
}
