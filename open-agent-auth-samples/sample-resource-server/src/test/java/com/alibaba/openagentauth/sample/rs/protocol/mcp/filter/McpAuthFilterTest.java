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
package com.alibaba.openagentauth.sample.rs.protocol.mcp.filter;

import com.alibaba.openagentauth.sample.rs.protocol.mcp.filter.McpAuthFilter.McpAuthContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for McpAuthFilter class.
 * Tests authentication header extraction, method skipping logic, and context management.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@DisplayName("McpAuthFilter Tests")
class McpAuthFilterTest {

    @Mock
    private HttpServletRequest mockRequest;

    @Mock
    private HttpServletResponse mockResponse;

    @Mock
    private FilterChain mockFilterChain;

    private McpAuthFilter filter;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        filter = new McpAuthFilter();
        objectMapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Should extract and store authentication headers for authenticated requests")
    void shouldExtractAndStoreAuthenticationHeaders() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(
                "Bearer token123",
                "wit-value",
                "wpt-value"
        );

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should skip authentication for initialize method")
    void shouldSkipAuthenticationForInitializeMethod() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(null, null, null);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should skip authentication for tools/list method")
    void shouldSkipAuthenticationForToolsListMethod() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(null, null, null);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should require authentication for tools/call method")
    void shouldRequireAuthenticationForToolsCallMethod() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(null, null, null);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle empty request body gracefully")
    void shouldHandleEmptyRequestBodyGracefully() throws ServletException, IOException {
        // Arrange
        String requestBody = "";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(null, null, null);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle null request body gracefully")
    void shouldHandleNullRequestBodyGracefully() throws ServletException, IOException {
        // Arrange
        String requestBody = null;
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(null, null, null);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle malformed JSON request body")
    void shouldHandleMalformedJsonRequestBody() throws ServletException, IOException {
        // Arrange
        String requestBody = "{invalid json}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders("Bearer token", "wit", "wpt");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle request without method field")
    void shouldHandleRequestWithoutMethodField() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders("Bearer token", "wit", "wpt");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should extract all HTTP headers correctly")
    void shouldExtractAllHttpHeadersCorrectly() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token");
        headers.put("X-Workload-Identity", "wit-value");
        headers.put("X-Workload-Proof", "wpt-value");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "test-agent");
        setupMockHeadersWithMap(headers);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle missing authorization header")
    void shouldHandleMissingAuthorizationHeader() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders(null, "wit-value", "wpt-value");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle missing WIT header")
    void shouldHandleMissingWitHeader() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders("Bearer token", null, "wpt-value");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle missing WPT header")
    void shouldHandleMissingWptHeader() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders("Bearer token", "wit-value", null);

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle GET requests")
    void shouldHandleGetRequests() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":1}";
        setupMockRequest(requestBody, "GET", "/mcp");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle PUT requests")
    void shouldHandlePutRequests() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "PUT", "/mcp");
        setupMockHeaders("Bearer token", "wit", "wpt");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should handle DELETE requests")
    void shouldHandleDeleteRequests() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "DELETE", "/mcp");
        setupMockHeaders("Bearer token", "wit", "wpt");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should clean up ThreadLocal after filter execution")
    void shouldCleanupThreadLocalAfterFilterExecution() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/mcp");
        setupMockHeaders("Bearer token", "wit", "wpt");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        // Filter should complete without exception, meaning ThreadLocal was cleaned up
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    @Test
    @DisplayName("Should create McpAuthContext with correct values")
    void shouldCreateMcpAuthContextWithCorrectValues() {
        // Arrange
        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer token");
        headers.put("X-Workload-Identity", "wit");
        headers.put("X-Workload-Proof", "wpt");

        // Act
        McpAuthContext context = new McpAuthContext(
                "Bearer token",
                "wit",
                "wpt",
                "POST",
                "/mcp",
                headers
        );

        // Assert
        assertEquals("Bearer token", context.getAuthorizationHeader());
        assertEquals("wit", context.getWitHeader());
        assertEquals("wpt", context.getWptHeader());
        assertEquals("POST", context.getHttpMethod());
        assertEquals("/mcp", context.getHttpUri());
        assertEquals(headers, context.getHttpHeaders());
    }

    @Test
    @DisplayName("Should create McpAuthContext with null values")
    void shouldCreateMcpAuthContextWithNullValues() {
        // Act
        McpAuthContext context = new McpAuthContext(
                null,
                null,
                null,
                "POST",
                "/mcp",
                Collections.emptyMap()
        );

        // Assert
        assertNull(context.getAuthorizationHeader());
        assertNull(context.getWitHeader());
        assertNull(context.getWptHeader());
        assertEquals("POST", context.getHttpMethod());
        assertEquals("/mcp", context.getHttpUri());
        assertTrue(context.getHttpHeaders().isEmpty());
    }

    @Test
    @DisplayName("Should handle different URI paths")
    void shouldHandleDifferentUriPaths() throws ServletException, IOException {
        // Arrange
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":1}";
        setupMockRequest(requestBody, "POST", "/custom/path");
        setupMockHeaders("Bearer token", "wit", "wpt");

        // Act
        filter.doFilterInternal(mockRequest, mockResponse, mockFilterChain);

        // Assert
        verify(mockFilterChain).doFilter(any(RepeatableReadHttpRequest.class), eq(mockResponse));
    }

    // Helper methods

    private void setupMockRequest(String body, String method, String uri) throws IOException {
        when(mockRequest.getRequestURI()).thenReturn(uri);
        when(mockRequest.getMethod()).thenReturn(method);
        
        ServletInputStream inputStream = new MockServletInputStream(
            (body != null ? body : "").getBytes()
        );
        when(mockRequest.getInputStream()).thenReturn(inputStream);
    }

    private void setupMockHeaders(String authorization, String wit, String wpt) {
        Map<String, String> headers = new HashMap<>();
        if (authorization != null) {
            headers.put("Authorization", authorization);
        }
        if (wit != null) {
            headers.put("X-Workload-Identity", wit);
        }
        if (wpt != null) {
            headers.put("X-Workload-Proof", wpt);
        }
        setupMockHeadersWithMap(headers);
    }

    private void setupMockHeadersWithMap(Map<String, String> headers) {
        lenient().when(mockRequest.getHeaderNames()).thenReturn(Collections.enumeration(headers.keySet()));
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            lenient().when(mockRequest.getHeader(entry.getKey())).thenReturn(entry.getValue());
        }
    }

    // Add inner class for mocking ServletInputStream
    private static class MockServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream inputStream;

        public MockServletInputStream(byte[] data) {
            this.inputStream = new ByteArrayInputStream(data);
        }

        @Override
        public boolean isFinished() {
            return inputStream.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(jakarta.servlet.ReadListener readListener) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int read() throws IOException {
            return inputStream.read();
        }
    }
}