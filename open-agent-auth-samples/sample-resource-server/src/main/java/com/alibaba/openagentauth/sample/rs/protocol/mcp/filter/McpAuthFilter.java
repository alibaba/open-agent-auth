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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * MCP Authentication Filter.
 * <p>
 * This filter extracts authentication headers from incoming HTTP requests
 * and stores them in ThreadLocal for later use by MCP tools.
 * Since the MCP SDK's McpSyncServerExchange does not provide direct access
 * to HTTP headers, and RequestContextHolder may not be available in async
 * execution contexts, we use ThreadLocal to store the authentication context.
 * </p>
 * <p>
 * <b>Authentication Headers:</b></p>
 * <ul>
 *   <li><b>Authorization:</b> Bearer {Agent OA Token}</li>
 *   <li><b>X-Workload-Identity:</b> {WIT}</li>
 *   <li><b>X-Workload-Proof:</b> {WPT}</li>
 * </ul>
 * <p>
 * <b>Authentication Exemptions:</b></p>
 * <p>
 * The following MCP method calls do not require authentication:
 * </p>
 * <ul>
 *   <li><b>initialize:</b> MCP client initialization handshake</li>
 *   <li><b>tools/list:</b> List available tools</li>
 * </ul>
 * <p>
 * <b>Important Note:</b></p>
 * In MCP streamable protocol, all requests are sent to the same endpoint
 * (typically /mcp). We identify the operation by parsing the JSON-RPC
 * method field from the request body.
 *
 * @since 1.0
 */
@Component
@Order(1)
public class McpAuthFilter extends OncePerRequestFilter {
    
    private static final Logger logger = LoggerFactory.getLogger(McpAuthFilter.class);
    
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_WORKLOAD_IDENTITY = "X-Workload-Identity";
    private static final String HEADER_WORKLOAD_PROOF = "X-Workload-Proof";
    
    // MCP methods that do not require authentication
    private static final String METHOD_INITIALIZE = "initialize";
    private static final String METHOD_TOOLS_LIST = "tools/list";
    
    // Request attribute key to store authentication context
    private static final String AUTH_CONTEXT_ATTRIBUTE = "com.alibaba.openagentauth.mcp.auth.context";
    
    // InheritableThreadLocal to store authentication context for async access
    private static final InheritableThreadLocal<McpAuthContext> AUTH_CONTEXT_HOLDER = 
        new InheritableThreadLocal<>();
    
    // ObjectMapper for JSON parsing
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        
        String requestUri = request.getRequestURI();
        String method = request.getMethod();
        
        logger.debug("Processing MCP request: {} {}", method, requestUri);
        
        // Wrap the request to allow multiple reads of the body
        RepeatableReadHttpRequest wrappedRequest = new RepeatableReadHttpRequest(request);
        
        // Skip authentication for initialize and tools/list calls
        if (shouldSkipAuthentication(wrappedRequest)) {
            logger.debug("Skipping authentication for exempted MCP method");
            filterChain.doFilter(wrappedRequest, response);
            return;
        }
        
        try {
            // Extract authentication headers
            String authorizationHeader = request.getHeader(HEADER_AUTHORIZATION);
            String witHeader = request.getHeader(HEADER_WORKLOAD_IDENTITY);
            String wptHeader = request.getHeader(HEADER_WORKLOAD_PROOF);
            
            // Extract all headers for validation
            Map<String, String> allHeaders = extractAllHeaders(request);
            
            // Store in request attribute for later use
            McpAuthContext context = new McpAuthContext(
                    authorizationHeader,
                    witHeader,
                    wptHeader,
                    method,
                    requestUri,
                    allHeaders
            );
            wrappedRequest.setAttribute(AUTH_CONTEXT_ATTRIBUTE, context);
            
            // Store in InheritableThreadLocal for async access
            AUTH_CONTEXT_HOLDER.set(context);
            
            logger.debug("Extracted MCP authentication headers - Authorization: {}, WIT: {}, WPT: {}",
                        authorizationHeader != null ? "present" : "missing",
                        witHeader != null ? "present" : "missing",
                        wptHeader != null ? "present" : "missing");
            
            // Continue filter chain with wrapped request
            filterChain.doFilter(wrappedRequest, response);
            
        } finally {
            // Clean up InheritableThreadLocal to prevent memory leaks
            AUTH_CONTEXT_HOLDER.remove();
        }
    }
    
    /**
     * Determines whether the current request should skip authentication.
     * <p>
     * MCP initialize and tools/list methods do not require authentication
     * as they are used for discovery and initialization purposes.
     * </p>
     * <p>
     * In MCP streamable protocol, all requests are sent to the same endpoint.
     * We identify the operation by parsing the JSON-RPC method field from
     * the request body.
     * </p>
     *
     * @param request the HTTP request
     * @return true if authentication should be skipped, false otherwise
     */
    private boolean shouldSkipAuthentication(HttpServletRequest request) {
        try {
            // Read request body to extract JSON-RPC method
            String requestBody = readRequestBody(request);
            if (ValidationUtils.isNullOrEmpty(requestBody)) {
                logger.debug("Empty request body, cannot determine method");
                return true;
            }
            
            // Parse JSON-RPC request using Jackson
            JsonNode jsonNode = objectMapper.readTree(requestBody);
            String rpcMethod = jsonNode.has("method") ? jsonNode.get("method").asText() : null;
            
            if (rpcMethod == null) {
                logger.debug("No method field in JSON-RPC request");
                return true;
            }
            
            // Skip authentication for initialize method
            if (METHOD_INITIALIZE.equals(rpcMethod)) {
                logger.debug("Skipping authentication for initialize method");
                return true;
            }
            
            // Skip authentication for tools/list method
            if (METHOD_TOOLS_LIST.equals(rpcMethod)) {
                logger.debug("Skipping authentication for tools/list method");
                return true;
            }
            
            logger.debug("MCP method requires authentication: {}", rpcMethod);
            return false;
            
        } catch (Exception e) {
            logger.warn("Failed to parse JSON-RPC method from request body: {}", e.getMessage());
            // If we cannot determine the method, require authentication for safety
            return false;
        }
    }
    
    /**
     * Reads the request body as a string.
     * <p>
     * This method reads the body from a RepeatableReadHttpRequest.
     * The wrapper caches the content in memory, allowing multiple reads.
     * </p>
     *
     * @param request the HTTP request (should be RepeatableReadHttpRequest)
     * @return the request body as a string, or null if reading fails
     */
    private String readRequestBody(HttpServletRequest request) {
        if (request instanceof RepeatableReadHttpRequest wrappedRequest) {
            return wrappedRequest.getBody();
        }
        
        logger.warn("Request is not a RepeatableReadHttpRequest, cannot read body");
        return null;
    }
    
    /**
     * Extracts all HTTP headers from the request.
     *
     * @param request the HTTP request
     * @return map of header names to values
     */
    private Map<String, String> extractAllHeaders(HttpServletRequest request) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            headers.put(headerName, headerValue);
        }
        
        return headers;
    }
    
    /**
     * Authentication context holder.
     */
    public static class McpAuthContext {
        private final String authorizationHeader;
        private final String witHeader;
        private final String wptHeader;
        private final String httpMethod;
        private final String httpUri;
        private final Map<String, String> httpHeaders;
        
        public McpAuthContext(String authorizationHeader, String witHeader, String wptHeader,
                             String httpMethod, String httpUri, Map<String, String> httpHeaders) {
            this.authorizationHeader = authorizationHeader;
            this.witHeader = witHeader;
            this.wptHeader = wptHeader;
            this.httpMethod = httpMethod;
            this.httpUri = httpUri;
            this.httpHeaders = httpHeaders;
        }
        
        public String getAuthorizationHeader() {
            return authorizationHeader;
        }
        
        public String getWitHeader() {
            return witHeader;
        }
        
        public String getWptHeader() {
            return wptHeader;
        }
        
        public String getHttpMethod() {
            return httpMethod;
        }
        
        public String getHttpUri() {
            return httpUri;
        }
        
        public Map<String, String> getHttpHeaders() {
            return httpHeaders;
        }
    }
}