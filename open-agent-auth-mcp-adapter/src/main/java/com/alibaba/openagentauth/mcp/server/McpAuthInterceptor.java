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
import com.alibaba.openagentauth.framework.model.request.ResourceRequest;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkValidationException;
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * MCP Server authentication interceptor.
 * <p>
 * This interceptor validates MCP requests by extracting authentication
 * credentials from HTTP headers and performing the five-layer verification.
 * It acts as the first line of defense for MCP servers implementing
 * Agent Operation Authorization.
 * </p>
 * <p>
 * <b>Authentication Headers Required:</b></p>
 * <ul>
 *   <li><b>Authorization:</b> Bearer {Agent OA Token}</li>
 *   <li><b>X-Workload-Identity:</b> {WIT}</li>
 *   <li><b>X-Workload-Proof:</b> {WPT}</li>
 * </ul>
 *
 * @see ResourceServer
 * @since 1.0
 */
public class McpAuthInterceptor {
    
    private static final Logger logger = LoggerFactory.getLogger(McpAuthInterceptor.class);

    private static final String BEARER_PREFIX = "Bearer ";
    
    private final ResourceServer resourceServer;
    
    /**
     * Creates a new MCP authentication interceptor.
     *
     * @param resourceServer the resource server service for validation
     */
    public McpAuthInterceptor(ResourceServer resourceServer) {
        this.resourceServer = resourceServer;
        logger.info("McpAuthInterceptor initialized");
    }
    
    /**
     * Validates an MCP request by extracting authentication headers and
     * performing five-layer verification.
     *
     * @param authorizationHeader the Authorization header value
     * @param witHeader the X-Workload-Identity header value
     * @param wptHeader the X-Workload-Proof header value
     * @param httpMethod the HTTP method
     * @param httpUri the HTTP URI
     * @param httpHeaders the HTTP headers map
     * @param httpBody the HTTP body
     * @return true if validation succeeds, false otherwise
     */
    public boolean validateRequest(String authorizationHeader, String witHeader, String wptHeader,
                                   String httpMethod, String httpUri,
                                   java.util.Map<String, String> httpHeaders,
                                   String httpBody) {
        
        logger.info("Validating MCP request: {} {}", httpMethod, httpUri);
        
        // Extract tokens from headers
        String agentOaToken = extractBearerToken(authorizationHeader);
        String wit = witHeader;
        String wpt = wptHeader;
        
        // Validate required headers
        if (agentOaToken == null) {
            logger.error("Missing Authorization header");
            return false;
        }
        if (wit == null) {
            logger.error("Missing X-Workload-Identity header");
            return false;
        }
        if (wpt == null) {
            logger.error("Missing X-Workload-Proof header");
            return false;
        }
        
        // Build resource request
        ResourceRequest resourceRequest = ResourceRequest.builder()
                .wit(wit)
                .wpt(wpt)
                .aoat(agentOaToken)
                .httpMethod(httpMethod)
                .httpUri(httpUri)
                .httpHeaders(httpHeaders)
                .httpBody(httpBody)
                .build();
        
        // Perform five-layer verification
        try {
            logger.debug("Starting five-layer verification");
            ValidationResult validationResult = resourceServer.validateRequest(resourceRequest);
            
            if (validationResult.isValid()) {
                logger.info("MCP request validation successful");
                return true;
            } else {
                logger.error("MCP request validation failed: {}", validationResult.getErrors());
                return false;
            }
        } catch (FrameworkValidationException e) {
            logger.error("MCP request validation error: {}", e.getMessage(), e);
            return false;
        } catch (Exception e) {
            logger.error("Unexpected error during MCP request validation: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Extracts the Bearer token from the Authorization header.
     *
     * @param authorizationHeader the Authorization header value
     * @return the bearer token, or null if invalid
     */
    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return authorizationHeader.substring(BEARER_PREFIX.length());
    }
}
