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
package com.alibaba.openagentauth.mcp.client;

import io.modelcontextprotocol.client.transport.customizer.McpAsyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.http.HttpRequest;

/**
 * MCP request customizer that adds authentication headers.
 * <p>
 * This customizer implements the {@link McpAsyncHttpClientRequestCustomizer}
 * interface to inject authentication headers into each MCP HTTP request.
 * It retrieves the authentication context from {@link McpAuthContextHolder}
 * and adds the following headers:
 * </p>
 * <ul>
 *   <li><b>Authorization:</b> Bearer {Agent OA Token}</li>
 *   <li><b>X-Workload-Identity:</b> {WIT}</li>
 *   <li><b>X-Workload-Proof:</b> {WPT}</li>
 * </ul>
 * <p>
 * This design ensures that each request carries fresh authentication
 * credentials from the ThreadLocal context, supporting concurrent
 * requests with different authentication contexts.
 * </p>
 *
 * @see McpAsyncHttpClientRequestCustomizer
 * @see McpAuthContextHolder
 * @since 1.0
 */
public class AuthHeaderCustomizer implements McpAsyncHttpClientRequestCustomizer {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthHeaderCustomizer.class);
    
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_WORKLOAD_IDENTITY = "X-Workload-Identity";
    private static final String HEADER_WORKLOAD_PROOF = "X-Workload-Proof";
    private static final String BEARER_PREFIX = "Bearer ";
    
    /**
     * Customizes the HTTP request builder by adding authentication headers.
     *
     * @param builder the HTTP request builder
     * @param method the HTTP method
     * @param uri the request URI
     * @param body the request body
     * @param context the request context
     * @return a Mono that completes with the customized builder
     */
    @Override
    public Mono<HttpRequest.Builder> customize(
            HttpRequest.Builder builder,
            String method,
            URI uri,
            String body,
            McpTransportContext context
    ) {
        McpAuthContext authContext = McpAuthContextHolder.getContext();
        if (authContext == null) {
            logger.warn("No authentication context found in ThreadLocal, " +
                       "request may be rejected by server");
        }
        
        if (authContext == null || !authContext.isValid()) {
            logger.warn("No valid authentication context found in ThreadLocal, " +
                       "request may be rejected by server");
            return Mono.just(builder);
        }

        logger.info("Beginning to customize HTTP request");
        try {
            // Add Authorization header with Bearer token
            if (authContext.getAgentOaToken() != null) {
                builder.setHeader(HEADER_AUTHORIZATION, BEARER_PREFIX + authContext.getAgentOaToken());
                logger.debug("Added {} header", HEADER_AUTHORIZATION);
            }
            
            // Add Workload Identity header
            if (authContext.getWit() != null) {
                builder.setHeader(HEADER_WORKLOAD_IDENTITY, authContext.getWit());
                logger.debug("Added {} header", HEADER_WORKLOAD_IDENTITY);
            }
            
            // Add Workload Proof header
            if (authContext.getWpt() != null) {
                builder.setHeader(HEADER_WORKLOAD_PROOF, authContext.getWpt());
                logger.debug("Added {} header", HEADER_WORKLOAD_PROOF);
            }
        } catch (Exception e) {
            logger.error("Failed to add authentication headers: {}", e.getMessage(), e);
        }
        
        return Mono.just(builder);
    }

}
