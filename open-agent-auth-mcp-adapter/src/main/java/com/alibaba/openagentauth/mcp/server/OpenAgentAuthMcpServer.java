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
import com.alibaba.openagentauth.framework.model.audit.AuditLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Open Agent Auth MCP Server with Agent Operation Authorization support.
 * <p>
 * This class provides a wrapper around MCP server implementations to support
 * Agent Operation Authorization. It intercepts all incoming MCP requests
 * and validates them using the five-layer verification architecture.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Automatic extraction of authentication headers from HTTP requests</li>
 *   <li>Five-layer verification using {@link ResourceServer}</li>
 *   <li>Audit logging for all access attempts</li>
 *   <li>Seamless integration with MCP SDK server implementations</li>
 * </ul>
 *
 * @see McpAuthInterceptor
 * @see ResourceServer
 * @since 1.0
 */
public class OpenAgentAuthMcpServer {
    
    private static final Logger logger = LoggerFactory.getLogger(OpenAgentAuthMcpServer.class);
    
    private final McpAuthInterceptor authInterceptor;
    private final ResourceServer resourceServer;
    
    /**
     * Creates a new Open Agent Auth MCP Server.
     *
     * @param resourceServer the resource server service for validation
     */
    public OpenAgentAuthMcpServer(ResourceServer resourceServer) {
        this.resourceServer = resourceServer;
        this.authInterceptor = new McpAuthInterceptor(resourceServer);
        logger.info("OpenAgentAuthMcpServer initialized");
    }
    
    /**
     * Validates an MCP request before allowing tool execution.
     * <p>
     * This method extracts authentication headers from the HTTP request
     * and performs the five-layer verification. If validation fails,
     * the request is rejected and an audit log is created.
     * </p>
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
        
        logger.debug("Validating MCP request: {} {}", httpMethod, httpUri);
        
        boolean isValid = authInterceptor.validateRequest(
                authorizationHeader, witHeader, wptHeader,
                httpMethod, httpUri, httpHeaders, httpBody
        );
        
        if (!isValid) {
            // Log denied access attempt
            logAccessAttempt(authorizationHeader, witHeader, httpMethod, httpUri, false, 
                           "Authentication validation failed");
        }
        
        return isValid;
    }
    
    /**
     * Logs an access attempt for audit purposes.
     *
     * @param authorizationHeader the Authorization header value
     * @param witHeader the X-Workload-Identity header value
     * @param httpMethod the HTTP method
     * @param httpUri the HTTP URI
     * @param allowed whether the access was allowed
     * @param reason the reason for the decision
     */
    private void logAccessAttempt(String authorizationHeader, String witHeader,
                                   String httpMethod, String httpUri,
                                   boolean allowed, String reason) {
        try {
            AuditLogEntry auditLog = AuditLogEntry.builder()
                    .timestamp(java.time.Instant.now())
                    .decision(allowed ? "ALLOW" : "DENY")
                    .reason(reason)
                    .operationType(httpMethod)
                    .resourceId(httpUri)
                    .build();
            
            resourceServer.logAccess(auditLog);
            logger.debug("Access attempt logged: {}", allowed ? "ALLOWED" : "DENIED");
        } catch (Exception e) {
            logger.error("Failed to log access attempt: {}", e.getMessage(), e);
        }
    }
}
