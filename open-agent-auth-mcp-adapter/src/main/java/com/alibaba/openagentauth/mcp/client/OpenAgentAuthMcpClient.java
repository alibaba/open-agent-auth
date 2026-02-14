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

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Open Agent Auth MCP Client with Agent Operation Authorization support.
 * <p>
 * This class provides a wrapper around the MCP SDK's client to support
 * Agent Operation Authorization. It automatically injects authentication
 * credentials (AOAT, WIT, WPT) into each request using the
 * {@link AuthHeaderCustomizer}.
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * <pre>{@code
 * // Create MCP client
 * OpenAgentAuthMcpClient client = new OpenAgentAuthMcpClient();
 * McpSyncClient mcpClient = client.createHttpClient("https://mcp-server.example.com");
 * 
 * // Initialize client
 * client.initialize(mcpClient);
 * 
 * // Set authentication context
 * McpAuthContext authContext = new McpAuthContext(aoat, wit, wpt);
 * McpAuthContextHolder.setContext(authContext);
 * 
 * try {
 *     // Call tool
 *     McpSchema.CallToolResult result = client.callTool(mcpClient, "tool_name", arguments);
 * } finally {
 *     // Clear context
 *     McpAuthContextHolder.clearContext();
 * }
 * }</pre>
 * </p>
 *
 * @see McpAuthContext
 * @see McpAuthContextHolder
 * @see AuthHeaderCustomizer
 * @since 1.0
 */
public class OpenAgentAuthMcpClient {
    
    private static final Logger logger = LoggerFactory.getLogger(OpenAgentAuthMcpClient.class);
    private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration INITIALIZATION_TIMEOUT = Duration.ofSeconds(30);
    
    private Duration requestTimeout = DEFAULT_REQUEST_TIMEOUT;
    
    /**
     * Creates a new OpenAgentAuthMcpClient with default timeout.
     */
    public OpenAgentAuthMcpClient() {
        logger.info("OpenAgentAuthMcpClient created with default timeout: {}s", DEFAULT_REQUEST_TIMEOUT.getSeconds());
    }
    
    /**
     * Creates a new OpenAgentAuthMcpClient with custom request timeout.
     *
     * @param requestTimeout the request timeout
     */
    public OpenAgentAuthMcpClient(Duration requestTimeout) {
        this.requestTimeout = requestTimeout;
        logger.info("OpenAgentAuthMcpClient created with custom timeout: {}s", requestTimeout.getSeconds());
    }
    
    /**
     * Creates an MCP client for HTTP transport with authentication support.
     *
     * @param serverUrl the MCP server URL
     * @return the MCP client
     */
    public McpSyncClient createHttpClient(String serverUrl) {
        logger.info("Creating MCP HTTP client for server: {}", serverUrl);
        
        AuthHeaderCustomizer customizer = new AuthHeaderCustomizer();
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder(serverUrl)
                .asyncHttpRequestCustomizer(customizer)
                .build();
        
        McpSyncClient client = McpClient.sync(transport)
                .requestTimeout(requestTimeout)
                .build();
        
        logger.info("MCP HTTP client created successfully for server: {}", serverUrl);
        return client;
    }
    
    /**
     * Initializes the MCP client.
     *
     * @param client the MCP client
     * @return true if successful, false otherwise
     */
    public boolean initialize(McpSyncClient client) {
        logger.info("Starting MCP client initialization");
        
        try {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            Future<Boolean> future = executor.submit(() -> {
                try {
                    logger.debug("Calling client.initialize()");
                    McpSchema.InitializeResult result = client.initialize();
                    logger.info("MCP client initialized successfully with server: {} (version: {})",
                            result.serverInfo().name(), result.serverInfo().version());
                    return true;
                } catch (Exception e) {
                    logger.error("Failed to initialize MCP client in worker thread - Error: {}", 
                               e.getMessage(), e);
                    return false;
                }
            });
            
            // Wait for initialization to complete before shutting down the executor
            boolean success = future.get(INITIALIZATION_TIMEOUT.getSeconds(), TimeUnit.SECONDS);
            executor.shutdown();
            
            logger.info("MCP client initialization completed: {}", success ? "SUCCESS" : "FAILED");
            return success;
        } catch (Exception e) {
            logger.error("Failed to initialize MCP client - Error: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Lists available tools from the MCP server.
     *
     * @param client the MCP client
     * @return list of tools
     */
    public List<McpSchema.Tool> listTools(McpSyncClient client) {
        logger.info("Listing available tools from MCP server");
        
        try {
            McpSchema.ListToolsResult result = client.listTools();
            logger.info("Retrieved {} tools from MCP server", result.tools().size());
            
            if (logger.isDebugEnabled()) {
                for (McpSchema.Tool tool : result.tools()) {
                    logger.debug("Tool: {} - {}", tool.name(), tool.description());
                }
            }
            
            return result.tools();
        } catch (Exception e) {
            logger.error("Failed to list tools from MCP server - Error: {}", e.getMessage(), e);
            return List.of();
        }
    }
    
    /**
     * Calls a tool on the MCP server.
     *
     * @param client the MCP client
     * @param toolName the tool name
     * @param arguments the tool arguments
     * @return tool execution result
     */
    public McpSchema.CallToolResult callTool(McpSyncClient client, String toolName, 
                                             Map<String, Object> arguments) {
        logger.info("Calling tool: {} with arguments: {}", toolName, arguments);
        
        try {
            McpSchema.CallToolRequest request = new McpSchema.CallToolRequest(toolName, arguments);
            McpSchema.CallToolResult result = client.callTool(request);
            
            logger.info("Tool {} executed successfully - IsError: {}, ContentSize: {}",
                    toolName, result.isError(), 
                    result.content() != null ? result.content().size() : 0);
            
            return result;
        } catch (Exception e) {
            logger.error("Failed to call tool {} - Error: {}", toolName, e.getMessage(), e);
            throw new RuntimeException("Tool execution failed: " + e.getMessage(), e);
        }
    }
}
