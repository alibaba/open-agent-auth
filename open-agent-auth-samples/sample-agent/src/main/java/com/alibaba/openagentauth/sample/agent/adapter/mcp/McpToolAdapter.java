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
package com.alibaba.openagentauth.sample.agent.adapter.mcp;

import com.alibaba.openagentauth.mcp.client.OpenAgentAuthMcpClient;
import com.alibaba.openagentauth.sample.agent.adapter.ToolAdapter;
import com.alibaba.openagentauth.sample.agent.exception.AgentException;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.model.ToolResult;
import com.alibaba.openagentauth.mcp.client.McpAuthContext;
import com.alibaba.openagentauth.mcp.client.McpAuthContextHolder;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP tool adapter implementation
 * 
 * Integrates MCP Adapter to provide unified tool call interface for MCP Server,
 * automatically handling injection and management of auth information
 */
public class McpToolAdapter implements ToolAdapter {
    
    private static final Logger log = LoggerFactory.getLogger(McpToolAdapter.class);
    
    /**
     * MCP server name
     */
    private final String serverName;
    
    /**
     * MCP server URL
     */
    private final String serverUrl;
    
    /**
     * MCP client
     */
    private final OpenAgentAuthMcpClient mcpClient;
    
    /**
     * Synchronous MCP client instance
     */
    private McpSyncClient syncClient;
    
    /**
     * Auth context
     */
    private McpAuthContext authContext;
    
    public McpToolAdapter(String serverName, String serverUrl, OpenAgentAuthMcpClient mcpClient) {
        this.serverName = serverName;
        this.serverUrl = serverUrl;
        this.mcpClient = mcpClient;
    }
    
    @Override
    public String getAdapterType() {
        return "mcp";
    }
    
    @Override
    public void initialize() throws Exception {
        log.info("Initializing MCP Tool Adapter for server: {}", serverName);
        
        // Create MCP client
        syncClient = mcpClient.createHttpClient(serverUrl);
        
        // Initialize connection
        boolean initialized = mcpClient.initialize(syncClient);
        if (!initialized) {
            throw new AgentException("INIT_FAILED", "Failed to initialize MCP client for server: " + serverName);
        }
        
        log.info("MCP Tool Adapter initialized successfully for server: {}", serverName);
    }
    
    @Override
    public List<ToolDefinition> listTools() {
        if (syncClient == null) {
            throw new AgentException("NOT_INITIALIZED", "MCP client not initialized for server: " + serverName);
        }
        
        try {
            List<McpSchema.Tool> mcpTools = mcpClient.listTools(syncClient);
            List<ToolDefinition> tools = new ArrayList<>();
            
            for (McpSchema.Tool mcpTool : mcpTools) {
                ToolDefinition tool = new ToolDefinition();
                tool.setServerName(serverName);
                tool.setToolName(mcpTool.name());
                tool.setDescription(mcpTool.description());
                tool.setType("mcp");
                
                // Convert input Schema
                if (mcpTool.inputSchema() != null) {
                    Map<String, Object> convertedSchema = convertInputSchema(mcpTool.inputSchema());
                    tool.setInputSchema(convertedSchema);
                    log.info("Tool: {}, Description: {}, InputSchema: {}", 
                            mcpTool.name(), mcpTool.description(), convertedSchema);
                }
                
                tools.add(tool);
            }
            
            log.info("Listed {} tools from MCP server: {}", tools.size(), serverName);
            return tools;
            
        } catch (Exception e) {
            log.error("Failed to list tools from MCP server: {}", serverName, e);
            throw new AgentException("LIST_TOOLS_FAILED", "Failed to list tools from MCP server: " + serverName, e);
        }
    }
    
    @Override
    public ToolResult callTool(String toolName, Map<String, Object> arguments) {
        if (syncClient == null) {
            return ToolResult.error("MCP client not initialized for server: " + serverName);
        }
        
        try {
            // Check if auth context is available in ThreadLocal (set by EnhancedAgentService)
            McpAuthContext context = McpAuthContextHolder.getContext();
            if (context != null) {
                log.info("Found auth context in ThreadLocal: aoat={}, wit={}, wpt={}", 
                        context.getAgentOaToken() != null ? "***" : null,
                        context.getWit() != null ? "***" : null,
                        context.getWpt() != null ? "***" : null);
            } else {
                log.warn("No auth context found in ThreadLocal, request may be rejected by server");
            }
            
            log.info("Calling MCP tool: {} from server: {} with arguments: {}", toolName, serverName, arguments);
            
            // Call MCP tool
            McpSchema.CallToolResult result = mcpClient.callTool(syncClient, toolName, arguments);
            
            // Extract result content
            Object resultContent = extractResultContent(result);
            
            log.info("MCP tool {} called successfully from server: {}", toolName, serverName);
            return ToolResult.success(resultContent);
            
        } catch (Exception e) {
            log.error("Failed to call MCP tool: {} from server: {}", toolName, serverName, e);
            return ToolResult.error("Failed to call tool: " + e.getMessage());
        } finally {
            // Clean up ThreadLocal
            McpAuthContextHolder.clearContext();
        }
    }
    
    @Override
    public void setAuthContext(McpAuthContext authContext) {
        this.authContext = authContext;
    }
    
    @Override
    public void close() {
        if (syncClient != null) {
            try {
                syncClient.close();
                log.info("MCP client closed for server: {}", serverName);
            } catch (Exception e) {
                log.error("Failed to close MCP client for server: {}", serverName, e);
            }
        }
    }
    
    /**
     * Convert MCP input Schema
     */
    private Map<String, Object> convertInputSchema(McpSchema.JsonSchema schema) {
        Map<String, Object> result = new HashMap<>();
        
        if (schema.type() != null) {
            result.put("type", schema.type());
        }
        
        if (schema.properties() != null) {
            result.put("properties", schema.properties());
        }
        
        if (schema.required() != null) {
            result.put("required", schema.required());
        }
        
        // JsonSchema may not have description method, skip this field
        // If description is needed, it can be obtained from other sources
        
        log.debug("Converted input schema for tool: {}", result);
        
        return result;
    }
    
    /**
     * Extract tool execution result content
     * 
     * Supports both TextContent and ImageContent, and returns structured JSON when possible
     */
    private Object extractResultContent(McpSchema.CallToolResult result) {
        if (result.content() == null || result.content().isEmpty()) {
            return "";
        }
        
        // If there's only one content item, return it directly
        if (result.content().size() == 1) {
            Object item = result.content().get(0);
            if (item instanceof io.modelcontextprotocol.spec.McpSchema.TextContent textContent) {
                return textContent.text();
            } else if (item instanceof io.modelcontextprotocol.spec.McpSchema.ImageContent imageContent) {
                return imageContent.data();
            } else {
                // Try to return structured data if available
                return item;
            }
        }
        
        // Multiple content items - build a list
        List<Object> contentList = new ArrayList<>();
        for (Object item : result.content()) {
            if (item instanceof io.modelcontextprotocol.spec.McpSchema.TextContent textContent) {
                contentList.add(textContent.text());
            } else if (item instanceof io.modelcontextprotocol.spec.McpSchema.ImageContent imageContent) {
                contentList.add(imageContent.data());
            } else {
                contentList.add(item);
            }
        }
        
        return contentList;
    }
}