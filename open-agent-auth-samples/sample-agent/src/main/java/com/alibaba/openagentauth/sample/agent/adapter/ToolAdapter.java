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
package com.alibaba.openagentauth.sample.agent.adapter;

import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.model.ToolResult;
import com.alibaba.openagentauth.mcp.client.McpAuthContext;

import java.util.List;
import java.util.Map;

/**
 * Tool adapter interface
 * 
 * Uses adapter pattern to unify different tool types (MCP, API),
 * implementing decoupling and extensibility of tool calls
 */
public interface ToolAdapter {
    
    /**
     * Get adapter type
     * 
     * @return Adapter type: mcp/api
     */
    String getAdapterType();
    
    /**
     * Get tool list
     * 
     * @return Tool definition list
     */
    List<ToolDefinition> listTools();
    
    /**
     * Call tool
     * 
     * @param toolName Tool name
     * @param arguments Tool arguments
     * @return Tool execution result
     */
    ToolResult callTool(String toolName, Map<String, Object> arguments);
    
    /**
     * Set auth context (for MCP adapter)
     * 
     * @param authContext Auth context
     */
    default void setAuthContext(McpAuthContext authContext) {
        // Default implementation: only MCP adapter needs auth context
    }
    
    /**
     * Initialize adapter
     * 
     * @throws Exception Throw exception when initialization fails
     */
    default void initialize() throws Exception {
        // Default implementation: no initialization needed
    }
    
    /**
     * Close adapter
     */
    default void close() {
        // Default implementation: no cleanup needed
    }
}
