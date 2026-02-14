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
package com.alibaba.openagentauth.mcp.server.tool;

import io.modelcontextprotocol.spec.McpSchema;

import java.util.Map;

/**
 * Interface for MCP tool implementations.
 * <p>
 * This interface defines the contract for tools that can be registered
 * with an MCP Server. Each tool represents a specific capability or
 * operation that can be invoked by AI agents through the MCP protocol.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern - allows different tool
 * implementations to be plugged into the MCP Server without modifying
 * the server code.
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * <pre>{@code
 * public class SearchProductsTool implements McpTool {
 *     @Override
 *     public McpSchema.Tool getDefinition() {
 *         return new McpSchema.Tool(
 *             "search_products",
 *             "Search for products by category and keywords",
 *             new McpSchema.JsonSchema(...)
 *         );
 *     }
 *     
 *     @Override
 *     public McpSchema.CallToolResult execute(Map<String, Object> arguments) {
 *         // Tool implementation logic
 *         return new McpSchema.CallToolResult(...);
 *     }
 * }
 * }</pre>
 * </p>
 *
 * @see ToolRegistry
 * @see AbstractOpenAgentAuthMcpServer
 * @since 1.0
 */
public interface McpTool {
    
    /**
     * Gets the tool definition for MCP registration.
     * <p>
     * This method returns the tool metadata including name, description,
     * and input schema that will be used to register the tool with the
     * MCP Server.
     * </p>
     *
     * @return the tool definition
     */
    McpSchema.Tool getDefinition();
    
    /**
     * Executes the tool with the given arguments.
     * <p>
     * This method contains the actual implementation of the tool logic.
     * It receives the arguments passed by the AI agent and returns
     * the execution result.
     * </p>
     * <p>
     * <b>Implementation Notes:</b>
     * <ul>
     *   <li>Always validate input arguments before processing</li>
     *   <li>Handle exceptions gracefully and return appropriate error messages</li>
     *   <li>Log important operations for debugging and auditing</li>
     *   <li>Return results in a structured format that agents can understand</li>
     * </ul>
     * </p>
     *
     * @param arguments the tool arguments passed by the AI agent
     * @return the tool execution result
     * @throws IllegalArgumentException if arguments are invalid
     * @throws RuntimeException if tool execution fails
     */
    McpSchema.CallToolResult execute(Map<String, Object> arguments);
    
    /**
     * Gets the unique name of this tool.
     * <p>
     * The tool name is used as the identifier for registration and
     * invocation. It must be unique within a single MCP Server.
     * </p>
     *
     * @return the tool name
     */
    String getName();
    
    /**
     * Gets the description of this tool.
     * <p>
     * The description helps AI agents understand what this tool does
     * and when to use it.
     * </p>
     *
     * @return the tool description
     */
    default String getDescription() {
        McpSchema.Tool definition = getDefinition();
        return definition != null ? definition.description() : "";
    }
}
