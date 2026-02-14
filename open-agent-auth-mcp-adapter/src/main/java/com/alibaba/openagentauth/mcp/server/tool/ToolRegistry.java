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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for managing MCP tools.
 * <p>
 * This class provides a centralized repository for registering and managing
 * MCP tool implementations. It uses a thread-safe map to store tools and
 * provides methods for registration, retrieval, and listing of tools.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Factory Pattern - manages the creation and
 * lifecycle of tool instances.
 * </p>
 * <p>
 * <b>Thread Safety:</b> This class is thread-safe and can be used in
 * concurrent environments. It uses ConcurrentHashMap internally to
 * ensure thread-safe operations.
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * <pre>{@code
 * ToolRegistry registry = new ToolRegistry();
 * 
 * // Register tools
 * registry.register(new SearchProductsTool());
 * registry.register(new AddToCartTool());
 * 
 * // Get a tool by name
 * McpTool tool = registry.getTool("search_products");
 * if (tool != null) {
 *     tool.execute(arguments);
 * }
 * 
 * // List all registered tools
 * Collection<McpTool> allTools = registry.getAllTools();
 * }</pre>
 * </p>
 *
 * @see McpTool
 * @since 1.0
 */
public class ToolRegistry {
    
    private static final Logger logger = LoggerFactory.getLogger(ToolRegistry.class);
    
    /**
     * Thread-safe map storing registered tools by their names.
     * <p>
     * Key: Tool name (unique identifier)
     * Value: McpTool implementation
     * </p>
     */
    private final Map<String, McpTool> tools;
    
    /**
     * Creates a new empty tool registry.
     */
    public ToolRegistry() {
        this.tools = new ConcurrentHashMap<>();
        logger.debug("ToolRegistry initialized");
    }
    
    /**
     * Registers a tool with the registry.
     * <p>
     * If a tool with the same name is already registered, it will be
     * replaced with the new tool implementation. This allows for
     * tool updates without restarting the server.
     * </p>
     *
     * @param tool the tool to register
     * @throws IllegalArgumentException if the tool is null
     */
    public void register(McpTool tool) {
        ValidationUtils.validateNotNull(tool, "Tool");
        
        String toolName = tool.getName();
        if (ValidationUtils.isNullOrEmpty(toolName)) {
            throw new IllegalArgumentException("Tool name cannot be null or empty");
        }
        
        McpTool existingTool = tools.put(toolName, tool);
        
        if (existingTool == null) {
            logger.info("Registered new tool: {}", toolName);
        } else {
            logger.info("Replaced existing tool: {}", toolName);
        }
    }
    
    /**
     * Gets a tool by its name.
     *
     * @param name the name of the tool to retrieve
     * @return the tool if found, null otherwise
     */
    public McpTool getTool(String name) {
        if (ValidationUtils.isNullOrEmpty(name)) {
            return null;
        }
        return tools.get(name);
    }
    
    /**
     * Checks if a tool with the given name is registered.
     *
     * @param name the name of the tool to check
     * @return true if the tool is registered, false otherwise
     */
    public boolean hasTool(String name) {
        if (ValidationUtils.isNullOrEmpty(name)) {
            return false;
        }
        return tools.containsKey(name);
    }
    
    /**
     * Gets all registered tools.
     * <p>
     * The returned collection is a snapshot of the current tools and
     * will not reflect subsequent changes to the registry.
     * </p>
     *
     * @return a collection of all registered tools
     */
    public Collection<McpTool> getAllTools() {
        return tools.values();
    }
    
    /**
     * Gets the number of registered tools.
     *
     * @return the number of tools in the registry
     */
    public int size() {
        return tools.size();
    }
    
    /**
     * Checks if the registry is empty.
     *
     * @return true if no tools are registered, false otherwise
     */
    public boolean isEmpty() {
        return tools.isEmpty();
    }
    
    /**
     * Unregisters a tool by its name.
     *
     * @param name the name of the tool to unregister
     * @return the unregistered tool if found, null otherwise
     */
    public McpTool unregister(String name) {
        if (ValidationUtils.isNullOrEmpty(name)) {
            return null;
        }
        
        McpTool removedTool = tools.remove(name);
        if (removedTool != null) {
            logger.info("Unregistered tool: {}", name);
        }
        
        return removedTool;
    }
    
    /**
     * Clears all registered tools.
     * <p>
     * This method is primarily used for testing and cleanup purposes.
     * In production, tools should be managed through registration
     * and unregistration methods.
     * </p>
     */
    public void clear() {
        int size = tools.size();
        tools.clear();
        logger.info("Cleared {} tools from registry", size);
    }
}