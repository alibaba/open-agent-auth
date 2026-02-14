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
package com.alibaba.openagentauth.sample.agent.service;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.sample.agent.adapter.ToolAdapter;
import com.alibaba.openagentauth.sample.agent.exception.AgentException;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.model.ToolResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tool adapter manager
 * 
 * Uses strategy pattern to manage registration, discovery and calling of all tool adapters,
 * implementing unified routing and result aggregation for tool calls
 */
@Service
public class ToolAdapterManager {
    
    private static final Logger log = LoggerFactory.getLogger(ToolAdapterManager.class);
    
    /**
     * Tool adapter mapping: serverName -> ToolAdapter
     */
    private final Map<String, ToolAdapter> adapters = new ConcurrentHashMap<>();
    
    /**
     * Register tool adapter
     * 
     * @param serverName Server name
     * @param adapter Tool adapter
     */
    public void registerAdapter(String serverName, ToolAdapter adapter) {
        ValidationUtils.validateNotNull(serverName, "Server name");
        ValidationUtils.validateNotNull(adapter, "Adapter");
        
        log.info("Registering tool adapter: {} with type: {}", serverName, adapter.getAdapterType());
        
        try {
            // Initialize adapter
            adapter.initialize();
            
            // Register adapter
            adapters.put(serverName, adapter);
            
            log.info("Tool adapter registered successfully: {}", serverName);
            
        } catch (Exception e) {
            log.error("Failed to register tool adapter: {}", serverName, e);
            throw new AgentException("REGISTRATION_FAILED", "Failed to register tool adapter: " + serverName, e);
        }
    }
    
    /**
     * Unregister tool adapter
     * 
     * @param serverName Server name
     */
    public void unregisterAdapter(String serverName) {
        log.info("Unregistering tool adapter: {}", serverName);
        
        ToolAdapter adapter = adapters.remove(serverName);
        if (adapter != null) {
            adapter.close();
            log.info("Tool adapter unregistered successfully: {}", serverName);
        }
    }
    
    /**
     * Get all tool definitions
     * 
     * @return Tool definition list
     */
    public List<ToolDefinition> getAllTools() {
        List<ToolDefinition> allTools = new ArrayList<>();
        
        for (ToolAdapter adapter : adapters.values()) {
            try {
                List<ToolDefinition> tools = adapter.listTools();
                allTools.addAll(tools);
            } catch (Exception e) {
                log.error("Failed to list tools from adapter: {}", adapter.getAdapterType(), e);
            }
        }
        
        return allTools;
    }
    
    /**
     * Get tool list by server name
     * 
     * @param serverName Server name
     * @return Tool definition list
     */
    public List<ToolDefinition> getToolsByServer(String serverName) {
        ToolAdapter adapter = adapters.get(serverName);
        if (adapter == null) {
            throw new AgentException("ADAPTER_NOT_FOUND", "Tool adapter not found for server: " + serverName);
        }
        
        return adapter.listTools();
    }
    
    /**
     * Call tool
     * 
     * @param serverName Server name
     * @param toolName Tool name
     * @param arguments Tool arguments
     * @return Tool execution result
     */
    public ToolResult callTool(String serverName, String toolName, Map<String, Object> arguments) {
        log.info("Calling tool: {} from server: {} with arguments: {}", toolName, serverName, arguments);
        
        ToolAdapter adapter = adapters.get(serverName);
        if (adapter == null) {
            log.error("Tool adapter not found for server: {}", serverName);
            return ToolResult.error("Tool adapter not found for server: " + serverName);
        }
        
        try {
            return adapter.callTool(toolName, arguments);
        } catch (Exception e) {
            log.error("Failed to call tool: {} from server: {}", toolName, serverName, e);
            return ToolResult.error("Failed to call tool: " + e.getMessage());
        }
    }
    
    /**
     * Get all registered adapters
     * 
     * @return Adapter mapping
     */
    public Map<String, ToolAdapter> getAdapters() {
        return Collections.unmodifiableMap(adapters);
    }
    
    /**
     * Check if adapter is registered
     * 
     * @param serverName Server name
     * @return Whether registered
     */
    public boolean isAdapterRegistered(String serverName) {
        return adapters.containsKey(serverName);
    }
}