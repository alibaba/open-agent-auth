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
package com.alibaba.openagentauth.sample.agent.model;

import java.util.Map;

/**
 * Tool definition model
 */
public class ToolDefinition {
    
    /**
     * Tool server name
     */
    private String serverName;
    
    /**
     * Tool name
     */
    private String toolName;
    
    /**
     * Tool description
     */
    private String description;
    
    /**
     * Tool parameter definition (JSON Schema format)
     */
    private Map<String, Object> inputSchema;
    
    /**
     * Tool type: mcp/api
     */
    private String type;
    
    public ToolDefinition() {
    }
    
    public ToolDefinition(String serverName, String toolName, String description, String type) {
        this.serverName = serverName;
        this.toolName = toolName;
        this.description = description;
        this.type = type;
    }
    
    public String getServerName() {
        return serverName;
    }
    
    public void setServerName(String serverName) {
        this.serverName = serverName;
    }
    
    public String getToolName() {
        return toolName;
    }
    
    public void setToolName(String toolName) {
        this.toolName = toolName;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public Map<String, Object> getInputSchema() {
        return inputSchema;
    }
    
    public void setInputSchema(Map<String, Object> inputSchema) {
        this.inputSchema = inputSchema;
    }
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
}
