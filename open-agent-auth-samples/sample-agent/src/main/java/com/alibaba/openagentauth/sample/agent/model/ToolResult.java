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

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Tool execution result
 * 
 * In MCP practice, tool results should be returned in structured JSON format
 * for better parsing and processing by MCP clients.
 */
public class ToolResult {
    
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Whether the execution was successful
     */
    private boolean success;
    
    /**
     * Result data
     * Can be either a String (for text content) or a Map/Object (for structured JSON data)
     */
    private Object data;
    
    /**
     * Error message (when execution fails)
     */
    private String error;
    
    public ToolResult() {
    }
    
    public ToolResult(boolean success, Object data) {
        this.success = success;
        this.data = data;
    }
    
    /**
     * Create a successful result with text content
     */
    public static ToolResult success(String data) {
        return new ToolResult(true, data);
    }
    
    /**
     * Create a successful result with structured JSON data
     */
    public static ToolResult success(Object data) {
        return new ToolResult(true, data);
    }
    
    /**
     * Create an error result
     */
    public static ToolResult error(String error) {
        ToolResult result = new ToolResult();
        result.setSuccess(false);
        result.setError(error);
        return result;
    }
    
    /**
     * Get data as string
     */
    public String getDataAsString() {
        if (data == null) {
            return null;
        }
        if (data instanceof String) {
            return (String) data;
        }
        try {
            return objectMapper.writeValueAsString(data);
        } catch (Exception e) {
            return data.toString();
        }
    }
    
    /**
     * Get data as object
     */
    public Object getData() {
        return data;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public void setData(Object data) {
        this.data = data;
    }
    
    public String getError() {
        return error;
    }
    
    public void setError(String error) {
        this.error = error;
    }
}