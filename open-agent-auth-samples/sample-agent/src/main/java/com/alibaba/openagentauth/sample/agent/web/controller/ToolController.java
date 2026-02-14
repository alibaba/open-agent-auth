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
package com.alibaba.openagentauth.sample.agent.web.controller;

import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.service.ToolAdapterManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Tool management Web controller
 * 
 * Provides tool query and registration APIs
 */
@RestController
public class ToolController {
    
    private static final Logger log = LoggerFactory.getLogger(ToolController.class);
    
    private final ToolAdapterManager toolAdapterManager;
    
    public ToolController(ToolAdapterManager toolAdapterManager) {
        this.toolAdapterManager = toolAdapterManager;
    }
    
    /**
     * Get all tools
     */
    @GetMapping("/api/tools")
    public List<ToolDefinition> getAllTools() {
        log.info("Getting all tools");
        return toolAdapterManager.getAllTools();
    }
    
    /**
     * Get tools for a specific server
     */
    @GetMapping("/api/tools/server/{serverName}")
    public List<ToolDefinition> getToolsByServer(@PathVariable String serverName) {
        log.info("Getting tools for server: {}", serverName);
        return toolAdapterManager.getToolsByServer(serverName);
    }
    
    /**
     * Call tool (manual call for debugging)
     */
    @PostMapping("/api/tools/call")
    public Map<String, Object> callTool(@RequestBody ToolCallRequest request) {
        log.info("Manual tool call: server={}, tool={}", request.getServerName(), request.getToolName());
        
        Map<String, Object> result = new java.util.HashMap<>();
        result.put("serverName", request.getServerName());
        result.put("toolName", request.getToolName());
        result.put("arguments", request.getArguments());
        result.put("result", toolAdapterManager.callTool(
                request.getServerName(), 
                request.getToolName(), 
                request.getArguments()
        ));
        
        return result;
    }
    
    /**
     * Tool call request
     */
    public static class ToolCallRequest {
        private String serverName;
        private String toolName;
        private Map<String, Object> arguments;
        
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
        
        public Map<String, Object> getArguments() {
            return arguments;
        }
        
        public void setArguments(Map<String, Object> arguments) {
            this.arguments = arguments;
        }
    }
}
