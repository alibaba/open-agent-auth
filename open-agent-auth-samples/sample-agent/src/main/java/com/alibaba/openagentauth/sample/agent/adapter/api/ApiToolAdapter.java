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
package com.alibaba.openagentauth.sample.agent.adapter.api;

import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.sample.agent.adapter.ToolAdapter;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.model.ToolResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * API tool adapter implementation
 * 
 * Supports direct REST API calls, providing simple and lightweight tool calling
 */
public class ApiToolAdapter implements ToolAdapter {
    
    private static final Logger log = LoggerFactory.getLogger(ApiToolAdapter.class);
    
    /**
     * API server name
     */
    private final String serverName;
    
    /**
     * Service endpoint resolver for resolving endpoint URLs
     */
    private final ServiceEndpointResolver serviceEndpointResolver;
    
    /**
     * REST client
     */
    private final RestTemplate restTemplate;
    
    /**
     * Authentication token (optional)
     */
    private String authToken;
    
    /**
     * Tool definition list
     */
    private final List<ToolDefinition> tools;
    
    public ApiToolAdapter(String serverName, ServiceEndpointResolver serviceEndpointResolver, RestTemplate restTemplate) {
        this.serverName = serverName;
        this.serviceEndpointResolver = serviceEndpointResolver;
        this.restTemplate = restTemplate;
        this.tools = new ArrayList<>();
    }
    
    @Override
    public String getAdapterType() {
        return "api";
    }
    
    @Override
    public void initialize() throws Exception {
        log.info("Initializing API Tool Adapter for server: {}", serverName);
        
        // API adapter requires no special initialization
        log.info("API Tool Adapter initialized successfully for server: {}", serverName);
    }
    
    @Override
    public List<ToolDefinition> listTools() {
        if (!tools.isEmpty()) {
            return tools;
        }
        
        // If no predefined tools, return empty list
        // In practice, tools can be dynamically discovered by scanning API documentation or configuration
        log.info("No predefined tools for API server: {}", serverName);
        return tools;
    }
    
    @Override
    public ToolResult callTool(String toolName, Map<String, Object> arguments) {
        try {
            // Build API endpoint URL
            String url = buildApiUrl(toolName);
            log.info("Calling API tool: {} with URL: {} and arguments: {}", toolName, url, arguments);
            
            // Send HTTP request
            ResponseEntity<String> response = sendHttpRequest(url, arguments);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("API tool {} called successfully", toolName);
                return ToolResult.success(response.getBody());
            } else {
                log.error("API tool {} failed with status: {}", toolName, response.getStatusCode());
                return ToolResult.error("API call failed with status: " + response.getStatusCode());
            }
            
        } catch (Exception e) {
            log.error("Failed to call API tool: {}", toolName, e);
            return ToolResult.error("Failed to call API tool: " + e.getMessage());
        }
    }
    
    /**
     * Register tool definition
     */
    public void registerTool(String toolName, String description, String httpMethod, String endpoint) {
        ToolDefinition tool = new ToolDefinition();
        tool.setServerName(serverName);
        tool.setToolName(toolName);
        tool.setDescription(description);
        tool.setType("api");
        
        Map<String, Object> schema = new HashMap<>();
        schema.put("httpMethod", httpMethod);
        schema.put("endpoint", endpoint);
        tool.setInputSchema(schema);
        
        tools.add(tool);
        log.info("Registered API tool: {} for server: {}", toolName, serverName);
    }
    
    /**
     * Set authentication token
     */
    public void setAuthToken(String authToken) {
        this.authToken = authToken;
    }
    
    /**
     * Build API URL
     */
    private String buildApiUrl(String toolName) {
        // Find endpoint in tool definition
        for (ToolDefinition tool : tools) {
            if (tool.getToolName().equals(toolName) && tool.getInputSchema() != null) {
                Object endpoint = tool.getInputSchema().get("endpoint");
                if (endpoint != null) {
                    String serviceName = tool.getServerName();
                    String endpointKey = endpoint.toString();
                    return serviceEndpointResolver.resolveConsumer(serviceName, endpointKey);
                }
            }
        }
        
        // Default to using tool name as endpoint
        String serviceName = serverName;
        return serviceEndpointResolver.resolveConsumer(serviceName, toolName);
    }
    
    /**
     * Send HTTP request
     */
    private ResponseEntity<String> sendHttpRequest(String url, Map<String, Object> arguments) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        // Add authentication token
        if (authToken != null) {
            headers.setBearerAuth(authToken);
        }
        
        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(arguments, headers);
        return restTemplate.exchange(url, HttpMethod.POST, requestEntity, String.class);
    }
}
