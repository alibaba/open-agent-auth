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
package com.alibaba.openagentauth.sample.rs.protocol.mcp.config;

import com.alibaba.openagentauth.framework.actor.ResourceServer;
import com.alibaba.openagentauth.framework.model.request.ResourceRequest;
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import com.alibaba.openagentauth.mcp.server.tool.McpTool;
import com.alibaba.openagentauth.sample.rs.protocol.mcp.tool.AddToCartTool;
import com.alibaba.openagentauth.sample.rs.protocol.mcp.tool.PurchaseProductTool;
import com.alibaba.openagentauth.sample.rs.protocol.mcp.tool.QueryOrdersTool;
import com.alibaba.openagentauth.sample.rs.protocol.mcp.tool.SearchProductsTool;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * MCP Server configuration for shopping service.
 * <p>
 * This class configures a compliant MCP Server using the MCP Java SDK.
 * It uses Streamable HTTP transport with context extractor for authentication.
 * All tools are registered using the standard MCP SDK mechanism.
 * </p>
 * <p>
 * <b>MCP Protocol Compliance:</b></p>
 * <ul>
 *   <li>Uses McpServer.sync() to create a synchronous MCP server</li>
 *   <li>Uses {@link HttpServletStreamableServerTransportProvider} for Streamable HTTP transport</li>
 *   <li>Uses context extractor to extract authentication context from HTTP request</li>
 *   <li>Registers tools using {@link McpServerFeatures.SyncToolSpecification}</li>
 *   <li>Implements tool execution with {@link BiFunction}<McpSyncServerExchange, Map, McpSchema.CallToolResult></li>
 *   <li>Sets server capabilities using {@link McpSchema.ServerCapabilities}</li>
 * </ul>
 * <p>
 * <b>Authentication:</b></p>
 * Authentication headers are extracted from HTTP requests using the standard
 * MCP {@link McpTransportContext} mechanism. The context extractor captures
 * authentication headers (Authorization, X-Workload-Identity, X-Workload-Proof)
 * and makes them available to tools via {@link McpSyncServerExchange#transportContext()}.
 * This ensures proper isolation between requests in Streamable HTTP scenarios.
 *
 * @since 1.0
 */
@Configuration
public class ShoppingMcpServerConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(ShoppingMcpServerConfig.class);
    
    private static final String SERVER_NAME = "shopping";
    private static final String SERVER_VERSION = "1.0.0";
    
    /**
     * Creates the Streamable HTTP transport provider for MCP communication.
     * <p>
     * This provider handles Streamable HTTP transport with context extractor
     * for authentication. The context extractor extracts HTTP headers and
     * makes them available via McpTransportContext in tool handlers.
     * </p>
     *
     * @return the Streamable HTTP transport provider
     */
    @Bean
    public HttpServletStreamableServerTransportProvider streamableHttpTransportProvider() {
        logger.info("Creating HttpServletStreamableServerTransportProvider with context extractor");
        
        return HttpServletStreamableServerTransportProvider.builder()
                .jsonMapper(McpJsonMapper.getDefault())
                .contextExtractor(this::extractAuthContext)
                .build();
    }
    
    /**
     * Extracts authentication context from HTTP request.
     * <p>
     * This method extracts authentication-related headers from the HTTP request
     * and creates a McpTransportContext that will be available in tool handlers.
     * This is the standard MCP SDK approach for passing request context to tools.
     * </p>
     *
     * @param request the HTTP request
     * @return the MCP transport context containing authentication headers
     */
    private McpTransportContext extractAuthContext(HttpServletRequest request) {
        Map<String, Object> contextMap = new HashMap<>();
        
        // Extract authentication headers
        String authorization = request.getHeader("Authorization");
        String wit = request.getHeader("X-Workload-Identity");
        String wpt = request.getHeader("X-Workload-Proof");
        
        if (authorization != null) {
            contextMap.put("Authorization", authorization);
        }
        if (wit != null) {
            contextMap.put("X-Workload-Identity", wit);
        }
        if (wpt != null) {
            contextMap.put("X-Workload-Proof", wpt);
        }
        
        // Extract HTTP method and URI for validation
        contextMap.put("httpMethod", request.getMethod());
        contextMap.put("httpUri", request.getRequestURI());
        
        // Extract all headers for validation
        Map<String, String> allHeaders = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            allHeaders.put(headerName, request.getHeader(headerName));
        }
        contextMap.put("httpHeaders", allHeaders);
        
        logger.debug("Extracted authentication context from request: {}", 
                    authorization != null ? "Authorization present" : "No Authorization");
        
        return McpTransportContext.create(contextMap);
    }
    
    /**
     * Registers the Streamable HTTP transport servlet.
     * <p>
     * This servlet handles MCP requests at the /mcp endpoint.
     * </p>
     *
     * @param transportProvider the Streamable HTTP transport provider
     * @return the servlet registration bean
     */
    @Bean
    public ServletRegistrationBean<HttpServletStreamableServerTransportProvider> streamableHttpServletRegistration(
            HttpServletStreamableServerTransportProvider transportProvider) {
        logger.info("Registering Streamable HTTP servlet at /mcp");
        return new ServletRegistrationBean<>(transportProvider, "/mcp");
    }
    
    /**
     * Creates and configures the MCP Server.
     * <p>
     * This method creates a compliant MCP server using the MCP Java SDK.
     * It registers all shopping-related tools with proper authentication
     * integration using the five-layer verification architecture.
     * </p>
     *
     * @param transportProvider the Streamable HTTP transport provider
     * @param shoppingService the shopping service for business logic
     * @param resourceServer the resource server service for authentication
     * @return the MCP sync server
     */
    @Bean(destroyMethod = "close")
    public McpSyncServer shoppingMcpServer(
            HttpServletStreamableServerTransportProvider transportProvider,
            ShoppingService shoppingService,
            ResourceServer resourceServer) {
        
        logger.info("Creating MCP Server: {} v{}", SERVER_NAME, SERVER_VERSION);
        
        McpSyncServer mcpServer = McpServer.sync(transportProvider)
                .serverInfo(SERVER_NAME, SERVER_VERSION)
                .capabilities(McpSchema.ServerCapabilities.builder()
                        .tools(true)
                        .logging()
                        .build())
                .build();
        
        registerSearchProductsTool(mcpServer, shoppingService, resourceServer);
        registerAddToCartTool(mcpServer, shoppingService, resourceServer);
        registerPurchaseProductTool(mcpServer, shoppingService, resourceServer);
        registerQueryOrdersTool(mcpServer, shoppingService, resourceServer);
        
        logger.info("MCP Server created successfully with 4 registered tools");
        
        return mcpServer;
    }
    
    private void registerSearchProductsTool(McpSyncServer mcpServer, 
                                           ShoppingService shoppingService,
                                           ResourceServer resourceServer) {
        SearchProductsTool tool = new SearchProductsTool(shoppingService);
        
        McpServerFeatures.SyncToolSpecification toolSpec = McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool.getDefinition())
                .callHandler(createAuthenticatedToolHandler(tool, resourceServer))
                .build();
        
        mcpServer.addTool(toolSpec);
        logger.info("Registered tool: search_products");
    }
    
    private void registerAddToCartTool(McpSyncServer mcpServer,
                                       ShoppingService shoppingService,
                                       ResourceServer resourceServer) {
        AddToCartTool tool = new AddToCartTool(shoppingService);
        
        McpServerFeatures.SyncToolSpecification toolSpec = McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool.getDefinition())
                .callHandler(createAuthenticatedToolHandler(tool, resourceServer))
                .build();
        
        mcpServer.addTool(toolSpec);
        logger.info("Registered tool: add_to_cart");
    }
    
    private void registerPurchaseProductTool(McpSyncServer mcpServer,
                                             ShoppingService shoppingService,
                                             ResourceServer resourceServer) {
        PurchaseProductTool tool = new PurchaseProductTool(shoppingService);
        
        McpServerFeatures.SyncToolSpecification toolSpec = McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool.getDefinition())
                .callHandler(createAuthenticatedToolHandler(tool, resourceServer))
                .build();
        
        mcpServer.addTool(toolSpec);
        logger.info("Registered tool: purchase_product");
    }
    
    private void registerQueryOrdersTool(McpSyncServer mcpServer,
                                         ShoppingService shoppingService,
                                         ResourceServer resourceServer) {
        QueryOrdersTool tool = new QueryOrdersTool(shoppingService);
        
        McpServerFeatures.SyncToolSpecification toolSpec = McpServerFeatures.SyncToolSpecification.builder()
                .tool(tool.getDefinition())
                .callHandler(createAuthenticatedToolHandler(tool, resourceServer))
                .build();
        
        mcpServer.addTool(toolSpec);
        logger.info("Registered tool: query_orders");
    }
    
    private BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult>
            createAuthenticatedToolHandler(McpTool tool, ResourceServer resourceServer) {
        
        return (exchange, request) -> {
            Map<String, Object> arguments = request.arguments();
            logger.info("Executing tool: {} with arguments: {}", tool.getName(), arguments);
            
            try {
                // Get authentication context from McpTransportContext
                McpTransportContext authContext = exchange.transportContext();
                
                if (authContext == null) {
                    logger.error("Failed to get authentication context from McpTransportContext");
                    return McpSchema.CallToolResult.builder()
                            .content(List.of(new McpSchema.TextContent("Error: Unable to access authentication context")))
                            .isError(true)
                            .build();
                }
                
                String authorizationHeader = (String) authContext.get("Authorization");
                String witHeader = (String) authContext.get("X-Workload-Identity");
                String wptHeader = (String) authContext.get("X-Workload-Proof");
                String httpMethod = (String) authContext.get("httpMethod");
                String httpUri = (String) authContext.get("httpUri");
                Map<String, String> httpHeaders = (Map<String, String>) authContext.get("httpHeaders");
                
                ResourceRequest resourceRequest = ResourceRequest.builder()
                        .wit(witHeader)
                        .wpt(wptHeader)
                        .aoat(extractBearerToken(authorizationHeader))
                        .httpMethod(httpMethod)
                        .httpUri(httpUri)
                        .httpHeaders(httpHeaders)
                        .httpBody(extractRequestBody(arguments))
                        .operationType(tool.getName())
                        .resourceId(SERVER_NAME)
                        .parameters(arguments)
                        .build();
                
                ValidationResult validationResult = resourceServer.validateRequest(resourceRequest);

                if (!validationResult.isValid()) {
                    String errorMessage = validationResult.getErrors() != null && !validationResult.getErrors().isEmpty()
                            ? String.join(", ", validationResult.getErrors())
                            : "Authentication failed";
                    logger.error("Authentication failed for tool: {}, reason: {}", tool.getName(), errorMessage);
                    return McpSchema.CallToolResult.builder()
                            .content(List.of(new McpSchema.TextContent("Error: Authentication failed - " + errorMessage)))
                            .isError(true)
                            .build();
                }
                
                return tool.execute(arguments);
                
            } catch (Exception e) {
                logger.error("Error executing tool: {}", tool.getName(), e);
                return McpSchema.CallToolResult.builder()
                        .content(List.of(new McpSchema.TextContent("Error: " + e.getMessage())))
                        .isError(true)
                        .build();
            }
        };
    }
    
    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return authorizationHeader;
    }
    
    private String extractRequestBody(Map<String, Object> arguments) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.writeValueAsString(arguments);
        } catch (Exception e) {
            logger.warn("Failed to serialize request body: {}", e.getMessage());
            return "{}";
        }
    }
}