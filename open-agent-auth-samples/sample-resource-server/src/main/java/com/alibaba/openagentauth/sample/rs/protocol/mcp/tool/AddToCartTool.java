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
package com.alibaba.openagentauth.sample.rs.protocol.mcp.tool;

import com.alibaba.openagentauth.mcp.server.tool.McpTool;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tool for adding products to shopping cart.
 * <p>
 * This tool delegates to {@link ShoppingService} for business logic.
 * It requires a product ID and quantity.
 * </p>
 *
 * @since 1.0
 */
public class AddToCartTool implements McpTool {
    
    private static final Logger logger = LoggerFactory.getLogger(AddToCartTool.class);
    
    private static final String TOOL_NAME = "add_to_cart";
    private static final String TOOL_DESCRIPTION = "Add products to shopping cart";
    
    private final ShoppingService shoppingService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Creates a new AddToCartTool.
     *
     * @param shoppingService the shopping service
     */
    public AddToCartTool(ShoppingService shoppingService) {
        this.shoppingService = shoppingService;
        logger.debug("AddToCartTool created");
    }
    
    @Override
    public McpSchema.Tool getDefinition() {
        
        Map<String, Object> productIdProperty = new HashMap<>();
        productIdProperty.put("type", "string");
        productIdProperty.put("description", "Product ID to add to cart (e.g., 'PROD-001', 'PROD-002')");
        productIdProperty.put("pattern", "^PROD-\\d{3}$");
        
        Map<String, Object> quantityProperty = new HashMap<>();
        quantityProperty.put("type", "integer");
        quantityProperty.put("description", "Quantity to add (must be a positive integer, typically 1-10)");
        quantityProperty.put("minimum", 1);
        quantityProperty.put("maximum", 100);
        
        Map<String, Object> schemaDefinition = Map.of(
                "type", "object",
                "properties", Map.of(
                        "productId", productIdProperty,
                        "quantity", quantityProperty
                ),
                "required", List.of("productId", "quantity")
        );
        
        McpSchema.JsonSchema inputSchema = objectMapper.convertValue(schemaDefinition, McpSchema.JsonSchema.class);
        
        return McpSchema.Tool.builder()
                .name(TOOL_NAME)
                .description(TOOL_DESCRIPTION)
                .inputSchema(inputSchema)
                .build();
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments) {
        logger.info("Executing add_to_cart with arguments: {}", arguments);
        
        try {
            // Validate productId
            McpSchema.CallToolResult validationResult = ToolValidationUtils.validateProductId(arguments, logger);
            if (validationResult != null) {
                return validationResult;
            }
            
            // Validate quantity
            validationResult = ToolValidationUtils.validateQuantity(arguments, logger);
            if (validationResult != null) {
                return validationResult;
            }
            
            String productId = (String) arguments.get("productId");
            int quantity = ToolValidationUtils.extractQuantity(arguments, logger);
            
            String userId = "demo-user";
            String serviceResult = shoppingService.addToCart(productId, quantity, userId);
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("productId", productId);
            result.put("quantity", quantity);
            result.put("message", serviceResult);
            
            logger.info("Successfully added {} units of product {} to cart", quantity, productId);
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent(objectMapper.writeValueAsString(result))))
                    .isError(false)
                    .build();
            
        } catch (Exception e) {
            logger.error("Error executing add_to_cart", e);
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent("Error: " + e.getMessage())))
                    .isError(true)
                    .build();
        }
    }
    
    @Override
    public String getName() {
        return TOOL_NAME;
    }
    
}
