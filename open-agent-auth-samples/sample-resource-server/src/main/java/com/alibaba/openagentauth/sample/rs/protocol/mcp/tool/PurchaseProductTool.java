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
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tool for purchasing products.
 * <p>
 * This tool delegates to {@link ShoppingService} for business logic.
 * It requires a product ID and quantity, and creates an order.
 * </p>
 *
 * @since 1.0
 */
public class PurchaseProductTool implements McpTool {
    
    private static final Logger logger = LoggerFactory.getLogger(PurchaseProductTool.class);
    
    private static final String TOOL_NAME = "purchase_product";
    private static final String TOOL_DESCRIPTION = "Purchase products and create an order";
    
    private final ShoppingService shoppingService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Creates a new PurchaseProductTool.
     *
     * @param shoppingService the shopping service
     */
    public PurchaseProductTool(ShoppingService shoppingService) {
        this.shoppingService = shoppingService;
        logger.debug("PurchaseProductTool created");
    }
    
    @Override
    public McpSchema.Tool getDefinition() {
        
        Map<String, Object> productIdProperty = new HashMap<>();
        productIdProperty.put("type", "string");
        productIdProperty.put("description", "Product ID to purchase (e.g., 'PROD-001', 'PROD-002')");
        productIdProperty.put("pattern", "^PROD-\\d{3}$");
        
        Map<String, Object> quantityProperty = new HashMap<>();
        quantityProperty.put("type", "integer");
        quantityProperty.put("description", "Quantity to purchase (must be a positive integer, typically 1-10)");
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
        logger.info("Executing purchase_product with arguments: {}", arguments);
        
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
            Order order = shoppingService.purchaseProduct(productId, quantity, userId);
            Map<String, Object> result = buildOrderResult(order);
            
            logger.info("Successfully purchased {} units of product {}, order ID: {}", 
                       quantity, productId, order.getId());
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent(objectMapper.writeValueAsString(result))))
                    .isError(false)
                    .build();
            
        } catch (Exception e) {
            logger.error("Error executing purchase_product", e);
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
    
    /**
     * Builds structured order result in JSON format.
     *
     * @param order the created order
     * @return structured order details as a Map
     */
    private Map<String, Object> buildOrderResult(Order order) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("orderId", order.getId());
        result.put("status", order.getStatus().toString());
        result.put("totalAmount", order.getTotalAmount());
        result.put("createdAt", order.getCreatedAt().toString());
        
        List<Map<String, Object>> itemsList = new ArrayList<>();
        for (Order.OrderItem item : order.getItems()) {
            Map<String, Object> itemMap = new HashMap<>();
            itemMap.put("productId", item.getProductId());
            itemMap.put("productName", item.getProductName());
            itemMap.put("quantity", item.getQuantity());
            itemMap.put("unitPrice", item.getUnitPrice());
            itemMap.put("totalPrice", item.getTotalPrice());
            itemsList.add(itemMap);
        }
        result.put("items", itemsList);
        
        return result;
    }
    
}
