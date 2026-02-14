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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.mcp.server.tool.McpTool;
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tool for querying order information.
 * <p>
 * This tool delegates to {@link ShoppingService} for business logic.
 * It supports querying by order ID or listing all orders.
 * </p>
 *
 * @since 1.0
 */
public class QueryOrdersTool implements McpTool {
    
    private static final Logger logger = LoggerFactory.getLogger(QueryOrdersTool.class);
    
    private static final String TOOL_NAME = "query_orders";
    private static final String TOOL_DESCRIPTION = "Query order information";
    
    private final ShoppingService shoppingService;
    
    /**
     * Creates a new QueryOrdersTool.
     *
     * @param shoppingService the shopping service
     */
    public QueryOrdersTool(ShoppingService shoppingService) {
        this.shoppingService = shoppingService;
        logger.debug("QueryOrdersTool created");
    }
    
    @Override
    public McpSchema.Tool getDefinition() {
        ObjectMapper objectMapper = new ObjectMapper();
        
        Map<String, Object> orderIdProperty = new HashMap<>();
        orderIdProperty.put("type", "string");
        orderIdProperty.put("description", "Order ID to query (optional, if not provided returns all orders). Format: 'ORDER-{timestamp}-{uuid}'");
        orderIdProperty.put("pattern", "^ORDER-\\d+-[a-f0-9]{8}$");
        
        Map<String, Object> schemaDefinition = Map.of(
                "type", "object",
                "properties", Map.of(
                        "orderId", orderIdProperty
                )
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
        logger.info("Executing query_orders with arguments: {}", arguments);
        
        try {
            String orderId = (String) arguments.get("orderId");
            String userId = "demo-user";
            
            String result;
            if (!ValidationUtils.isNullOrEmpty(orderId)) {
                Order order = shoppingService.queryOrder(orderId, userId);
                if (order == null) {
                    result = "Order not found: " + orderId;
                } else {
                    result = formatOrderDetails(order);
                }
            } else {
                List<Order> orders = shoppingService.listOrders(userId);
                result = formatOrderList(orders);
            }
            
            logger.info("Order query completed");
            return new McpSchema.CallToolResult(
                    List.of(new McpSchema.TextContent(result)),
                    false
            );
            
        } catch (Exception e) {
            logger.error("Error executing query_orders", e);
            return new McpSchema.CallToolResult(
                    List.of(new McpSchema.TextContent("Error: " + e.getMessage())),
                    true
            );
        }
    }
    
    @Override
    public String getName() {
        return TOOL_NAME;
    }
    
    /**
     * Formats order details for display.
     *
     * @param order the order
     * @return formatted order details
     */
    private String formatOrderDetails(Order order) {
        StringBuilder result = new StringBuilder();
        result.append("Order Information:\n");
        result.append("- Order ID: ").append(order.getId()).append("\n");
        result.append("- Status: ").append(order.getStatus()).append("\n");
        result.append("- Created At: ").append(order.getCreatedAt()).append("\n");
        result.append("- Total Amount: ¥").append(order.getTotalAmount()).append("\n");
        
        if (order.getShippingAddress() != null) {
            result.append("- Shipping Address: ").append(order.getShippingAddress()).append("\n");
        }
        
        if (order.getTrackingNumber() != null) {
            result.append("- Tracking Number: ").append(order.getTrackingNumber()).append("\n");
        }
        
        result.append("\nOrder Items:\n");
        for (Order.OrderItem item : order.getItems()) {
            result.append(String.format("- %s x%d = ¥%s\n", 
                    item.getProductName(), item.getQuantity(), item.getTotalPrice()));
        }
        
        return result.toString();
    }
    
    /**
     * Formats order list for display.
     *
     * @param orders the list of orders
     * @return formatted order list
     */
    private String formatOrderList(List<Order> orders) {
        if (orders.isEmpty()) {
            return "No orders found.";
        }
        
        StringBuilder result = new StringBuilder();
        result.append("Your Recent Orders:\n\n");
        
        int index = 1;
        BigDecimal totalSpent = BigDecimal.ZERO;
        for (Order order : orders) {
            result.append(String.format("%d. %s - %s - ¥%s - %s\n", 
                    index++, order.getId(), 
                    order.getItems().get(0).getProductName(),
                    order.getTotalAmount(), order.getStatus()));
            totalSpent = totalSpent.add(order.getTotalAmount());
        }
        
        result.append("\nTotal: ").append(orders.size()).append(" orders\n");
        result.append("Total Spent: ¥").append(totalSpent);
        
        return result.toString();
    }
    
}