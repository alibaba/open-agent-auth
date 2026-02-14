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

import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link QueryOrdersTool}.
 * <p>
 * Test coverage includes:
 * - Successful single order query
 * - Order not found scenario
 * - Successful all orders query
 * - Empty order list scenario
 * - ShoppingService exception handling
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class QueryOrdersToolTest {
    
    @Mock
    private ShoppingService shoppingService;
    
    private QueryOrdersTool queryOrdersTool;
    
    @BeforeEach
    void setUp() {
        queryOrdersTool = new QueryOrdersTool(shoppingService);
    }
    
    /**
     * Test successful query of a single order.
     * Verifies that the result is not marked as error.
     */
    @Test
    void testQuerySingleOrder_Success() {
        // Arrange
        Order order = createMockOrder("ORDER-1234567890-abc12345");
        when(shoppingService.queryOrder("ORDER-1234567890-abc12345", "demo-user")).thenReturn(order);
        
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("orderId", "ORDER-1234567890-abc12345");
        
        // Act
        McpSchema.CallToolResult result = queryOrdersTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not be marked as error for successful query");
    }
    
    /**
     * Test query when order does not exist.
     * Verifies that the result is not marked as error (service returns null).
     */
    @Test
    void testQuerySingleOrder_NotFound() {
        // Arrange
        when(shoppingService.queryOrder("ORDER-1234567890-abc12345", "demo-user")).thenReturn(null);
        
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("orderId", "ORDER-1234567890-abc12345");
        
        // Act
        McpSchema.CallToolResult result = queryOrdersTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not be marked as error when order not found");
    }
    
    /**
     * Test successful query of all orders.
     * Verifies that the result is not marked as error.
     */
    @Test
    void testQueryAllOrders_Success() {
        // Arrange
        List<Order> orders = createMockOrderList(3);
        when(shoppingService.listOrders("demo-user")).thenReturn(orders);
        
        Map<String, Object> arguments = new HashMap<>();
        
        // Act
        McpSchema.CallToolResult result = queryOrdersTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not be marked as error for successful all orders query");
    }
    
    /**
     * Test query when order list is empty.
     * Verifies that the result is not marked as error.
     */
    @Test
    void testQueryAllOrders_EmptyList() {
        // Arrange
        List<Order> emptyList = new ArrayList<>();
        when(shoppingService.listOrders("demo-user")).thenReturn(emptyList);
        
        Map<String, Object> arguments = new HashMap<>();
        
        // Act
        McpSchema.CallToolResult result = queryOrdersTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not be marked as error when order list is empty");
    }
    
    /**
     * Test when ShoppingService throws an exception.
     * Verifies that the result is marked as error.
     */
    @Test
    void testQueryOrders_ServiceThrowsException() {
        // Arrange
        when(shoppingService.queryOrder(anyString(), anyString()))
                .thenThrow(new RuntimeException("Database connection failed"));
        
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("orderId", "ORDER-1234567890-abc12345");
        
        // Act
        McpSchema.CallToolResult result = queryOrdersTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should be marked as error when service throws exception");
    }
    
    /**
     * Test when ShoppingService throws exception during list orders.
     * Verifies that the result is marked as error.
     */
    @Test
    void testQueryAllOrders_ServiceThrowsException() {
        // Arrange
        when(shoppingService.listOrders("demo-user"))
                .thenThrow(new RuntimeException("Service unavailable"));
        
        Map<String, Object> arguments = new HashMap<>();
        
        // Act
        McpSchema.CallToolResult result = queryOrdersTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should be marked as error when listOrders throws exception");
    }
    
    /**
     * Helper method to create a mock order for testing.
     *
     * @param orderId the order ID
     * @return a mock Order object
     */
    private Order createMockOrder(String orderId) {
        Order.OrderItem item1 = new Order.OrderItem(
                "PROD001", "Test Product 1", 2, new BigDecimal("99.99"));
        Order.OrderItem item2 = new Order.OrderItem(
                "PROD002", "Test Product 2", 1, new BigDecimal("100.01"));
        
        Order order = new Order(
                orderId, 
                "demo-user", 
                List.of(item1, item2), 
                Order.OrderStatus.DELIVERED, 
                LocalDateTime.now()
        );
        
        order.setShippingAddress("123 Test Street, Test City");
        order.setTrackingNumber("TRACK123456789");
        
        return order;
    }
    
    /**
     * Helper method to create a list of mock orders.
     *
     * @param count the number of orders to create
     * @return a list of mock Order objects
     */
    private List<Order> createMockOrderList(int count) {
        List<Order> orders = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Order.OrderItem item = new Order.OrderItem(
                    String.format("PROD%03d", i + 1),
                    String.format("Product %d", i + 1),
                    1,
                    new BigDecimal(String.format("%d.00", (i + 1) * 100))
            );
            
            Order order = new Order(
                    String.format("ORDER-%d-abc%d", System.currentTimeMillis(), i),
                    "demo-user",
                    List.of(item),
                    i % 2 == 0 ? Order.OrderStatus.DELIVERED : Order.OrderStatus.PROCESSING,
                    LocalDateTime.now().minusDays(i)
            );
            
            orders.add(order);
        }
        return orders;
    }
    
}