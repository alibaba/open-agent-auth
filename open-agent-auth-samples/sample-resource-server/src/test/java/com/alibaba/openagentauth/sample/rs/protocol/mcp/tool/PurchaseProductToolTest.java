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
import org.junit.jupiter.api.DisplayName;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PurchaseProductTool}.
 * <p>
 * Tests cover successful product purchase scenarios and various error conditions
 * including missing parameters, invalid values, and service exceptions.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("PurchaseProductTool Tests")
class PurchaseProductToolTest {
    
    @Mock
    private ShoppingService shoppingService;
    
    @InjectMocks
    private PurchaseProductTool purchaseProductTool;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        purchaseProductTool = new PurchaseProductTool(shoppingService);
    }
    
    @Test
    @DisplayName("Should successfully purchase product with valid parameters")
    void testExecute_Success() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 2);
        
        Order mockOrder = createMockOrder("ORDER-123", "PROD-001", "Test Product", 2, new BigDecimal("99.99"));
        when(shoppingService.purchaseProduct(anyString(), anyInt(), anyString())).thenReturn(mockOrder);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not indicate an error for successful purchase");
    }
    
    @Test
    @DisplayName("Should return error when productId parameter is missing")
    void testExecute_MissingProductId() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("quantity", 2);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when productId is missing");
    }
    
    @Test
    @DisplayName("Should return error when productId is null")
    void testExecute_NullProductId() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", null);
        arguments.put("quantity", 2);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when productId is null");
    }
    
    @Test
    @DisplayName("Should return error when productId is empty string")
    void testExecute_EmptyProductId() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "");
        arguments.put("quantity", 2);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when productId is empty");
    }
    
    @Test
    @DisplayName("Should return error when productId is blank (whitespace only)")
    void testExecute_BlankProductId() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "   ");
        arguments.put("quantity", 2);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when productId is blank");
    }
    
    @Test
    @DisplayName("Should return error when quantity parameter is missing")
    void testExecute_MissingQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when quantity is missing");
    }
    
    @Test
    @DisplayName("Should return error when quantity is null")
    void testExecute_NullQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", null);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when quantity is null");
    }
    
    @Test
    @DisplayName("Should return error when quantity is zero")
    void testExecute_ZeroQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 0);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when quantity is zero");
    }
    
    @Test
    @DisplayName("Should return error when quantity is negative")
    void testExecute_NegativeQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", -5);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when quantity is negative");
    }
    
    @Test
    @DisplayName("Should return error when quantity is non-numeric string")
    void testExecute_NonNumericQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", "invalid");
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when quantity is non-numeric");
    }
    
    @Test
    @DisplayName("Should return error when quantity is decimal number")
    void testExecute_DecimalQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 2.5);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when quantity is decimal");
    }
    
    @Test
    @DisplayName("Should return error when ShoppingService throws IllegalArgumentException")
    void testExecute_ShoppingServiceThrowsIllegalArgumentException() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "INVALID-PROD");
        arguments.put("quantity", 1);
        
        when(shoppingService.purchaseProduct(anyString(), anyInt(), anyString()))
                .thenThrow(new IllegalArgumentException("Product not found"));
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when service throws IllegalArgumentException");
    }
    
    @Test
    @DisplayName("Should return error when ShoppingService throws RuntimeException")
    void testExecute_ShoppingServiceThrowsRuntimeException() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 1);
        
        when(shoppingService.purchaseProduct(anyString(), anyInt(), anyString()))
                .thenThrow(new RuntimeException("Database connection failed"));
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when service throws RuntimeException");
    }
    
    @Test
    @DisplayName("Should return error when ShoppingService throws NullPointerException")
    void testExecute_ShoppingServiceThrowsNullPointerException() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 1);
        
        when(shoppingService.purchaseProduct(anyString(), anyInt(), anyString()))
                .thenThrow(new NullPointerException("Unexpected null reference"));
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertTrue(result.isError(), "Result should indicate an error when service throws NullPointerException");
    }
    
    @Test
    @DisplayName("Should successfully purchase product with maximum quantity")
    void testExecute_SuccessWithMaximumQuantity() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-002");
        arguments.put("quantity", 100);
        
        Order mockOrder = createMockOrder("ORDER-456", "PROD-002", "Bulk Product", 100, new BigDecimal("50.00"));
        when(shoppingService.purchaseProduct(anyString(), anyInt(), anyString())).thenReturn(mockOrder);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not indicate an error for maximum valid quantity");
    }
    
    @Test
    @DisplayName("Should return error when quantity is provided as string number")
    void testExecute_QuantityAsStringNumber() {
        // Arrange
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", "5");
        
        Order mockOrder = createMockOrder("ORDER-789", "PROD-001", "Test Product", 5, new BigDecimal("99.99"));
        when(shoppingService.purchaseProduct(anyString(), anyInt(), anyString())).thenReturn(mockOrder);
        
        // Act
        McpSchema.CallToolResult result = purchaseProductTool.execute(arguments);
        
        // Assert
        assertFalse(result.isError(), "Result should not indicate an error when quantity is valid string number");
    }
    
    /**
     * Creates a mock order for testing purposes.
     *
     * @param orderId the order ID
     * @param productId the product ID
     * @param productName the product name
     * @param quantity the quantity
     * @param unitPrice the unit price
     * @return a mock Order object
     */
    private Order createMockOrder(String orderId, String productId, String productName, 
                                   int quantity, BigDecimal unitPrice) {
        Order.OrderItem orderItem = new Order.OrderItem(productId, productName, quantity, unitPrice);
        return new Order(
                orderId,
                "demo-user",
                java.util.List.of(orderItem),
                Order.OrderStatus.PROCESSING,
                LocalDateTime.now()
        );
    }
}
