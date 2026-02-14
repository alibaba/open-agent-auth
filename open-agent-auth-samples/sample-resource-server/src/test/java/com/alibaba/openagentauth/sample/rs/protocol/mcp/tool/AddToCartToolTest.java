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

import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AddToCartTool}.
 * <p>
 * Tests cover various scenarios including successful execution,
 * validation errors, and exception handling.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AddToCartTool Unit Tests")
class AddToCartToolTest {
    
    @Mock
    private ShoppingService shoppingService;
    
    private AddToCartTool addToCartTool;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        addToCartTool = new AddToCartTool(shoppingService);
    }
    
    @Test
    @DisplayName("Should successfully add product to cart")
    void testSuccessfulAddToCart() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 2);
        
        when(shoppingService.addToCart("PROD-001", 2, "demo-user"))
                .thenReturn("Product added successfully");
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not indicate error");
        verify(shoppingService, times(1)).addToCart("PROD-001", 2, "demo-user");
    }
    
    @Test
    @DisplayName("Should return error when productId parameter is missing")
    void testMissingProductId() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("quantity", 2);
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when productId is missing");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when productId is empty")
    void testEmptyProductId() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "");
        arguments.put("quantity", 2);
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when productId is empty");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when productId is blank")
    void testBlankProductId() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "   ");
        arguments.put("quantity", 2);
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when productId is blank");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when quantity parameter is missing")
    void testMissingQuantity() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when quantity is missing");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when quantity is zero")
    void testZeroQuantity() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 0);
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when quantity is zero");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when quantity is negative")
    void testNegativeQuantity() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", -5);
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when quantity is negative");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when quantity is not a number")
    void testNonNumericQuantity() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", "invalid");
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when quantity is not a number");
        verify(shoppingService, never()).addToCart(anyString(), anyInt(), anyString());
    }
    
    @Test
    @DisplayName("Should return error when ShoppingService throws exception")
    void testShoppingServiceThrowsException() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 2);
        
        when(shoppingService.addToCart("PROD-001", 2, "demo-user"))
                .thenThrow(new RuntimeException("Service unavailable"));
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when service throws exception");
        verify(shoppingService, times(1)).addToCart("PROD-001", 2, "demo-user");
    }
    
    @Test
    @DisplayName("Should return error when ShoppingService throws checked exception")
    void testShoppingServiceThrowsCheckedException() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-001");
        arguments.put("quantity", 2);
        
        when(shoppingService.addToCart("PROD-001", 2, "demo-user"))
                .thenThrow(new IllegalStateException("Invalid operation"));
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should indicate error when service throws checked exception");
        verify(shoppingService, times(1)).addToCart("PROD-001", 2, "demo-user");
    }
    
    @Test
    @DisplayName("Should successfully add product with maximum valid quantity")
    void testSuccessfulAddToCartWithMaxQuantity() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-100");
        arguments.put("quantity", 100);
        
        when(shoppingService.addToCart("PROD-100", 100, "demo-user"))
                .thenReturn("Bulk product added successfully");
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not indicate error for max valid quantity");
        verify(shoppingService, times(1)).addToCart("PROD-100", 100, "demo-user");
    }
    
    @Test
    @DisplayName("Should successfully add product with minimum valid quantity")
    void testSuccessfulAddToCartWithMinQuantity() {
        Map<String, Object> arguments = new HashMap<>();
        arguments.put("productId", "PROD-999");
        arguments.put("quantity", 1);
        
        when(shoppingService.addToCart("PROD-999", 1, "demo-user"))
                .thenReturn("Single product added successfully");
        
        McpSchema.CallToolResult result = addToCartTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not indicate error for min valid quantity");
        verify(shoppingService, times(1)).addToCart("PROD-999", 1, "demo-user");
    }
}
