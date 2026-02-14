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

import com.alibaba.openagentauth.sample.rs.domain.model.Product;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SearchProductsTool}.
 * <p>
 * Tests cover various scenarios including successful searches with different parameters,
 * empty results, and error handling.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
class SearchProductsToolTest {
    
    @Mock
    private ShoppingService shoppingService;
    
    private SearchProductsTool searchProductsTool;
    
    @BeforeEach
    void setUp() {
        searchProductsTool = new SearchProductsTool(shoppingService);
    }
    
    @Test
    void testExecute_WithCategoryOnly_ShouldReturnSuccess() {
        Map<String, Object> arguments = Map.of("category", "books");
        
        List<Product> mockProducts = List.of(createMockProduct("1", "Java Programming", "books", "A comprehensive guide", new BigDecimal("49.99")));
        when(shoppingService.searchProducts("books", null, "demo-user")).thenReturn(mockProducts);
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not be an error when searching with category only");
    }
    
    @Test
    void testExecute_WithKeywordsOnly_ShouldReturnSuccess() {
        Map<String, Object> arguments = Map.of("keywords", "programming");
        
        List<Product> mockProducts = List.of(createMockProduct("2", "Advanced Programming", "technology", "Deep dive into algorithms", new BigDecimal("59.99")));
        when(shoppingService.searchProducts(null, "programming", "demo-user")).thenReturn(mockProducts);
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not be an error when searching with keywords only");
    }
    
    @Test
    void testExecute_WithCategoryAndKeywords_ShouldReturnSuccess() {
        Map<String, Object> arguments = Map.of(
                "category", "electronics",
                "keywords", "wireless"
        );
        
        List<Product> mockProducts = List.of(
                createMockProduct("3", "Wireless Mouse", "electronics", "Ergonomic design", new BigDecimal("29.99")),
                createMockProduct("4", "Wireless Keyboard", "electronics", "Mechanical switches", new BigDecimal("79.99"))
        );
        when(shoppingService.searchProducts("electronics", "wireless", "demo-user")).thenReturn(mockProducts);
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not be an error when searching with both category and keywords");
    }
    
    @Test
    void testExecute_WithEmptyCategoryAndKeywords_ShouldReturnError() {
        Map<String, Object> arguments = Map.of(
                "category", "",
                "keywords", ""
        );
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should be an error when both category and keywords are empty");
    }
    
    @Test
    void testExecute_WithNullCategoryAndKeywords_ShouldReturnError() {
        Map<String, Object> arguments = Map.of();
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should be an error when both category and keywords are null");
    }
    
    @Test
    void testExecute_WhenShoppingServiceReturnsEmptyList_ShouldReturnSuccess() {
        Map<String, Object> arguments = Map.of("category", "clothing");
        
        when(shoppingService.searchProducts("clothing", null, "demo-user")).thenReturn(Collections.emptyList());
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertFalse(result.isError(), "Result should not be an error when search returns empty product list");
    }
    
    @Test
    void testExecute_WhenShoppingServiceThrowsException_ShouldReturnError() {
        Map<String, Object> arguments = Map.of("category", "books");
        
        when(shoppingService.searchProducts(anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("Database connection failed"));
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should be an error when ShoppingService throws an exception");
    }
    
    @Test
    void testExecute_WhenShoppingServiceThrowsIllegalArgumentException_ShouldReturnError() {
        Map<String, Object> arguments = Map.of("keywords", "invalid");
        
        when(shoppingService.searchProducts(anyString(), anyString(), anyString()))
                .thenThrow(new IllegalArgumentException("Invalid category"));
        
        McpSchema.CallToolResult result = searchProductsTool.execute(arguments);
        
        assertTrue(result.isError(), "Result should be an error when ShoppingService throws IllegalArgumentException");
    }
    
    private Product createMockProduct(String id, String name, String category, String description, BigDecimal price) {
        return new Product(id, name, category, description, price, "http://example.com/images/" + id + ".jpg");
    }
}