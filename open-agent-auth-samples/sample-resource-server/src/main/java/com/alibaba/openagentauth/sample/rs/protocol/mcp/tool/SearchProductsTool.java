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
import com.alibaba.openagentauth.sample.rs.domain.model.Product;
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
 * Tool for searching products by category and keywords.
 * <p>
 * This tool delegates to {@link ShoppingService} for business logic.
 * It supports filtering by category and optional keyword search.
 * </p>
 *
 * @since 1.0
 */
public class SearchProductsTool implements McpTool {
    
    private static final Logger logger = LoggerFactory.getLogger(SearchProductsTool.class);
    
    private static final String TOOL_NAME = "search_products";
    private static final String TOOL_DESCRIPTION = "Search for products in an online shopping store. " +
            "Use this tool when users want to find books, clothing, electronics, or any other products. " +
            "Optional parameters: category (e.g., books, clothing, electronics) for filtering by category, " +
            "keywords for filtering results by text.";
    
    private final ShoppingService shoppingService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Creates a new SearchProductsTool.
     *
     * @param shoppingService the shopping service
     */
    public SearchProductsTool(ShoppingService shoppingService) {
        this.shoppingService = shoppingService;
        logger.debug("SearchProductsTool created");
    }
    
    @Override
    public McpSchema.Tool getDefinition() {
        
        Map<String, Object> categoryProperty = new HashMap<>();
        categoryProperty.put("type", "string");
        categoryProperty.put("description", "Product category (must be one of the supported categories)");
        categoryProperty.put("enum", List.of("books", "clothing", "electronics"));
        
        Map<String, Object> keywordsProperty = new HashMap<>();
        keywordsProperty.put("type", "string");
        keywordsProperty.put("description", "Optional search keywords for filtering results " +
                "(e.g., 'programming', 'winter', 'wireless')." +
                " Must be in English letters only.");
        keywordsProperty.put("pattern", "^[a-zA-Z\\s\\-']+$");
        keywordsProperty.put("minLength", 1);
        keywordsProperty.put("maxLength", 100);
        
        Map<String, Object> schemaDefinition = Map.of(
                "type", "object",
                "properties", Map.of(
                        "category", categoryProperty,
                        "keywords", keywordsProperty
                ),
                "required", List.of()
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
        logger.info("Executing search_products with arguments: {}", arguments);
        
        try {
            String category = (String) arguments.get("category");
            String keywords = (String) arguments.get("keywords");
            String userId = "demo-user";
            
            // If both category and keywords are empty, return an error
            if (ValidationUtils.isNullOrEmpty(category) && ValidationUtils.isNullOrEmpty(keywords)) {
                logger.error("At least one of category or keywords is required");
                return McpSchema.CallToolResult.builder()
                        .content(List.of(new McpSchema.TextContent("Error: At least one of category or keywords is required")))
                        .isError(true)
                        .build();
            }
            
            List<Product> products = shoppingService.searchProducts(category, keywords, userId);
            Map<String, Object> result = buildSearchResults(products, category, keywords);
            
            logger.info("Product search completed for category: {}, found {} products", category, products.size());
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent(objectMapper.writeValueAsString(result))))
                    .isError(false)
                    .build();
            
        } catch (Exception e) {
            logger.error("Error executing search_products", e);
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
     * Builds structured search results in JSON format.
     *
     * @param products the list of products
     * @param category the search category
     * @param keywords the search keywords
     * @return structured search results as a Map
     */
    private Map<String, Object> buildSearchResults(List<Product> products, String category, String keywords) {
        Map<String, Object> result = new HashMap<>();
        result.put("success", true);
        result.put("category", category);
        result.put("count", products.size());
        
        List<Map<String, Object>> productList = new ArrayList<>();
        for (Product product : products) {
            Map<String, Object> productMap = new HashMap<>();
            productMap.put("id", product.getId());
            productMap.put("name", product.getName());
            productMap.put("description", product.getDescription());
            productMap.put("price", product.getPrice());
            productMap.put("imageUrl", product.getImageUrl());
            productList.add(productMap);
        }
        result.put("products", productList);
        
        if (!ValidationUtils.isNullOrEmpty(keywords)) {
            result.put("keywords", keywords);
        }
        
        return result;
    }
    
}