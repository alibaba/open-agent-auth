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
import io.modelcontextprotocol.spec.McpSchema;
import org.slf4j.Logger;

import java.util.List;
import java.util.Map;

/**
 * Utility class for common tool parameter validation.
 * <p>
 * Provides reusable validation methods to reduce code duplication
 * across different tool implementations.
 * </p>
 *
 * @since 1.0
 */
public class ToolValidationUtils {
    
    /**
     * Validates productId parameter.
     *
     * @param arguments the tool arguments
     * @param logger the logger instance
     * @return error result if validation fails, null otherwise
     */
    public static McpSchema.CallToolResult validateProductId(Map<String, Object> arguments, Logger logger) {
        String productId = (String) arguments.get("productId");
        if (ValidationUtils.isNullOrEmpty(productId)) {
            logger.error("Product ID is required");
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent("Error: Product ID is required")))
                    .isError(true)
                    .build();
        }
        return null;
    }
    
    /**
     * Validates quantity parameter.
     *
     * @param arguments the tool arguments
     * @param logger the logger instance
     * @return error result if validation fails, null otherwise
     */
    public static McpSchema.CallToolResult validateQuantity(Map<String, Object> arguments, Logger logger) {
        Object quantityObj = arguments.get("quantity");
        if (quantityObj == null) {
            logger.error("Quantity is required");
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent("Error: Quantity is required")))
                    .isError(true)
                    .build();
        }
        
        int quantity;
        try {
            quantity = Integer.parseInt(quantityObj.toString());
        } catch (NumberFormatException e) {
            logger.error("Invalid quantity format: {}", quantityObj);
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent("Error: Quantity must be a valid integer")))
                    .isError(true)
                    .build();
        }
        
        if (quantity <= 0) {
            logger.error("Quantity must be positive: {}", quantity);
            return McpSchema.CallToolResult.builder()
                    .content(List.of(new McpSchema.TextContent("Error: Quantity must be a positive integer")))
                    .isError(true)
                    .build();
        }
        
        return null;
    }
    
    /**
     * Extracts and parses quantity from arguments.
     *
     * @param arguments the tool arguments
     * @param logger the logger instance
     * @return the parsed quantity
     * @throws IllegalArgumentException if quantity is invalid
     */
    public static int extractQuantity(Map<String, Object> arguments, Logger logger) {
        Object quantityObj = arguments.get("quantity");
        
        int quantity;
        try {
            quantity = Integer.parseInt(quantityObj.toString());
        } catch (NumberFormatException e) {
            logger.error("Invalid quantity format: {}", quantityObj);
            throw new IllegalArgumentException("Quantity must be a valid integer");
        }
        
        if (quantity <= 0) {
            logger.error("Quantity must be positive: {}", quantity);
            throw new IllegalArgumentException("Quantity must be a positive integer");
        }
        
        return quantity;
    }
}