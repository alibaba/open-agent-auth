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

import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ToolValidationUtils}.
 * <p>
 * Tests cover parameter validation logic for MCP tools, including:
 * <ul>
 *   <li>Product ID validation</li>
 *   <li>Quantity validation</li>
 *   <li>Quantity extraction</li>
 *   <li>Error handling</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ToolValidationUtils Tests")
class ToolValidationUtilsTest {
    
    private static final Logger logger = LoggerFactory.getLogger(ToolValidationUtilsTest.class);
    
    private Map<String, Object> validArguments;
    
    @BeforeEach
    void setUp() {
        validArguments = new HashMap<>();
        validArguments.put("productId", "PROD-001");
        validArguments.put("quantity", 5);
    }
    
    @Nested
    @DisplayName("validateProductId Tests")
    class ValidateProductIdTests {
        
        @Test
        @DisplayName("Should return null when productId is valid")
        void shouldReturnNullWhenProductIdIsValid() {
            McpSchema.CallToolResult result = ToolValidationUtils.validateProductId(validArguments, logger);
            
            assertNull(result, "Should return null for valid productId");
        }
        
        @Test
        @DisplayName("Should return error when productId is null")
        void shouldReturnErrorWhenProductIdIsNull() {
            validArguments.remove("productId");
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateProductId(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
        
        @Test
        @DisplayName("Should return error when productId is empty string")
        void shouldReturnErrorWhenProductIdIsEmptyString() {
            validArguments.put("productId", "");
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateProductId(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
        
        @Test
        @DisplayName("Should return error when productId is blank")
        void shouldReturnErrorWhenProductIdIsBlank() {
            validArguments.put("productId", "   ");
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateProductId(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
    }
    
    @Nested
    @DisplayName("validateQuantity Tests")
    class ValidateQuantityTests {
        
        @Test
        @DisplayName("Should return null when quantity is valid positive integer")
        void shouldReturnNullWhenQuantityIsValid() {
            McpSchema.CallToolResult result = ToolValidationUtils.validateQuantity(validArguments, logger);
            
            assertNull(result, "Should return null for valid quantity");
        }
        
        @Test
        @DisplayName("Should return error when quantity is null")
        void shouldReturnErrorWhenQuantityIsNull() {
            validArguments.remove("quantity");
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateQuantity(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
        
        @Test
        @DisplayName("Should return error when quantity is zero")
        void shouldReturnErrorWhenQuantityIsZero() {
            validArguments.put("quantity", 0);
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateQuantity(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
        
        @Test
        @DisplayName("Should return error when quantity is negative")
        void shouldReturnErrorWhenQuantityIsNegative() {
            validArguments.put("quantity", -1);
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateQuantity(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
        
        @Test
        @DisplayName("Should return error when quantity is invalid string")
        void shouldReturnErrorWhenQuantityIsInvalidString() {
            validArguments.put("quantity", "abc");
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateQuantity(validArguments, logger);
            
            assertNotNull(result, "Should return error result");
            assertTrue(result.isError(), "Result should indicate error");
        }
        
        @Test
        @DisplayName("Should return null when quantity is valid string number")
        void shouldReturnNullWhenQuantityIsValidStringNumber() {
            validArguments.put("quantity", "10");
            
            McpSchema.CallToolResult result = ToolValidationUtils.validateQuantity(validArguments, logger);
            
            assertNull(result, "Should return null for valid string quantity");
        }
    }
    
    @Nested
    @DisplayName("extractQuantity Tests")
    class ExtractQuantityTests {
        
        @Test
        @DisplayName("Should extract quantity from integer value")
        void shouldExtractQuantityFromIntegerValue() {
            validArguments.put("quantity", 42);
            
            int quantity = ToolValidationUtils.extractQuantity(validArguments, logger);
            
            assertEquals(42, quantity, "Should extract correct quantity");
        }
        
        @Test
        @DisplayName("Should extract quantity from string value")
        void shouldExtractQuantityFromStringValue() {
            validArguments.put("quantity", "99");
            
            int quantity = ToolValidationUtils.extractQuantity(validArguments, logger);
            
            assertEquals(99, quantity, "Should extract correct quantity from string");
        }
        
        @Test
        @DisplayName("Should throw exception when quantity is invalid format")
        void shouldThrowExceptionWhenQuantityIsInvalidFormat() {
            validArguments.put("quantity", "not-a-number");
            
            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> ToolValidationUtils.extractQuantity(validArguments, logger)
            );
            
            assertTrue(exception.getMessage().contains("valid integer"),
                    "Exception message should mention valid integer");
        }
        
        @Test
        @DisplayName("Should throw exception when quantity is zero")
        void shouldThrowExceptionWhenQuantityIsZero() {
            validArguments.put("quantity", 0);
            
            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> ToolValidationUtils.extractQuantity(validArguments, logger)
            );
            
            assertTrue(exception.getMessage().contains("positive integer"),
                    "Exception message should mention positive integer");
        }
        
        @Test
        @DisplayName("Should throw exception when quantity is negative")
        void shouldThrowExceptionWhenQuantityIsNegative() {
            validArguments.put("quantity", -5);
            
            IllegalArgumentException exception = assertThrows(
                    IllegalArgumentException.class,
                    () -> ToolValidationUtils.extractQuantity(validArguments, logger)
            );
            
            assertTrue(exception.getMessage().contains("positive integer"),
                    "Exception message should mention positive integer");
        }
    }
}