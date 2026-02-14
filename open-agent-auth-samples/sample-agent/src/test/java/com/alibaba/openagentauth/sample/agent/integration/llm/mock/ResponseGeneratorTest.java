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
package com.alibaba.openagentauth.sample.agent.integration.llm.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ResponseGenerator}.
 * <p>
 * This test class validates the response generation functionality
 * including template-based generation with variable substitution.
 * </p>
 */
@DisplayName("ResponseGenerator Tests")
class ResponseGeneratorTest {

    private ResponseGenerator responseGenerator;

    @BeforeEach
    void setUp() {
        responseGenerator = new ResponseGenerator();
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize successfully")
        void shouldInitializeSuccessfully() {
            assertThat(responseGenerator).isNotNull();
        }
    }

    @Nested
    @DisplayName("generateSuccessResponse()")
    class GenerateSuccessResponseTests {

        @Test
        @DisplayName("Should generate response with template and result")
        void shouldGenerateResponseWithTemplateAndResult() {
            String template = "Operation completed successfully. Result: {result}";
            String toolResult = "Product found: iPhone 15";
            Map<String, Object> params = Map.of("product", "iPhone 15");

            String result = responseGenerator.generateSuccessResponse(template, toolResult, params);

            assertThat(result).isEqualTo("Operation completed successfully. Result: Product found: iPhone 15");
        }

        @Test
        @DisplayName("Should replace multiple placeholders")
        void shouldReplaceMultiplePlaceholders() {
            String template = "Product: {product}, Quantity: {quantity}, Result: {result}";
            String toolResult = "Order confirmed";
            Map<String, Object> params = Map.of(
                    "product", "iPhone 15",
                    "quantity", 5
            );

            String result = responseGenerator.generateSuccessResponse(template, toolResult, params);

            assertThat(result).isEqualTo("Product: iPhone 15, Quantity: 5, Result: Order confirmed");
        }

        @Test
        @DisplayName("Should handle null result")
        void shouldHandleNullResult() {
            String template = "Result: {result}";
            Map<String, Object> params = Map.of();

            String result = responseGenerator.generateSuccessResponse(template, null, params);

            assertThat(result).isEqualTo("Result: ");
        }

        @Test
        @DisplayName("Should handle null params")
        void shouldHandleNullParams() {
            String template = "Result: {result}";
            String toolResult = "Success";

            String result = responseGenerator.generateSuccessResponse(template, toolResult, null);

            assertThat(result).isEqualTo("Result: Success");
        }

        @Test
        @DisplayName("Should handle null template")
        void shouldHandleNullTemplate() {
            String toolResult = "Success";
            Map<String, Object> params = Map.of();

            String result = responseGenerator.generateSuccessResponse(null, toolResult, params);

            assertThat(result).isEqualTo("Operation completed successfully. Result: Success");
        }

        @Test
        @DisplayName("Should handle empty template")
        void shouldHandleEmptyTemplate() {
            String toolResult = "Success";
            Map<String, Object> params = Map.of();

            String result = responseGenerator.generateSuccessResponse("", toolResult, params);

            assertThat(result).isEqualTo("Operation completed successfully. Result: Success");
        }

        @Test
        @DisplayName("Should handle null param value")
        void shouldHandleNullParamValue() {
            String template = "Product: {product}";
            String toolResult = "Success";
            Map<String, Object> params = new HashMap<>();
            params.put("product", null);

            String result = responseGenerator.generateSuccessResponse(template, toolResult, params);

            assertThat(result).isEqualTo("Product: ");
        }
    }

    @Nested
    @DisplayName("generateErrorResponse()")
    class GenerateErrorResponseTests {

        @Test
        @DisplayName("Should generate error response with template and error message")
        void shouldGenerateErrorResponseWithTemplateAndErrorMessage() {
            String template = "Operation failed. Error: {error}";
            String errorMessage = "Product not found";

            String result = responseGenerator.generateErrorResponse(template, errorMessage);

            assertThat(result).isEqualTo("Operation failed. Error: Product not found");
        }

        @Test
        @DisplayName("Should handle null error message")
        void shouldHandleNullErrorMessage() {
            String template = "Error: {error}";

            String result = responseGenerator.generateErrorResponse(template, null);

            assertThat(result).isEqualTo("Error: Unknown error");
        }

        @Test
        @DisplayName("Should handle null template")
        void shouldHandleNullTemplate() {
            String errorMessage = "Product not found";

            String result = responseGenerator.generateErrorResponse(null, errorMessage);

            assertThat(result).isEqualTo("Operation failed. Error: Product not found");
        }

        @Test
        @DisplayName("Should handle empty template")
        void shouldHandleEmptyTemplate() {
            String errorMessage = "Product not found";

            String result = responseGenerator.generateErrorResponse("", errorMessage);

            assertThat(result).isEqualTo("Operation failed. Error: Product not found");
        }
    }
}
