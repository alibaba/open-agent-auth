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
package com.alibaba.openagentauth.core.model.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link PolicyEvaluationResult}.
 */
@DisplayName("PolicyEvaluationResult Tests")
class PolicyEvaluationResultTest {

    @Test
    @DisplayName("Constructor - create with all fields")
    void testConstructorWithAllFields() {
        Map<String, Object> output = Map.of(
                "matched_rules", List.of("rule1", "rule2"),
                "evaluation_time_ms", 150
        );

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "User has admin privileges",
                null,
                output
        );

        assertNotNull(result);
        assertTrue(result.isAllowed());
        assertEquals("User has admin privileges", result.getReasoning());
        assertNull(result.getErrorMessage());
        assertEquals(output, result.getOutput());
    }

    @Test
    @DisplayName("Constructor - create with error")
    void testConstructorWithError() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                null,
                "Policy evaluation failed: invalid input",
                null
        );

        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertNull(result.getReasoning());
        assertEquals("Policy evaluation failed: invalid input", result.getErrorMessage());
        assertNull(result.getOutput());
    }

    @Test
    @DisplayName("Constructor - create with null values")
    void testConstructorWithNullValues() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                null,
                null,
                null
        );

        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertNull(result.getReasoning());
        assertNull(result.getErrorMessage());
        assertNull(result.getOutput());
    }

    @Test
    @DisplayName("Constructor - create with minimal fields")
    void testConstructorWithMinimalFields() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Access granted",
                null,
                null
        );

        assertNotNull(result);
        assertTrue(result.isAllowed());
        assertEquals("Access granted", result.getReasoning());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() {
        Map<String, Object> output = Map.of("key", "value");
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Reason",
                "Error",
                output
        );

        assertTrue(result.isAllowed());
        assertEquals("Reason", result.getReasoning());
        assertEquals("Error", result.getErrorMessage());
        assertEquals(output, result.getOutput());
    }

    @Test
    @DisplayName("isSuccess - returns true when no error")
    void testIsSuccessReturnsTrue() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Access granted",
                null,
                null
        );

        assertTrue(result.isSuccess());
    }

    @Test
    @DisplayName("isSuccess - returns false when has error")
    void testIsSuccessReturnsFalse() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                null,
                "Evaluation failed",
                null
        );

        assertFalse(result.isSuccess());
    }

    @Test
    @DisplayName("isSuccess - returns true when errorMessage is null")
    void testIsSuccessWithNullErrorMessage() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                "Access denied",
                null,
                null
        );

        assertTrue(result.isSuccess());
    }

    @Test
    @DisplayName("isSuccess - returns false when errorMessage is empty string")
    void testIsSuccessWithEmptyErrorMessage() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                "Access denied",
                "",
                null
        );

        // The isSuccess() method only checks if errorMessage is null
        // An empty string is not null, so isSuccess() returns false
        assertFalse(result.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - allowed true with reasoning")
    void testAllowedTrueWithReasoning() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "User is authorized",
                null,
                null
        );

        assertTrue(result.isAllowed());
        assertEquals("User is authorized", result.getReasoning());
        assertTrue(result.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - allowed false with reasoning")
    void testAllowedFalseWithReasoning() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                "User is not authorized",
                null,
                null
        );

        assertFalse(result.isAllowed());
        assertEquals("User is not authorized", result.getReasoning());
        assertTrue(result.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - very long reasoning")
    void testVeryLongReasoning() {
        String longReasoning = "A".repeat(10000);
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                longReasoning,
                null,
                null
        );

        assertEquals(longReasoning, result.getReasoning());
    }

    @Test
    @DisplayName("Boundary condition - very long error message")
    void testVeryLongErrorMessage() {
        String longError = "E".repeat(10000);
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                null,
                longError,
                null
        );

        assertEquals(longError, result.getErrorMessage());
        assertFalse(result.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - complex output map")
    void testComplexOutputMap() {
        Map<String, Object> output = Map.of(
                "matched_rules", List.of("rule1", "rule2", "rule3"),
                "evaluation_details", Map.of(
                        "time_ms", 150,
                        "policy_version", "1.0"
                ),
                "metadata", Map.of(
                        "evaluator", "opa",
                        "timestamp", System.currentTimeMillis()
                )
        );

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                output
        );

        assertEquals(output, result.getOutput());
        assertEquals(3, result.getOutput().size());
    }

    @Test
    @DisplayName("Boundary condition - empty output map")
    void testEmptyOutputMap() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                Map.of()
        );

        assertNotNull(result.getOutput());
        assertTrue(result.getOutput().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - null output map")
    void testNullOutputMap() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                null
        );

        assertNull(result.getOutput());
    }

    @Test
    @DisplayName("Boundary condition - reasoning with unicode characters")
    void testReasoningWithUnicode() {
        String unicodeReasoning = "User has admin privileges and can access all resources";
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                unicodeReasoning,
                null,
                null
        );

        assertEquals(unicodeReasoning, result.getReasoning());
    }

    @Test
    @DisplayName("Boundary condition - error message with special characters")
    void testErrorMessageWithSpecialCharacters() {
        String specialError = "Error: Invalid input at line 10, column 5. Expected '}' but found ']'";
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                null,
                specialError,
                null
        );

        assertEquals(specialError, result.getErrorMessage());
        assertFalse(result.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - output with list values")
    void testOutputWithListValues() {
        Map<String, Object> output = Map.of(
                "rules", List.of("rule1", "rule2", "rule3"),
                "actions", List.of("read", "write", "delete")
        );

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                output
        );

        assertEquals(2, result.getOutput().size());
        assertEquals(3, ((java.util.List<?>) result.getOutput().get("rules")).size());
    }

    @Test
    @DisplayName("Boundary condition - output with nested maps")
    void testOutputWithNestedMaps() {
        Map<String, Object> nested = Map.of(
                "inner_key", "inner_value",
                "inner_number", 123
        );

        Map<String, Object> output = Map.of("outer_key", nested);

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                output
        );

        assertEquals(Map.of("outer_key", nested), result.getOutput());
    }

    @Test
    @DisplayName("Boundary condition - output with mixed types")
    void testOutputWithMixedTypes() {
        // Map.of() does not allow null values, so we need to use a HashMap
        Map<String, Object> output = new java.util.HashMap<>();
        output.put("string_value", "text");
        output.put("number_value", 42);
        output.put("boolean_value", true);
        output.put("list_value", List.of(1, 2, 3));
        output.put("null_value", null);

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
            output
        );

        assertEquals(5, result.getOutput().size());
        assertEquals("text", result.getOutput().get("string_value"));
        assertEquals(42, result.getOutput().get("number_value"));
        assertEquals(true, result.getOutput().get("boolean_value"));
        assertNull(result.getOutput().get("null_value"));
    }

    @Test
    @DisplayName("Boundary condition - allowed true with error message")
    void testAllowedTrueWithErrorMessage() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Access granted with warnings",
                "Some warnings occurred but access is granted",
                null
        );

        assertTrue(result.isAllowed());
        assertEquals("Access granted with warnings", result.getReasoning());
        assertEquals("Some warnings occurred but access is granted", result.getErrorMessage());
        assertFalse(result.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - empty reasoning string")
    void testEmptyReasoningString() {
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "",
                null,
                null
        );

        assertEquals("", result.getReasoning());
    }

    @Test
    @DisplayName("Boundary condition - output with large integer values")
    void testOutputWithLargeIntegerValues() {
        Map<String, Object> output = Map.of(
                "timestamp", System.currentTimeMillis(),
                "count", Integer.MAX_VALUE,
                "total", Long.MAX_VALUE
        );

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                output
        );

        assertEquals(3, result.getOutput().size());
        assertEquals(Long.MAX_VALUE, result.getOutput().get("total"));
    }

    @Test
    @DisplayName("Boundary condition - output with floating point values")
    void testOutputWithFloatingPointValues() {
        Map<String, Object> output = Map.of(
                "pi", 3.14159,
                "e", 2.71828,
                "ratio", 0.618
        );

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Success",
                null,
                output
        );

        assertEquals(3, result.getOutput().size());
        assertEquals(3.14159, result.getOutput().get("pi"));
    }

    @Test
    @DisplayName("Boundary condition - multiple results with same allowed status")
    void testMultipleResultsWithSameAllowedStatus() {
        PolicyEvaluationResult result1 = new PolicyEvaluationResult(
                true,
                "Reason 1",
                null,
                Map.of("key", "value1")
        );

        PolicyEvaluationResult result2 = new PolicyEvaluationResult(
                true,
                "Reason 2",
                null,
                Map.of("key", "value2")
        );

        assertTrue(result1.isAllowed());
        assertTrue(result2.isAllowed());
        assertNotEquals(result1.getReasoning(), result2.getReasoning());
        assertNotEquals(result1.getOutput(), result2.getOutput());
    }
}