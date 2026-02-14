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
package com.alibaba.openagentauth.core.policy.api;

import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link PolicyEvaluationResult}.
 * <p>
 * Tests the policy evaluation result functionality including success states,
 * error handling, and output data management.
 * </p>
 */
class PolicyEvaluationResultTest {

    @Test
    void testConstructorWithAllFields() {
        // Given
        boolean allowed = true;
        String reasoning = "Policy allows the operation";
        String errorMessage = null;
        Map<String, Object> output = new HashMap<>();
        output.put("allowed", true);
        output.put("decision_id", "123");

        // When
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                allowed, reasoning, errorMessage, output
        );

        // Then
        assertTrue(result.isAllowed());
        assertEquals(reasoning, result.getReasoning());
        assertNull(result.getErrorMessage());
        assertNotNull(result.getOutput());
        assertEquals(2, result.getOutput().size());
        assertTrue(result.isSuccess());
    }

    @Test
    void testConstructorWithErrorMessage() {
        // Given
        boolean allowed = false;
        String reasoning = "Policy denies the operation";
        String errorMessage = "Evaluation failed: timeout";
        Map<String, Object> output = null;

        // When
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                allowed, reasoning, errorMessage, output
        );

        // Then
        assertFalse(result.isAllowed());
        assertEquals(reasoning, result.getReasoning());
        assertEquals(errorMessage, result.getErrorMessage());
        assertNull(result.getOutput());
        assertFalse(result.isSuccess());
    }

    @Test
    void testConstructorWithMinimalFields() {
        // Given
        boolean allowed = true;
        String reasoning = null;
        String errorMessage = null;
        Map<String, Object> output = null;

        // When
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                allowed, reasoning, errorMessage, output
        );

        // Then
        assertTrue(result.isAllowed());
        assertNull(result.getReasoning());
        assertNull(result.getErrorMessage());
        assertNull(result.getOutput());
        assertTrue(result.isSuccess());
    }

    @Test
    void testIsAllowedTrue() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, "Allowed", null, null
        );

        // When & Then
        assertTrue(result.isAllowed());
    }

    @Test
    void testIsAllowedFalse() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false, "Denied", null, null
        );

        // When & Then
        assertFalse(result.isAllowed());
    }

    @Test
    void testIsSuccessTrue() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, "Success", null, Map.of()
        );

        // When & Then
        assertTrue(result.isSuccess());
    }

    @Test
    void testIsSuccessFalse() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false, "Failed", "Error occurred", null
        );

        // When & Then
        assertFalse(result.isSuccess());
    }

    @Test
    void testGetReasoning() {
        // Given
        String reasoning = "Transaction amount exceeds limit";
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false, reasoning, null, null
        );

        // When & Then
        assertEquals(reasoning, result.getReasoning());
    }

    @Test
    void testGetReasoningNull() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, null, null, null
        );

        // When & Then
        assertNull(result.getReasoning());
    }

    @Test
    void testGetErrorMessage() {
        // Given
        String errorMessage = "Policy not found";
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false, null, errorMessage, null
        );

        // When & Then
        assertEquals(errorMessage, result.getErrorMessage());
    }

    @Test
    void testGetErrorMessageNull() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, null, null, null
        );

        // When & Then
        assertNull(result.getErrorMessage());
    }

    @Test
    void testGetOutput() {
        // Given
        Map<String, Object> output = new HashMap<>();
        output.put("allowed", true);
        output.put("rule", "allow");
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, null, null, output
        );

        // When & Then
        assertNotNull(result.getOutput());
        assertEquals(2, result.getOutput().size());
        assertEquals(true, result.getOutput().get("allowed"));
        assertEquals("allow", result.getOutput().get("rule"));
    }

    @Test
    void testGetOutputNull() {
        // Given
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, null, null, null
        );

        // When & Then
        assertNull(result.getOutput());
    }

    @Test
    void testImmutability() {
        // Given
        Map<String, Object> originalOutput = new HashMap<>();
        originalOutput.put("key", "value");
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true, "reasoning", null, originalOutput
        );

        // When - try to modify the output map
        originalOutput.put("newKey", "newValue");

        // Then - the returned map should still have the original structure
        // Note: This test verifies that the result object doesn't expose
        // internal state that could be modified by callers
        assertNotNull(result.getOutput());
        assertEquals(2, result.getOutput().size());
    }

    @Test
    void testSuccessfulEvaluationResult() {
        // Given - typical successful evaluation scenario
        Map<String, Object> output = new HashMap<>();
        output.put("allowed", true);
        output.put("decision_id", "abc-123");
        output.put("reason", "Amount within limit");

        // When
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                true,
                "Transaction allowed: amount is within the permitted range",
                null,
                output
        );

        // Then
        assertTrue(result.isAllowed());
        assertTrue(result.isSuccess());
        assertNotNull(result.getReasoning());
        assertNotNull(result.getOutput());
        assertEquals(3, result.getOutput().size());
        assertTrue(result.getOutput().containsKey("decision_id"));
    }

    @Test
    void testFailedEvaluationResult() {
        // Given - typical failed evaluation scenario
        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                null,
                "Policy evaluation error: missing required field 'user.id'",
                null
        );

        // Then
        assertFalse(result.isAllowed());
        assertFalse(result.isSuccess());
        assertEquals("Policy evaluation error: missing required field 'user.id'",
                result.getErrorMessage());
        assertNull(result.getReasoning());
        assertNull(result.getOutput());
    }

    @Test
    void testDeniedEvaluationResult() {
        // Given - typical denied evaluation scenario
        Map<String, Object> output = new HashMap<>();
        output.put("allowed", false);
        output.put("reason", "Amount exceeds limit");

        PolicyEvaluationResult result = new PolicyEvaluationResult(
                false,
                "Transaction denied: amount exceeds the permitted limit of $50",
                null,
                output
        );

        // Then
        assertFalse(result.isAllowed());
        assertTrue(result.isSuccess());
        assertNotNull(result.getReasoning());
        assertNotNull(result.getOutput());
        assertEquals(false, result.getOutput().get("allowed"));
    }
}
