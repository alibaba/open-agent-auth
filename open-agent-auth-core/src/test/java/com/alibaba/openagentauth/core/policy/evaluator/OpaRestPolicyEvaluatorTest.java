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
package com.alibaba.openagentauth.core.policy.evaluator;

import com.alibaba.openagentauth.core.exception.policy.PolicyEvaluationException;
import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.exception.policy.PolicyRegistrationException;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.policy.registry.InMemoryPolicyRegistry;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link OpaRestPolicyEvaluator}.
 * <p>
 * Tests the policy evaluation functionality including basic evaluation,
 * detailed evaluation results, caching, and error handling.
 * </p>
 *
 * <p><b>Note:</b> These tests require an OPA Server running at
 * {@code http://localhost:8181}. If the OPA Server is not available,
 * tests will be skipped automatically.</p>
 */
class OpaRestPolicyEvaluatorTest {

    private static final String OPA_SERVER_URL = "http://localhost:8181";
    private PolicyRegistry registry;
    private PolicyEvaluator evaluator;

    /**
     * Checks if OPA Server is available before running tests.
     *
     * @return true if OPA Server is available, false otherwise
     */
    private boolean isOpaServerAvailable() {
        try {
            HttpURLConnection connection = (HttpURLConnection) URI.create(OPA_SERVER_URL).toURL().openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(1000);
            connection.setReadTimeout(1000);
            connection.connect();
            int responseCode = connection.getResponseCode();
            connection.disconnect();
            return responseCode >= 200 && responseCode < 500;
        } catch (IOException e) {
            return false;
        }
    }

    @BeforeEach
    void setUp() throws PolicyRegistrationException {
        // Skip all tests if OPA Server is not available
        Assumptions.assumeTrue(isOpaServerAvailable(),
                "OPA Server is not available at " + OPA_SERVER_URL +
                ". Skipping OPA integration tests.");

        registry = new InMemoryPolicyRegistry();
        evaluator = new OpaRestPolicyEvaluator(registry, OPA_SERVER_URL);
        
        // Register a test policy
        String regoPolicy = "package agent\nallow { input.transaction.amount <= 50.0 }";
        registry.register(regoPolicy, "Allow transactions under $50", "test-user", null);
    }

    @Test
    void testEvaluateAllowed() throws PolicyNotFoundException, PolicyEvaluationException {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateDenied() throws PolicyNotFoundException, PolicyEvaluationException {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 100.0);
        inputData.put("transaction", transaction);

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithDetails() throws PolicyNotFoundException, PolicyEvaluationException {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // When
        PolicyEvaluationResult result =
                evaluator.evaluateWithDetails(policyId, inputData);

        // Then
        assertNotNull(result);
        assertTrue(result.isSuccess());
        assertTrue(result.isAllowed());
        assertNotNull(result.getReasoning());
        assertNotNull(result.getOutput());
    }

    @Test
    void testEvaluateNonExistentPolicy() {
        // Given
        String nonExistentPolicyId = "non-existent-id";
        Map<String, Object> inputData = new HashMap<>();

        // When & Then
        assertThrows(PolicyNotFoundException.class,
                () -> evaluator.evaluate(nonExistentPolicyId, inputData));
    }

    @Test
    void testEvaluateWithDetailsNonExistentPolicy() {
        // Given
        String nonExistentPolicyId = "non-existent-id";
        Map<String, Object> inputData = new HashMap<>();

        // When & Then
        assertThrows(PolicyNotFoundException.class,
                () -> evaluator.evaluateWithDetails(nonExistentPolicyId, inputData));
    }

    @Test
    void testEvaluateWithEmptyInputData() throws PolicyNotFoundException, PolicyEvaluationException {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        // Should not throw, but may return false due to missing input
        assertNotNull(result);
    }

    @Test
    void testEvaluateWithComplexInputData() throws PolicyNotFoundException,
                                                   PolicyEvaluationException,
                                                   PolicyRegistrationException {
        // Given
        String regoPolicy = "package agent\nallow { input.user.role == \"admin\" }";
        var registration = registry.register(regoPolicy, "Admin only policy", "user", null);

        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> user = new HashMap<>();
        user.put("id", "user-123");
        user.put("role", "admin");
        user.put("authenticated", true);
        inputData.put("user", user);
        inputData.put("action", "delete");

        // When
        boolean result = evaluator.evaluate(registration.getPolicy().getPolicyId(), inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateWithMultiplePolicies() throws PolicyNotFoundException,
                                                   PolicyEvaluationException,
                                                   PolicyRegistrationException {
        // Given
        String policy1 = "package agent\nallow { input.amount <= 50 }";
        String policy2 = "package agent\nallow { input.amount <= 100 }";

        var reg1 = registry.register(policy1, "Low limit", "user", null);
        var reg2 = registry.register(policy2, "High limit", "user", null);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("amount", 75);

        // When
        boolean result1 = evaluator.evaluate(reg1.getPolicy().getPolicyId(), inputData);
        boolean result2 = evaluator.evaluate(reg2.getPolicy().getPolicyId(), inputData);

        // Then
        assertFalse(result1);
        assertTrue(result2);
    }

    @Test
    void testEvaluateWithDetailsResultStructure() throws PolicyNotFoundException,
                                                          PolicyEvaluationException {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // When
        PolicyEvaluationResult result =
                evaluator.evaluateWithDetails(policyId, inputData);

        // Then
        assertTrue(result.isSuccess());
        assertTrue(result.isAllowed());
        assertNotNull(result.getReasoning());
        assertNotNull(result.getOutput());
        assertTrue(result.getOutput().containsKey("allowed"));
        assertEquals(true, result.getOutput().get("allowed"));
    }
}
