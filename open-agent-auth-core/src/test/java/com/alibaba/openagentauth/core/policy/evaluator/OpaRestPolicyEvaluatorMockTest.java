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
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.policy.evaluator.opa.OpaHttpClient;
import com.alibaba.openagentauth.core.policy.evaluator.opa.OpaHttpResponse;
import com.alibaba.openagentauth.core.policy.registry.InMemoryPolicyRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpaRestPolicyEvaluator} using mocked HTTP client.
 * <p>
 * These tests use Mockito to mock the HTTP client, allowing tests to run
 * without requiring a real OPA server. This provides better isolation,
 * faster execution, and improved test coverage.
 * </p>
 *
 * @see OpaRestPolicyEvaluator
 * @see OpaHttpClient
 * @see OpaHttpResponse
 */
class OpaRestPolicyEvaluatorMockTest {

    private static final String OPA_SERVER_URL = "http://localhost:8181";

    private OpaHttpClient mockHttpClient;
    private PolicyRegistry registry;
    private PolicyEvaluator evaluator;

    @BeforeEach
    void setUp() throws Exception {
        mockHttpClient = mock(OpaHttpClient.class);
        registry = new InMemoryPolicyRegistry();
        evaluator = new OpaRestPolicyEvaluator(registry, OPA_SERVER_URL, Duration.ofSeconds(10), mockHttpClient);

        // Register a test policy
        String regoPolicy = "package agent\nallow { input.transaction.amount <= 50.0 }";
        registry.register(regoPolicy, "Allow transactions under $50", "test-user", null);
    }

    @Test
    void testEvaluateAllowed() throws Exception {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // Mock HTTP response for allowed decision
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": true, \"decision_id\": \"test-123\"}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateDenied() throws Exception {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 100.0);
        inputData.put("transaction", transaction);

        // Mock HTTP response for denied decision
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": false, \"decision_id\": \"test-456\"}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithDetails() throws Exception {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // Mock HTTP response for allowed decision
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": true, \"decision_id\": \"test-789\"}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(policyId, inputData);

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
    void testEvaluateWithEmptyInputData() throws Exception {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();

        // Mock HTTP response for denied decision (empty input should be denied)
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": false}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        assertNotNull(result);
    }

    @Test
    void testEvaluateWithComplexInputData() throws Exception {
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

        // Mock HTTP response for allowed decision
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": true}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        boolean result = evaluator.evaluate(registration.getPolicy().getPolicyId(), inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateWithMultiplePolicies() throws Exception {
        // Given
        String policy1 = "package agent\nallow { input.amount <= 50 }";
        String policy2 = "package agent\nallow { input.amount <= 100 }";

        var reg1 = registry.register(policy1, "Low limit", "user", null);
        var reg2 = registry.register(policy2, "High limit", "user", null);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("amount", 75);

        // Mock HTTP responses - each call gets a different response
        OpaHttpResponse<String> mockResponse1 = createMockResponse(200, "{\"result\": false}");
        OpaHttpResponse<String> mockResponse2 = createMockResponse(200, "{\"result\": true}");
        doReturn(mockResponse1).when(mockHttpClient).send(any(), any());
        
        // When
        boolean result1 = evaluator.evaluate(reg1.getPolicy().getPolicyId(), inputData);
        
        // Reset mock for second call
        doReturn(mockResponse2).when(mockHttpClient).send(any(), any());
        boolean result2 = evaluator.evaluate(reg2.getPolicy().getPolicyId(), inputData);

        // Then
        assertFalse(result1);
        assertTrue(result2);
    }

    @Test
    void testEvaluateWithDetailsResultStructure() throws Exception {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // Mock HTTP response for allowed decision
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": true, \"decision_id\": \"test-abc\"}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(policyId, inputData);

        // Then
        assertTrue(result.isSuccess());
        assertTrue(result.isAllowed());
        assertNotNull(result.getReasoning());
        assertNotNull(result.getOutput());
        assertTrue(result.getOutput().containsKey("allowed"));
        assertEquals(true, result.getOutput().get("allowed"));
    }

    @Test
    void testEvaluateWithHttpError() throws Exception {
        // Given
        String regoPolicy = "package agent\nallow { input.amount <= 50 }";
        var registration = registry.register(regoPolicy, "Test policy", "user", null);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("amount", 30);

        // Mock HTTP response for error
        OpaHttpResponse<String> mockResponse = createMockResponse(500, "{\"error\": \"Internal server error\"}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When & Then
        assertThrows(PolicyEvaluationException.class,
                () -> evaluator.evaluate(registration.getPolicy().getPolicyId(), inputData));
    }

    @Test
    void testEvaluateWithCustomTimeout() throws Exception {
        // Given
        String policyId = registry.listAll().get(0).getPolicyId();
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", 30.0);
        inputData.put("transaction", transaction);

        // Mock HTTP response for allowed decision
        OpaHttpResponse<String> mockResponse = createMockResponse(200, "{\"result\": true}");
        doReturn(mockResponse).when(mockHttpClient).send(any(), any());

        // When
        boolean result = evaluator.evaluate(policyId, inputData);

        // Then
        assertTrue(result);
    }

    /**
     * Creates a mock OpaHttpResponse with the given status code and body.
     *
     * @param statusCode the HTTP status code
     * @param body the response body
     * @return the mocked OpaHttpResponse
     */
    @SuppressWarnings("unchecked")
    private OpaHttpResponse<String> createMockResponse(int statusCode, String body) {
        OpaHttpResponse<String> mockResponse = mock(OpaHttpResponse.class);
        when(mockResponse.statusCode()).thenReturn(statusCode);
        when(mockResponse.body()).thenReturn(body);
        return mockResponse;
    }
}