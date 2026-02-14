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

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ScopePolicyEvaluator}.
 * <p>
 * Tests the OAuth Scope policy evaluator functionality including scope validation,
 * resource access control, RFC 6749/8707 compliance, and caching.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class ScopePolicyEvaluatorTest {

    @Mock
    private PolicyRegistry policyRegistry;

    private ScopePolicyEvaluator evaluator;

    private static final String TEST_POLICY_ID = "test-scope-policy";
    private static final String SCOPE_POLICY_JSON = "{\n" +
            "  \"version\": \"1.0\",\n" +
            "  \"scopes\": [\n" +
            "    {\n" +
            "      \"name\": \"read\",\n" +
            "      \"description\": \"Read access to resources\",\n" +
            "      \"resources\": [\"resource-123\", \"resource-456\"]\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"write\",\n" +
            "      \"description\": \"Write access to resources\",\n" +
            "      \"resources\": [\"resource-123\"]\n" +
            "    },\n" +
            "    {\n" +
            "      \"name\": \"admin\",\n" +
            "      \"description\": \"Admin access to all resources\",\n" +
            "      \"resources\": [\"*\"]\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    @BeforeEach
    void setUp() {
        evaluator = new ScopePolicyEvaluator(policyRegistry);
    }

    @Test
    void testEvaluateWithValidScopeAndResource() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateWithDetailsAllow() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "write");
        inputData.put("resourceId", "resource-123");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertTrue(result.isAllowed());
        assertTrue(result.isSuccess());
        assertTrue(result.getReasoning().contains("Access granted"));
        assertTrue(result.getReasoning().contains("write"));
    }

    @Test
    void testEvaluateWithWildcardResource() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "admin");
        inputData.put("resourceId", "any-resource");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateWithInvalidScope() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "invalid-scope");
        inputData.put("resourceId", "resource-123");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithDetailsInvalidScope() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "invalid-scope");
        inputData.put("resourceId", "resource-123");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertTrue(result.isSuccess());
        assertTrue(result.getReasoning().contains("Scope not found"));
    }

    @Test
    void testEvaluateWithInvalidResourceForScope() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "write");
        inputData.put("resourceId", "resource-456");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithDetailsInvalidResource() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "write");
        inputData.put("resourceId", "resource-999");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertTrue(result.isSuccess());
        assertTrue(result.getReasoning().contains("does not grant access"));
    }

    @Test
    void testEvaluateWithMissingScope() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("resourceId", "resource-123");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertTrue(result.isSuccess());
        assertTrue(result.getReasoning().contains("No scope provided"));
    }

    @Test
    void testEvaluateWithPolicyNotFoundException() {
        // Given
        when(policyRegistry.get(TEST_POLICY_ID)).thenThrow(new PolicyNotFoundException(TEST_POLICY_ID));

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When & Then
        assertThrows(PolicyNotFoundException.class, () -> {
            evaluator.evaluate(TEST_POLICY_ID, inputData);
        });
    }

    @Test
    void testEvaluateWithInvalidPolicyJson() {
        // Given
        String invalidJson = "{ invalid json }";
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(invalidJson)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertFalse(result.isSuccess());
        assertNotNull(result.getErrorMessage());
    }

    @Test
    void testCacheFunctionality() {
        // Given
        ScopePolicyEvaluator cachedEvaluator = new ScopePolicyEvaluator(policyRegistry, true, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When - first evaluation
        cachedEvaluator.evaluate(TEST_POLICY_ID, inputData);
        int cacheSizeAfterFirst = cachedEvaluator.getCacheSize();

        // When - second evaluation (should use cache)
        cachedEvaluator.evaluate(TEST_POLICY_ID, inputData);
        int cacheSizeAfterSecond = cachedEvaluator.getCacheSize();

        // Then
        assertEquals(1, cacheSizeAfterFirst);
        assertEquals(1, cacheSizeAfterSecond);
    }

    @Test
    void testClearCache() {
        // Given
        ScopePolicyEvaluator cachedEvaluator = new ScopePolicyEvaluator(policyRegistry, true, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When
        cachedEvaluator.evaluate(TEST_POLICY_ID, inputData);
        cachedEvaluator.clearCache();

        // Then
        assertEquals(0, cachedEvaluator.getCacheSize());
    }

    @Test
    void testCacheDisabled() {
        // Given
        ScopePolicyEvaluator noCacheEvaluator = new ScopePolicyEvaluator(policyRegistry, false, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When
        noCacheEvaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertEquals(0, noCacheEvaluator.getCacheSize());
    }

    @Test
    void testEvaluateWithMultipleResourcesInScope() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-456");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateOutputContainsScopeAndResource() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(SCOPE_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "resource-123");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertTrue(result.isAllowed());
        Map<String, Object> output = result.getOutput();
        assertTrue(output.containsKey("scope"));
        assertTrue(output.containsKey("resource"));
        assertEquals("read", output.get("scope"));
        assertEquals("resource-123", output.get("resource"));
    }
}
