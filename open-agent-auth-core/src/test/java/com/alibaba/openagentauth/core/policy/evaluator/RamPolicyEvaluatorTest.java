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
 * Unit tests for {@link RamPolicyEvaluator}.
 * <p>
 * Tests the RAM policy evaluator functionality including statement evaluation,
 * effect handling, action/resource matching, condition evaluation, and caching.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class RamPolicyEvaluatorTest {

    @Mock
    private PolicyRegistry policyRegistry;

    private RamPolicyEvaluator evaluator;

    private static final String TEST_POLICY_ID = "test-ram-policy";
    private static final String RAM_POLICY_JSON = "{\n" +
            "  \"version\": \"1.0\",\n" +
            "  \"statement\": [\n" +
            "    {\n" +
            "      \"effect\": \"ALLOW\",\n" +
            "      \"action\": [\"read\", \"write\"],\n" +
            "      \"resource\": [\"resource-123\", \"resource-456\"]\n" +
            "    },\n" +
            "    {\n" +
            "      \"effect\": \"DENY\",\n" +
            "      \"action\": [\"delete\"],\n" +
            "      \"resource\": [\"*\"]\n" +
            "    },\n" +
            "    {\n" +
            "      \"effect\": \"ALLOW\",\n" +
            "      \"action\": [\"admin\"],\n" +
            "      \"resource\": [\"*\"],\n" +
            "      \"condition\": {\n" +
            "        \"operator\": \"StringEquals\",\n" +
            "        \"key\": \"role\",\n" +
            "        \"value\": \"admin\"\n" +
            "      }\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    @BeforeEach
    void setUp() {
        evaluator = new RamPolicyEvaluator(policyRegistry);
    }

    @Test
    void testEvaluateWithAllowStatement() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
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
    void testEvaluateWithDenyStatement() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "delete");
        inputData.put("resourceId", "any-resource");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithWildcardResource() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "delete");
        inputData.put("resourceId", "any-resource");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithConditionNotSatisfied() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "admin");
        inputData.put("resourceId", "any-resource");
        inputData.put("role", "user");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithNoMatchingStatement() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "invalid-action");
        inputData.put("resourceId", "resource-123");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
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
        RamPolicyEvaluator cachedEvaluator = new RamPolicyEvaluator(policyRegistry, true, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
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
        RamPolicyEvaluator cachedEvaluator = new RamPolicyEvaluator(policyRegistry, true, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
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
        RamPolicyEvaluator noCacheEvaluator = new RamPolicyEvaluator(policyRegistry, false, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
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
    void testEvaluateWithMissingAction() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("resourceId", "resource-123");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithMissingResource() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(RAM_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testDenyTakesPrecedenceOverAllow() {
        // Given
        String policyWithBothEffects = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": [\n" +
                "    {\n" +
                "      \"effect\": \"ALLOW\",\n" +
                "      \"action\": [\"read\"],\n" +
                "      \"resource\": [\"*\"]\n" +
                "    },\n" +
                "    {\n" +
                "      \"effect\": \"DENY\",\n" +
                "      \"action\": [\"read\"],\n" +
                "      \"resource\": [\"forbidden\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(policyWithBothEffects)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "forbidden");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }
}
