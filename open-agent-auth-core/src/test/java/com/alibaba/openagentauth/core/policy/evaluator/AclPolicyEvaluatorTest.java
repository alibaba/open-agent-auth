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
 * Unit tests for {@link AclPolicyEvaluator}.
 * <p>
 * Tests the ACL policy evaluator functionality including entry matching,
 * effect handling, principal matching, and caching.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class AclPolicyEvaluatorTest {

    @Mock
    private PolicyRegistry policyRegistry;

    private AclPolicyEvaluator evaluator;

    private static final String TEST_POLICY_ID = "test-acl-policy";
    private static final String ACL_POLICY_JSON = "{\n" +
            "  \"version\": \"1.0\",\n" +
            "  \"entries\": [\n" +
            "    {\n" +
            "      \"principal\": \"user-123\",\n" +
            "      \"resource\": \"resource-123\",\n" +
            "      \"permissions\": [\"read\", \"write\"],\n" +
            "      \"effect\": \"ALLOW\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"principal\": \"user-456\",\n" +
            "      \"resource\": \"*\",\n" +
            "      \"permissions\": [\"read\"],\n" +
            "      \"effect\": \"ALLOW\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"principal\": \"*\",\n" +
            "      \"resource\": \"forbidden-resource\",\n" +
            "      \"permissions\": [\"*\"],\n" +
            "      \"effect\": \"DENY\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";

    @BeforeEach
    void setUp() {
        evaluator = new AclPolicyEvaluator(policyRegistry);
    }

    @Test
    void testEvaluateWithDenyEntry() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "forbidden-resource");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithDetailsDeny() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "forbidden-resource");

        // When
        PolicyEvaluationResult result = evaluator.evaluateWithDetails(TEST_POLICY_ID, inputData);

        // Then
        assertNotNull(result);
        assertFalse(result.isAllowed());
        assertTrue(result.isSuccess());
        assertTrue(result.getReasoning().contains("DENY"));
    }

    @Test
    void testEvaluateWithWildcardPrincipal() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "read");
        inputData.put("resourceId", "forbidden-resource");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithNoMatchingEntry() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("operationType", "delete");
        inputData.put("resourceId", "resource-999");

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
        AclPolicyEvaluator cachedEvaluator = new AclPolicyEvaluator(policyRegistry, true, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
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
        AclPolicyEvaluator cachedEvaluator = new AclPolicyEvaluator(policyRegistry, true, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
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
        AclPolicyEvaluator noCacheEvaluator = new AclPolicyEvaluator(policyRegistry, false, 10);
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
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
    void testEvaluateWithMissingPrincipal() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
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
                .regoPolicy(ACL_POLICY_JSON)
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
    void testEvaluateWithMissingPermission() {
        // Given
        Policy policy = Policy.builder()
                .policyId(TEST_POLICY_ID)
                .regoPolicy(ACL_POLICY_JSON)
                .build();
        when(policyRegistry.get(TEST_POLICY_ID)).thenReturn(policy);

        Map<String, Object> inputData = new HashMap<>();
        inputData.put("resourceId", "resource-123");

        // When
        boolean result = evaluator.evaluate(TEST_POLICY_ID, inputData);

        // Then
        assertFalse(result);
    }
}
