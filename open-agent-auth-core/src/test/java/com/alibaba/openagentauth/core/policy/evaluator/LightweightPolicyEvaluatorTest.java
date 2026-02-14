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
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.model.policy.PolicyMetadata;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link LightweightPolicyEvaluator}.
 * <p>
 * Tests the SimplePolicyEvaluator's ability to evaluate basic Rego policies,
 * including allow rules, conditions, and nested input data access.
 * </p>
 * <p>
 * <b>Test Coverage:</b></p>
 * <ul>
 *   <li>Basic allow rule evaluation</li>
 *   <li>Numeric comparison conditions</li>
 *   <li>String comparison conditions</li>
 *   <li>Nested input data access</li>
 *   <li>Policy caching functionality with size limits</li>
 *   <li>Error handling for missing policies</li>
 *   <li>Fail-safe behavior on evaluation errors</li>
 *   <li>Performance metrics tracking</li>
 *   <li>Policy syntax validation</li>
 *   <li>Edge cases and boundary conditions</li>
 * </ul>
 * </p>
 */
@DisplayName("SimplePolicyEvaluator Tests")
class LightweightPolicyEvaluatorTest {

    private LightweightPolicyEvaluator evaluator;
    private PolicyRegistry policyRegistry;

    @BeforeEach
    void setUp() {
        policyRegistry = new TestPolicyRegistry();
        evaluator = new LightweightPolicyEvaluator(policyRegistry);
    }

    @Nested
    @DisplayName("Basic Evaluation Tests")
    class BasicEvaluationTests {

        @Test
        @DisplayName("Should allow when policy has allow { true }")
        void testAllowTrue() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            boolean result = evaluator.evaluate(policyId, new HashMap<>());

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should deny when policy has no allow rule")
        void testNoAllowRule() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\ndefault deny := false");

            // When
            boolean result = evaluator.evaluate(policyId, new HashMap<>());

            // Then - Should return false when no allow rule is present
            assertFalse(result);
        }

        @Test
        @DisplayName("Should evaluate with details successfully")
        void testEvaluateWithDetails() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            PolicyEvaluationResult result = evaluator.evaluateWithDetails(policyId, new HashMap<>());

            // Then
            assertNotNull(result);
            assertTrue(result.isAllowed());
            assertTrue(result.isSuccess());
            assertNotNull(result.getReasoning());
            assertNull(result.getErrorMessage());
        }
    }

    @Nested
    @DisplayName("Numeric Comparison Tests")
    class NumericComparisonTests {

        @Test
        @DisplayName("Should allow when amount is less than limit") void testLessThanOrEqualOperator() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(30);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should deny when amount exceeds limit")
        void testGreaterThanLimit() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow { input.transaction.amount <= 50.0 }"
            );
            Map<String, Object> inputData = createTransactionInput(75.0);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should allow when amount equals limit")
        void testEqualsLimit() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(50);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should support greater than or equal operator")
        void testGreaterThanOrEqual() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount >= 100.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(150);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should deny when amount is below minimum")
        void testBelowMinimum() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount >= 100.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(50);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should support less than operator")
        void testLessThanOperator() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount < 100.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(50);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should support greater than operator")
        void testGreaterThanOperator() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount > 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(75);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should support equality operator")
        void testEqualityOperator() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount == 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(50);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should support inequality operator")
        void testInequalityOperator() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount != 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(75);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }
    }

    @Nested
    @DisplayName("Nested Input Data Tests")
    class NestedInputDataTests {

        @Test
        @DisplayName("Should access nested transaction amount")
        void testNestedAccess() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 100.0\n}"
            );
            Map<String, Object> inputData = new HashMap<>();
            Map<String, Object> transaction = new HashMap<>();
            transaction.put("amount", 80);
            inputData.put("transaction", transaction);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should handle missing nested data gracefully")
        void testMissingNestedData() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 100.0\n}"
            );
            Map<String, Object> inputData = new HashMap<>();

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then - Should default to false when data is missing (fail-safe)
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle null nested values")
        void testNullNestedValues() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow { input.transaction.amount <= 100.0 }"
            );
            Map<String, Object> inputData = new HashMap<>();
            inputData.put("transaction", null);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then - Should default to false (fail-safe) when value is null
            assertFalse(result);
        }
    }

    @Nested
    @DisplayName("String Comparison Tests")
    class StringComparisonTests {

        @Test
        @DisplayName("Should support string equality comparison")
        void testStringEquality() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.user.role == \"admin\"\n}"
            );
            Map<String, Object> inputData = new HashMap<>();
            Map<String, Object> user = new HashMap<>();
            user.put("role", "admin");
            inputData.put("user", user);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should deny on string inequality")
        void testStringInequality() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow { input.user.role == \"admin\" }"
            );
            Map<String, Object> inputData = new HashMap<>();
            Map<String, Object> user = new HashMap<>();
            user.put("role", "user");
            inputData.put("user", user);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should support string not equal comparison")
        void testStringNotEqual() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow { input.user.role != \"guest\" }"
            );
            Map<String, Object> inputData = new HashMap<>();
            Map<String, Object> user = new HashMap<>();
            user.put("role", "admin");
            inputData.put("user", user);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }
    }

    @Nested
    @DisplayName("Cache Tests")
    class CacheTests {

        @Test
        @DisplayName("Should cache compiled policies")
        void testPolicyCaching() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");
            assertEquals(0, evaluator.getCacheSize());

            // When - First evaluation
            evaluator.evaluate(policyId, new HashMap<>());

            // Then
            assertEquals(1, evaluator.getCacheSize());

            // When - Second evaluation (should use cache)
            evaluator.evaluate(policyId, new HashMap<>());

            // Then - Cache size should remain 1
            assertEquals(1, evaluator.getCacheSize());
        }

        @Test
        @DisplayName("Should allow cache to be cleared")
        void testClearCache() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");
            evaluator.evaluate(policyId, new HashMap<>());
            assertEquals(1, evaluator.getCacheSize());

            // When
            evaluator.clearCache();

            // Then
            assertEquals(0, evaluator.getCacheSize());
        }

        @Test
        @DisplayName("Should work with caching disabled")
        void testCacheDisabled() throws PolicyEvaluationException {
            // Given
            LightweightPolicyEvaluator noCacheEvaluator = new LightweightPolicyEvaluator(policyRegistry, false);
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            noCacheEvaluator.evaluate(policyId, new HashMap<>());

            // Then
            assertEquals(0, noCacheEvaluator.getCacheSize());
        }

        @Test
        @DisplayName("Should track cache hits")
        void testCacheHitTracking() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");
            
            // When - First evaluation (cache miss)
            evaluator.evaluate(policyId, new HashMap<>());
            long firstHitCount = evaluator.getCacheHitCount();
            
            // Second evaluation (cache hit)
            evaluator.evaluate(policyId, new HashMap<>());
            long secondHitCount = evaluator.getCacheHitCount();
            
            // Then
            assertEquals(0, firstHitCount);
            assertEquals(1, secondHitCount);
        }

        @Test
        @DisplayName("Should track total evaluation count")
        void testEvaluationCountTracking() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");
            
            // When
            evaluator.evaluate(policyId, new HashMap<>());
            evaluator.evaluate(policyId, new HashMap<>());
            
            // Then
            assertEquals(2, evaluator.getTotalEvaluationCount());
        }

        @Test
        @DisplayName("Should calculate cache hit rate")
        void testCacheHitRate() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");
            
            // When - First evaluation (cache miss)
            evaluator.evaluate(policyId, new HashMap<>());
            double hitRate1 = evaluator.getCacheHitRate();
            
            // Second evaluation (cache hit)
            evaluator.evaluate(policyId, new HashMap<>());
            double hitRate2 = evaluator.getCacheHitRate();
            
            // Then
            assertEquals(0.0, hitRate1, 0.01);
            assertEquals(50.0, hitRate2, 0.01);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception for non-existent policy")
        void testNonExistentPolicy() {
            // Given
            String nonExistentPolicyId = "policy-non-existent";

            // When & Then
            assertThrows(
                    PolicyNotFoundException.class,
                    () -> evaluator.evaluate(nonExistentPolicyId, new HashMap<>())
            );
        }

        @Test
        @DisplayName("Should return false when policy has no allow rule")
        void testEvaluationException() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\ndefault deny := false");

            // When
            boolean result = evaluator.evaluate(policyId, new HashMap<>());

            // Then - Should return false instead of throwing exception
            assertFalse(result);
        }

        @Test
        @DisplayName("Should return error result in evaluateWithDetails")
        void testErrorInEvaluateWithDetails() {
            // Given
            String policyId = registerPolicy("package agent\ndefault deny := false");

            // When
            PolicyEvaluationResult result = evaluator.evaluateWithDetails(
                    policyId,
                    new HashMap<>()
            );

            // Then
            assertNotNull(result);
            assertTrue(result.isSuccess());
            assertFalse(result.isAllowed());
            assertNull(result.getErrorMessage());
        }

        @Test
        @DisplayName("Should return deny result on evaluation error (fail-safe)")
        void testFailSafeOnError() {
            // Given
            String policyId = registerPolicy("package agent\nallow {\n  input.invalid.path <= 100\n}");
            Map<String, Object> inputData = new HashMap<>();

            // When
            PolicyEvaluationResult result = evaluator.evaluateWithDetails(policyId, inputData);

            // Then - Should return deny instead of throwing exception
            assertNotNull(result);
            assertFalse(result.isAllowed());
            assertTrue(result.getReasoning().contains("DENIED"));
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty input data")
        void testEmptyInputData() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            boolean result = evaluator.evaluate(policyId, new HashMap<>());

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should handle zero amount")
        void testZeroAmount() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(0);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should handle negative amount")
        void testNegativeAmount() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(-10);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should handle very large amounts")
        void testVeryLargeAmount() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow { input.transaction.amount <= 50.0 }"
            );
            Map<String, Object> inputData = createTransactionInput(Double.MAX_VALUE);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertFalse(result);
        }

        @Test
        @DisplayName("Should handle decimal amounts")
        void testDecimalAmounts() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow {\n  input.transaction.amount <= 50.0\n}"
            );
            Map<String, Object> inputData = createTransactionInput(49.99);

            // When
            boolean result = evaluator.evaluate(policyId, inputData);

            // Then
            assertTrue(result);
        }

        @Test
        @DisplayName("Should extract package name correctly")
        void testPackageNameExtraction() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package custom.agent\nallow { true }");

            // When
            PolicyEvaluationResult result = evaluator.evaluateWithDetails(
                    policyId,
                    new HashMap<>()
            );

            // Then
            assertNotNull(result);
            assertTrue(result.isAllowed());
            assertTrue(result.getReasoning().contains("ALLOWED"));
        }

        @Test
        @DisplayName("Should reject policy with unbalanced braces")
        void testUnbalancedBraces() {
            // Given
            String policyId = registerPolicy("package agent\nallow { true");

            // When & Then - Should throw exception for invalid syntax
            assertThrows(
                    PolicyEvaluationException.class,
                    () -> evaluator.evaluate(policyId, new HashMap<>())
            );
        }

        @Test
        @DisplayName("Should reject empty policy")
        void testEmptyPolicy() {
            // Given
            String policyId = registerPolicy("");

            // When & Then - Should throw exception for empty policy
            assertThrows(
                    PolicyEvaluationException.class,
                    () -> evaluator.evaluate(policyId, new HashMap<>())
            );
        }

        @Test
        @DisplayName("Should work with custom cache size")
        void testCustomCacheSize() throws PolicyEvaluationException {
            // Given
            LightweightPolicyEvaluator customEvaluator = new LightweightPolicyEvaluator(policyRegistry, true, 5);
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            customEvaluator.evaluate(policyId, new HashMap<>());

            // Then
            assertEquals(1, customEvaluator.getCacheSize());
        }

        @Test
        @DisplayName("Should handle negative cache size with default")
        void testNegativeCacheSize() throws PolicyEvaluationException {
            // Given
            LightweightPolicyEvaluator customEvaluator = new LightweightPolicyEvaluator(policyRegistry, true, -1);
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            customEvaluator.evaluate(policyId, new HashMap<>());

            // Then - Should use default cache size
            assertTrue(customEvaluator.getCacheSize() > 0);
        }
    }

    @Nested
    @DisplayName("Output Data Tests")
    class OutputDataTests {

        @Test
        @DisplayName("Should include allowed field in output")
        void testOutputContainsAllowed() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy("package agent\nallow { true }");

            // When
            PolicyEvaluationResult result = evaluator.evaluateWithDetails(
                    policyId,
                    new HashMap<>()
            );

            // Then
            assertNotNull(result.getOutput());
            assertEquals(true, result.getOutput().get("allowed"));
        }

        @Test
        @DisplayName("Should include reasoning in result")
        void testReasoningContent() throws PolicyEvaluationException {
            // Given
            String policyId = registerPolicy(
                    "package agent\nallow { true }",
                    "Test policy description"
            );

            // When
            PolicyEvaluationResult result = evaluator.evaluateWithDetails(
                    policyId,
                    new HashMap<>()
            );

            // Then
            assertNotNull(result.getReasoning());
            assertTrue(result.getReasoning().contains("ALLOWED"));
            assertTrue(result.getReasoning().contains("Test policy description"));
        }
    }

    // Helper methods

    private String registerPolicy(String regoPolicy) {
        return registerPolicy(regoPolicy, null);
    }

    private String registerPolicy(String regoPolicy, String description) {
        String policyId = "policy-" + System.currentTimeMillis();
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0")
                .createdAt(Instant.now())
                .createdBy("test-user")
                .expirationTime(Instant.now().plusSeconds(86400))
                .build();
        
        Policy policy = Policy.builder()
                .policyId(policyId)
                .regoPolicy(regoPolicy)
                .description(description)
                .metadata(metadata)
                .build();
        ((TestPolicyRegistry) policyRegistry).addPolicy(policy);
        return policyId;
    }

    private Map<String, Object> createTransactionInput(double amount) {
        Map<String, Object> inputData = new HashMap<>();
        Map<String, Object> transaction = new HashMap<>();
        transaction.put("amount", amount);
        inputData.put("transaction", transaction);
        return inputData;
    }

    /**
     * Simple in-memory policy registry for testing purposes.
     */
    private static class TestPolicyRegistry implements PolicyRegistry {
        private final Map<String, Policy> policies = new HashMap<>();

        public void addPolicy(Policy policy) {
            policies.put(policy.getPolicyId(), policy);
        }

        @Override
        public Policy get(String policyId) throws PolicyNotFoundException {
            Policy policy = policies.get(policyId);
            if (policy == null) {
                throw new PolicyNotFoundException("Policy not found: " + policyId);
            }
            return policy;
        }

        @Override
        public PolicyRegistration register(
                String regoPolicy,
                String description,
                String createdBy,
                Instant expirationTime) {
            // Not used in tests
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public Optional<Policy> get(String policyId, boolean includeExpired) {
            Policy policy = policies.get(policyId);
            return Optional.ofNullable(policy);
        }

        @Override
        public boolean exists(String policyId) {
            return policies.containsKey(policyId);
        }

        @Override
        public Policy update(String policyId, String regoPolicy, String description) {
            throw new UnsupportedOperationException("Not implemented");
        }

        @Override
        public void delete(String policyId) {
            policies.remove(policyId);
        }

        @Override
        public List<Policy> listAll() {
            return new ArrayList<>(policies.values());
        }

        @Override
        public List<Policy> listByCreator(String createdBy) {
            return new ArrayList<>();
        }

        @Override
        public List<Policy> listExpired() {
            return new ArrayList<>();
        }

        @Override
        public int cleanupExpired() {
            return 0;
        }

        @Override
        public int size() {
            return policies.size();
        }
    }
}
