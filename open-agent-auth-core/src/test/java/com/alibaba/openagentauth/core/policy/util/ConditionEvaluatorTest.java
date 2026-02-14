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
package com.alibaba.openagentauth.core.policy.util;

import com.alibaba.openagentauth.core.model.policy.RamPolicy;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ConditionEvaluator}.
 * <p>
 * Tests the RAM condition evaluation functionality including all supported operators:
 * - String operators: StringEquals, StringNotEquals, StringContains, StringStartsWith, StringEndsWith
 * - Numeric operators: NumericLessThan, NumericLessThanEquals, NumericGreaterThan, NumericGreaterThanEquals
 * - Boolean operators: Bool, Null, NotNull
 * - Date operators: DateLessThan, DateGreaterThan
 * - IP operators: IpInRange
 * </p>
 */
class ConditionEvaluatorTest {

    private final ConditionEvaluator evaluator = new ConditionEvaluator();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Helper method to create a RamCondition using Jackson's ObjectMapper.
     * This is necessary because RamCondition's constructor is private and uses @JsonCreator.
     */
    private RamPolicy.RamCondition createCondition(String operator, String key, Object value) {
        try {
            String json = String.format("{\"operator\":\"%s\",\"key\":\"%s\",\"value\":%s}",
                    operator, key, objectMapper.writeValueAsString(value));
            return objectMapper.readValue(json, RamPolicy.RamCondition.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create condition", e);
        }
    }

    // ==================== String Operators ====================

    @Test
    void testStringEquals_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", "role", "admin");
        Map<String, Object> inputData = Map.of("role", "admin");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testStringEquals_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", "role", "admin");
        Map<String, Object> inputData = Map.of("role", "user");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testStringNotEquals_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringNotEquals", "role", "admin");
        Map<String, Object> inputData = Map.of("role", "user");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testStringNotEquals_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringNotEquals", "role", "admin");
        Map<String, Object> inputData = Map.of("role", "admin");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testStringContains_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringContains", "email", "@example.com");
        Map<String, Object> inputData = Map.of("email", "user@example.com");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testStringContains_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringContains", "email", "@example.com");
        Map<String, Object> inputData = Map.of("email", "user@other.com");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testStringStartsWith_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringStartsWith", "path", "/api/");
        Map<String, Object> inputData = Map.of("path", "/api/users");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testStringStartsWith_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringStartsWith", "path", "/api/");
        Map<String, Object> inputData = Map.of("path", "/web/users");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testStringEndsWith_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEndsWith", "file", ".pdf");
        Map<String, Object> inputData = Map.of("file", "document.pdf");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testStringEndsWith_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEndsWith", "file", ".pdf");
        Map<String, Object> inputData = Map.of("file", "document.doc");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    // ==================== Numeric Operators ====================

    @Test
    void testNumericLessThan_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericLessThan", "age", 18);
        Map<String, Object> inputData = Map.of("age", 16);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testNumericLessThan_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericLessThan", "age", 18);
        Map<String, Object> inputData = Map.of("age", 20);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testNumericLessThanEquals_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericLessThanEquals", "age", 18);
        Map<String, Object> inputData = Map.of("age", 18);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testNumericLessThanEquals_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericLessThanEquals", "age", 18);
        Map<String, Object> inputData = Map.of("age", 19);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testNumericGreaterThan_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericGreaterThan", "age", 18);
        Map<String, Object> inputData = Map.of("age", 20);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testNumericGreaterThan_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericGreaterThan", "age", 18);
        Map<String, Object> inputData = Map.of("age", 16);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testNumericGreaterThanEquals_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericGreaterThanEquals", "age", 18);
        Map<String, Object> inputData = Map.of("age", 18);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testNumericGreaterThanEquals_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericGreaterThanEquals", "age", 18);
        Map<String, Object> inputData = Map.of("age", 17);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testNumericComparison_WithDoubleValues() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericGreaterThan", "price", 10.5);
        Map<String, Object> inputData = Map.of("price", 10.6);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    // ==================== Boolean Operators ====================

    @Test
    void testBool_True() {
        // Given
        RamPolicy.RamCondition condition = createCondition("Bool", "isActive", true);
        Map<String, Object> inputData = Map.of("isActive", true);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testBool_False() {
        // Given
        RamPolicy.RamCondition condition = createCondition("Bool", "isActive", true);
        Map<String, Object> inputData = Map.of("isActive", false);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testNull_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("Null", "deletedAt", null);
        Map<String, Object> inputData = Map.of("deletedAt", "2024-01-01");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testNotNull_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NotNull", "deletedAt", null);
        Map<String, Object> inputData = Map.of("deletedAt", "2024-01-01");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    // ==================== Date Operators ====================

    @Test
    void testDateComparison_WithString() {
        // Given
        RamPolicy.RamCondition condition = createCondition("DateLessThan", "expiresAt", "2024-12-31T23:59:59Z");
        Map<String, Object> inputData = Map.of("expiresAt", "2024-01-01T00:00:00Z");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testDateComparison_WithLong() {
        // Given
        long timestamp = System.currentTimeMillis();
        RamPolicy.RamCondition condition = createCondition("DateLessThan", "expiresAt", timestamp);
        Map<String, Object> inputData = Map.of("expiresAt", timestamp - 3600000);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    // ==================== IP Range Operators ====================

    @Test
    void testIpInRange_Match() {
        // Given
        RamPolicy.RamCondition condition = createCondition("IpInRange", "ipAddress", "192.168.1.*");
        Map<String, Object> inputData = Map.of("ipAddress", "192.168.1.100");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testIpInRange_NoMatch() {
        // Given
        RamPolicy.RamCondition condition = createCondition("IpInRange", "ipAddress", "192.168.1.*");
        Map<String, Object> inputData = Map.of("ipAddress", "10.0.0.1");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    // ==================== Nested Key Support ====================

    @Test
    void testEvaluateWithNestedKey() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", "user.role", "admin");
        Map<String, Object> nestedData = new HashMap<>();
        nestedData.put("role", "admin");
        Map<String, Object> inputData = Map.of("user", nestedData);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateWithDeeplyNestedKey() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", "user.profile.settings.theme", "dark");
        Map<String, Object> themeData = Map.of("theme", "dark");
        Map<String, Object> settingsData = Map.of("settings", themeData);
        Map<String, Object> profileData = Map.of("profile", settingsData);
        Map<String, Object> inputData = Map.of("user", profileData);

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertTrue(result);
    }

    @Test
    void testEvaluateWithNestedKey_PathNotFound() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", "user.role", "admin");
        Map<String, Object> inputData = Map.of("user", Map.of("name", "John"));

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    // ==================== Edge Cases ====================

    @Test
    void testEvaluateWithNullInputData() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", "role", "admin");
        Map<String, Object> inputData = null;

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithNullConditionKey() {
        // Given
        RamPolicy.RamCondition condition = createCondition("StringEquals", null, "admin");
        Map<String, Object> inputData = Map.of("role", "admin");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithUnknownOperator() {
        // Given
        RamPolicy.RamCondition condition = createCondition("UnknownOperator", "role", "admin");
        Map<String, Object> inputData = Map.of("role", "admin");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithInvalidNumericComparison() {
        // Given
        RamPolicy.RamCondition condition = createCondition("NumericGreaterThan", "age", 18);
        Map<String, Object> inputData = Map.of("age", "not a number");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    @Test
    void testEvaluateWithInvalidDateComparison() {
        // Given
        RamPolicy.RamCondition condition = createCondition("DateLessThan", "expiresAt", "2024-12-31");
        Map<String, Object> inputData = Map.of("expiresAt", "invalid date");

        // When
        boolean result = evaluator.evaluate(condition, inputData);

        // Then
        assertFalse(result);
    }

    // ==================== Complex Scenarios ====================

    @Test
    void testEvaluateMultipleConditions() {
        // Given
        RamPolicy.RamCondition condition1 = createCondition("StringEquals", "role", "admin");
        RamPolicy.RamCondition condition2 = createCondition("Bool", "isActive", true);
        Map<String, Object> inputData = Map.of("role", "admin", "isActive", true);

        // When
        boolean result1 = evaluator.evaluate(condition1, inputData);
        boolean result2 = evaluator.evaluate(condition2, inputData);

        // Then
        assertTrue(result1);
        assertTrue(result2);
    }

    @Test
    void testEvaluateWithMixedDataTypes() {
        // Given
        Map<String, Object> inputData = new HashMap<>();
        inputData.put("name", "John");
        inputData.put("age", 25);
        inputData.put("active", true);
        inputData.put("score", 95.5);
        
        RamPolicy.RamCondition stringCondition = createCondition("StringEquals", "name", "John");
        RamPolicy.RamCondition numericCondition = createCondition("NumericGreaterThan", "age", 20);
        RamPolicy.RamCondition boolCondition = createCondition("Bool", "active", true);
        RamPolicy.RamCondition doubleCondition = createCondition("NumericGreaterThan", "score", 90.0);

        // When
        boolean result1 = evaluator.evaluate(stringCondition, inputData);
        boolean result2 = evaluator.evaluate(numericCondition, inputData);
        boolean result3 = evaluator.evaluate(boolCondition, inputData);
        boolean result4 = evaluator.evaluate(doubleCondition, inputData);

        // Then
        assertTrue(result1);
        assertTrue(result2);
        assertTrue(result3);
        assertTrue(result4);
    }
}
