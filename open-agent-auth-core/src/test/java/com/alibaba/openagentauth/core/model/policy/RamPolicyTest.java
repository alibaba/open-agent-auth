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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RamPolicy}.
 */
@DisplayName("RamPolicy Tests")
class RamPolicyTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("Constructor - create with all fields via JSON")
    void testConstructorWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"statement\": [\n" +
                "    {\n" +
                "      \"effect\": \"ALLOW\",\n" +
                "      \"action\": [\"ecs:DescribeInstances\", \"ecs:StartInstance\"],\n" +
                "      \"resource\": [\"acs:ecs:*:*:instance/i-*\"],\n" +
                "      \"condition\": {\n" +
                "        \"operator\": \"StringEquals\",\n" +
                "        \"key\": \"acs:CurrentUser\",\n" +
                "        \"value\": \"user123\"\n" +
                "      }\n" +
                "    },\n" +
                "    {\n" +
                "      \"effect\": \"DENY\",\n" +
                "      \"action\": [\"ecs:DeleteInstance\"],\n" +
                "      \"resource\": [\"acs:ecs:*:*:instance/*\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);

        assertNotNull(policy);
        assertEquals("2.0", policy.getVersion());
        assertEquals(2, policy.getStatements().size());
        assertEquals(RamPolicy.Effect.ALLOW, policy.getStatements().get(0).getEffect());
        assertEquals(2, policy.getStatements().get(0).getActions().size());
        assertEquals("ecs:DescribeInstances", policy.getStatements().get(0).getActions().get(0));
        assertEquals(RamPolicy.Effect.DENY, policy.getStatements().get(1).getEffect());
    }

    @Test
    @DisplayName("Constructor - default version when null via JSON")
    void testConstructorDefaultVersion() throws Exception {
        String json = "{\n" +
                "  \"version\": null,\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);

        assertEquals("1.0", policy.getVersion());
    }

    @Test
    @DisplayName("Constructor - empty statements when null via JSON")
    void testConstructorEmptyStatements() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": null\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);

        assertNotNull(policy.getStatements());
        assertTrue(policy.getStatements().isEmpty());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() throws Exception {
        String json = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"statement\": [\n" +
                "    {\n" +
                "      \"effect\": \"ALLOW\",\n" +
                "      \"action\": [\"read\", \"write\"],\n" +
                "      \"resource\": [\"resource1\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);

        assertEquals("2.0", policy.getVersion());
        assertEquals(1, policy.getStatements().size());
        assertEquals(RamPolicy.Effect.ALLOW, policy.getStatements().get(0).getEffect());
        assertEquals(List.of("read", "write"), policy.getStatements().get(0).getActions());
        assertEquals(List.of("resource1"), policy.getStatements().get(0).getResources());
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        assertEquals(policy, policy);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        assertNotEquals(null, policy);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        assertNotEquals("policy", policy);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": [\n" +
                "    {\n" +
                "      \"effect\": \"ALLOW\",\n" +
                "      \"action\": [\"read\"],\n" +
                "      \"resource\": [\"resource1\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        RamPolicy policy1 = objectMapper.readValue(json, RamPolicy.class);
        RamPolicy policy2 = objectMapper.readValue(json, RamPolicy.class);

        assertEquals(policy1, policy2);
    }

    @Test
    @DisplayName("equals - different version returns false")
    void testEqualsDifferentVersion() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy1 = objectMapper.readValue(json1, RamPolicy.class);
        RamPolicy policy2 = objectMapper.readValue(json2, RamPolicy.class);

        assertNotEquals(policy1, policy2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": [\n" +
                "    {\n" +
                "      \"effect\": \"ALLOW\",\n" +
                "      \"action\": [\"read\"],\n" +
                "      \"resource\": [\"resource1\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        RamPolicy policy1 = objectMapper.readValue(json, RamPolicy.class);
        RamPolicy policy2 = objectMapper.readValue(json, RamPolicy.class);

        assertEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy1 = objectMapper.readValue(json1, RamPolicy.class);
        RamPolicy policy2 = objectMapper.readValue(json2, RamPolicy.class);

        assertNotEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        String result = policy.toString();

        assertTrue(result.contains("1.0"));
        assertTrue(result.contains("RamPolicy"));
    }

    // RamStatement tests
    @Test
    @DisplayName("RamStatement - create with all fields via JSON")
    void testRamStatementWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\", \"write\", \"delete\"],\n" +
                "  \"resource\": [\"resource1\", \"resource2\"],\n" +
                "  \"condition\": {\n" +
                "    \"operator\": \"StringEquals\",\n" +
                "    \"key\": \"key1\",\n" +
                "    \"value\": \"value1\"\n" +
                "  }\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertEquals(RamPolicy.Effect.ALLOW, statement.getEffect());
        assertEquals(3, statement.getActions().size());
        assertTrue(statement.getActions().contains("read"));
        assertEquals(2, statement.getResources().size());
        assertNotNull(statement.getCondition());
        assertEquals("StringEquals", statement.getCondition().getOperator());
    }

    @Test
    @DisplayName("RamStatement - default effect when null via JSON")
    void testRamStatementDefaultEffect() throws Exception {
        String json = "{\n" +
                "  \"effect\": null,\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertEquals(RamPolicy.Effect.ALLOW, statement.getEffect());
    }

    @Test
    @DisplayName("RamStatement - empty actions when null via JSON")
    void testRamStatementEmptyActions() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": null,\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertNotNull(statement.getActions());
        assertTrue(statement.getActions().isEmpty());
    }

    @Test
    @DisplayName("RamStatement - empty resources when null via JSON")
    void testRamStatementEmptyResources() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": null\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertNotNull(statement.getResources());
        assertTrue(statement.getResources().isEmpty());
    }

    @Test
    @DisplayName("RamStatement - actions list is immutable")
    void testRamStatementActionsImmutable() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\", \"write\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertThrows(UnsupportedOperationException.class, () -> {
            statement.getActions().add("delete");
        });
    }

    @Test
    @DisplayName("RamStatement - resources list is immutable")
    void testRamStatementResourcesImmutable() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\", \"resource2\"]\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertThrows(UnsupportedOperationException.class, () -> {
            statement.getResources().add("resource3");
        });
    }

    @Test
    @DisplayName("RamStatement equals - equal objects")
    void testRamStatementEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement1 = objectMapper.readValue(json, RamPolicy.RamStatement.class);
        RamPolicy.RamStatement statement2 = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertEquals(statement1, statement2);
    }

    @Test
    @DisplayName("RamStatement equals - different effect")
    void testRamStatementEqualsDifferentEffect() throws Exception {
        String json1 = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        String json2 = "{\n" +
                "  \"effect\": \"DENY\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement1 = objectMapper.readValue(json1, RamPolicy.RamStatement.class);
        RamPolicy.RamStatement statement2 = objectMapper.readValue(json2, RamPolicy.RamStatement.class);

        assertNotEquals(statement1, statement2);
    }

    @Test
    @DisplayName("RamStatement hashCode - equal objects have same hash")
    void testRamStatementHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement1 = objectMapper.readValue(json, RamPolicy.RamStatement.class);
        RamPolicy.RamStatement statement2 = objectMapper.readValue(json, RamPolicy.RamStatement.class);

        assertEquals(statement1.hashCode(), statement2.hashCode());
    }

    @Test
    @DisplayName("RamStatement toString - contains all fields")
    void testRamStatementToString() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"]\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);
        String result = statement.toString();

        assertTrue(result.contains("ALLOW"));
        assertTrue(result.contains("read"));
        assertTrue(result.contains("resource1"));
    }

    // Effect enum tests
    @Test
    @DisplayName("Effect enum - has ALLOW and DENY")
    void testEffectEnum() {
        assertEquals(2, RamPolicy.Effect.values().length);
        assertEquals(RamPolicy.Effect.ALLOW, RamPolicy.Effect.valueOf("ALLOW"));
        assertEquals(RamPolicy.Effect.DENY, RamPolicy.Effect.valueOf("DENY"));
    }

    // RamCondition tests
    @Test
    @DisplayName("RamCondition - create with all fields via JSON")
    void testRamConditionWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"operator\": \"StringEquals\",\n" +
                "  \"key\": \"acs:CurrentUser\",\n" +
                "  \"value\": \"user123\"\n" +
                "}";

        RamPolicy.RamCondition condition = objectMapper.readValue(json, RamPolicy.RamCondition.class);

        assertEquals("StringEquals", condition.getOperator());
        assertEquals("acs:CurrentUser", condition.getKey());
        assertEquals("user123", condition.getValue());
    }

    @Test
    @DisplayName("RamCondition - create with null value via JSON")
    void testRamConditionWithNullValue() throws Exception {
        String json = "{\n" +
                "  \"operator\": \"StringEquals\",\n" +
                "  \"key\": \"key1\",\n" +
                "  \"value\": null\n" +
                "}";

        RamPolicy.RamCondition condition = objectMapper.readValue(json, RamPolicy.RamCondition.class);

        assertNull(condition.getValue());
    }

    @Test
    @DisplayName("RamCondition equals - equal objects")
    void testRamConditionEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"operator\": \"StringEquals\",\n" +
                "  \"key\": \"key1\",\n" +
                "  \"value\": \"value1\"\n" +
                "}";

        RamPolicy.RamCondition condition1 = objectMapper.readValue(json, RamPolicy.RamCondition.class);
        RamPolicy.RamCondition condition2 = objectMapper.readValue(json, RamPolicy.RamCondition.class);

        assertEquals(condition1, condition2);
    }

    @Test
    @DisplayName("RamCondition equals - different operator")
    void testRamConditionEqualsDifferentOperator() throws Exception {
        String json1 = "{\n" +
                "  \"operator\": \"StringEquals\",\n" +
                "  \"key\": \"key1\",\n" +
                "  \"value\": \"value1\"\n" +
                "}";

        String json2 = "{\n" +
                "  \"operator\": \"StringNotEquals\",\n" +
                "  \"key\": \"key1\",\n" +
                "  \"value\": \"value1\"\n" +
                "}";

        RamPolicy.RamCondition condition1 = objectMapper.readValue(json1, RamPolicy.RamCondition.class);
        RamPolicy.RamCondition condition2 = objectMapper.readValue(json2, RamPolicy.RamCondition.class);

        assertNotEquals(condition1, condition2);
    }

    @Test
    @DisplayName("RamCondition hashCode - equal objects have same hash")
    void testRamConditionHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"operator\": \"StringEquals\",\n" +
                "  \"key\": \"key1\",\n" +
                "  \"value\": \"value1\"\n" +
                "}";

        RamPolicy.RamCondition condition1 = objectMapper.readValue(json, RamPolicy.RamCondition.class);
        RamPolicy.RamCondition condition2 = objectMapper.readValue(json, RamPolicy.RamCondition.class);

        assertEquals(condition1.hashCode(), condition2.hashCode());
    }

    @Test
    @DisplayName("RamCondition toString - contains all fields")
    void testRamConditionToString() throws Exception {
        String json = "{\n" +
                "  \"operator\": \"StringEquals\",\n" +
                "  \"key\": \"key1\",\n" +
                "  \"value\": \"value1\"\n" +
                "}";

        RamPolicy.RamCondition condition = objectMapper.readValue(json, RamPolicy.RamCondition.class);
        String result = condition.toString();

        assertTrue(result.contains("StringEquals"));
        assertTrue(result.contains("key1"));
        assertTrue(result.contains("value1"));
    }

    @Test
    @DisplayName("Boundary condition - empty statements list")
    void testEmptyStatementsList() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": []\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        assertNotNull(policy.getStatements());
        assertTrue(policy.getStatements().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - multiple statements")
    void testMultipleStatements() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": [\n" +
                "    {\"effect\": \"ALLOW\", \"action\": [\"read\"], \"resource\": [\"r1\"]},\n" +
                "    {\"effect\": \"DENY\", \"action\": [\"write\"], \"resource\": [\"r2\"]},\n" +
                "    {\"effect\": \"ALLOW\", \"action\": [\"delete\"], \"resource\": [\"r3\"]}\n" +
                "  ]\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        assertEquals(3, policy.getStatements().size());
    }

    @Test
    @DisplayName("Boundary condition - statements list is immutable")
    void testStatementsListImmutable() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"statement\": [\n" +
                "    {\"effect\": \"ALLOW\", \"action\": [\"read\"], \"resource\": [\"r1\"]}\n" +
                "  ]\n" +
                "}";

        RamPolicy policy = objectMapper.readValue(json, RamPolicy.class);
        assertThrows(UnsupportedOperationException.class, () -> {
            policy.getStatements().add(null);
        });
    }

    @Test
    @DisplayName("Boundary condition - statement with null condition")
    void testStatementWithNullCondition() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"],\n" +
                "  \"condition\": null\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);
        assertNull(statement.getCondition());
    }

    @Test
    @DisplayName("Boundary condition - statement with complex value in condition")
    void testStatementWithComplexConditionValue() throws Exception {
        String json = "{\n" +
                "  \"effect\": \"ALLOW\",\n" +
                "  \"action\": [\"read\"],\n" +
                "  \"resource\": [\"resource1\"],\n" +
                "  \"condition\": {\n" +
                "    \"operator\": \"ForAllValues:StringEquals\",\n" +
                "    \"key\": \"key1\",\n" +
                "    \"value\": [\"value1\", \"value2\"]\n" +
                "  }\n" +
                "}";

        RamPolicy.RamStatement statement = objectMapper.readValue(json, RamPolicy.RamStatement.class);
        assertNotNull(statement.getCondition());
        assertEquals("ForAllValues:StringEquals", statement.getCondition().getOperator());
    }
}
