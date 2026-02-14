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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link OpaPolicy}.
 */
@DisplayName("OpaPolicy Tests")
class OpaPolicyTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("Constructor - create with all fields via JSON")
    void testConstructorWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"packageName\": \"authz\",\n" +
                "  \"ruleName\": \"allow\",\n" +
                "  \"regoPolicy\": \"package authz\\nallow { input.user == \\\"admin\\\" }\",\n" +
                "  \"description\": \"Admin authorization policy\",\n" +
                "  \"data\": {\n" +
                "    \"roles\": {\n" +
                "      \"admin\": [\"read\", \"write\"]\n" +
                "    },\n" +
                "    \"resources\": [\"resource1\", \"resource2\"]\n" +
                "  }\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertEquals("2.0", policy.getVersion());
        assertEquals("authz", policy.getPackageName());
        assertEquals("allow", policy.getRuleName());
        assertEquals("package authz\nallow { input.user == \"admin\" }", policy.getRegoPolicy());
        assertEquals("Admin authorization policy", policy.getDescription());
        assertNotNull(policy.getData());
        assertTrue(policy.getData().containsKey("roles"));
    }

    @Test
    @DisplayName("Constructor - default values when null via JSON")
    void testConstructorDefaultValues() throws Exception {
        String json = "{\n" +
                "  \"version\": null,\n" +
                "  \"packageName\": null,\n" +
                "  \"ruleName\": null,\n" +
                "  \"regoPolicy\": null,\n" +
                "  \"description\": null,\n" +
                "  \"data\": null\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertEquals("1.0", policy.getVersion()); // default
        assertEquals("default", policy.getPackageName()); // default
        assertEquals("allow", policy.getRuleName()); // default
        assertNull(policy.getRegoPolicy());
        assertNull(policy.getDescription());
        assertTrue(policy.getData().isEmpty()); // default empty map
    }

    @Test
    @DisplayName("Constructor - minimal fields via JSON")
    void testConstructorWithMinimalFields() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"package authz\\nallow { true }\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertEquals("1.0", policy.getVersion());
        assertEquals("default", policy.getPackageName());
        assertEquals("allow", policy.getRuleName());
        assertEquals("package authz\nallow { true }", policy.getRegoPolicy());
        assertNull(policy.getDescription());
        assertTrue(policy.getData().isEmpty());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.5\",\n" +
                "  \"packageName\": \"mypackage\",\n" +
                "  \"ruleName\": \"myrule\",\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"description\": \"Test\",\n" +
                "  \"data\": {\n" +
                "    \"key\": \"value\"\n" +
                "  }\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertEquals("1.5", policy.getVersion());
        assertEquals("mypackage", policy.getPackageName());
        assertEquals("myrule", policy.getRuleName());
        assertEquals("allow", policy.getRegoPolicy());
        assertEquals("Test", policy.getDescription());
        assertEquals("value", policy.getData().get("key"));
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);
        assertEquals(policy, policy);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);
        assertNotEquals(null, policy);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);
        assertNotEquals("policy", policy);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"packageName\": \"authz\",\n" +
                "  \"ruleName\": \"allow\",\n" +
                "  \"regoPolicy\": \"package authz\\nallow { true }\",\n" +
                "  \"description\": \"Test\",\n" +
                "  \"data\": {\n" +
                "    \"key\": \"value\"\n" +
                "  }\n" +
                "}";

        OpaPolicy policy1 = objectMapper.readValue(json, OpaPolicy.class);
        OpaPolicy policy2 = objectMapper.readValue(json, OpaPolicy.class);

        assertEquals(policy1, policy2);
    }

    @Test
    @DisplayName("equals - different version returns false")
    void testEqualsDifferentVersion() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        OpaPolicy policy1 = objectMapper.readValue(json1, OpaPolicy.class);
        OpaPolicy policy2 = objectMapper.readValue(json2, OpaPolicy.class);

        assertNotEquals(policy1, policy2);
    }

    @Test
    @DisplayName("equals - different regoPolicy returns false")
    void testEqualsDifferentRegoPolicy() throws Exception {
        String json1 = "{\n" +
                "  \"regoPolicy\": \"allow { true }\"\n" +
                "}";

        String json2 = "{\n" +
                "  \"regoPolicy\": \"allow { false }\"\n" +
                "}";

        OpaPolicy policy1 = objectMapper.readValue(json1, OpaPolicy.class);
        OpaPolicy policy2 = objectMapper.readValue(json2, OpaPolicy.class);

        assertNotEquals(policy1, policy2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"packageName\": \"authz\",\n" +
                "  \"ruleName\": \"allow\",\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"description\": \"Test\",\n" +
                "  \"data\": {\n" +
                "    \"key\": \"value\"\n" +
                "  }\n" +
                "}";

        OpaPolicy policy1 = objectMapper.readValue(json, OpaPolicy.class);
        OpaPolicy policy2 = objectMapper.readValue(json, OpaPolicy.class);

        assertEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        OpaPolicy policy1 = objectMapper.readValue(json1, OpaPolicy.class);
        OpaPolicy policy2 = objectMapper.readValue(json2, OpaPolicy.class);

        assertNotEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"packageName\": \"authz\",\n" +
                "  \"ruleName\": \"allow\",\n" +
                "  \"regoPolicy\": \"package authz\\nallow { true }\",\n" +
                "  \"description\": \"Test policy\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);
        String result = policy.toString();

        assertTrue(result.contains("1.0"));
        assertTrue(result.contains("authz"));
        assertTrue(result.contains("allow"));
        assertTrue(result.contains("Test policy"));
        assertTrue(result.contains("OpaPolicy"));
    }

    @Test
    @DisplayName("toString - truncates long regoPolicy")
    void testToStringTruncatesLongRegoPolicy() throws Exception {
        String longPolicy = "package authz\n" + "allow { input.user == \"admin\" }\n".repeat(100);
        String json = "{\n" +
                "  \"regoPolicy\": \"" + longPolicy.replace("\n", "\\n").replace("\"", "\\\"") + "\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);
        String result = policy.toString();

        // The toString should truncate the policy to first 50 chars
        assertTrue(result.contains("..."));
    }

    @Test
    @DisplayName("Boundary condition - empty regoPolicy")
    void testEmptyRegoPolicy() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertEquals("", policy.getRegoPolicy());
    }

    @Test
    @DisplayName("Boundary condition - very long description")
    void testVeryLongDescription() throws Exception {
        String longDescription = "A".repeat(10000);
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"description\": \"" + longDescription + "\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertEquals(longDescription, policy.getDescription());
    }

    @Test
    @DisplayName("Boundary condition - empty data map")
    void testEmptyDataMap() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"data\": {}\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertTrue(policy.getData().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - complex nested data")
    void testComplexNestedData() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"data\": {\n" +
                "    \"users\": {\n" +
                "      \"admin\": [\"read\", \"write\", \"delete\"],\n" +
                "      \"user\": [\"read\"]\n" +
                "    },\n" +
                "    \"resources\": {\n" +
                "      \"db\": [\"table1\", \"table2\"],\n" +
                "      \"api\": [\"/api/v1/*\"]\n" +
                "    }\n" +
                "  }\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNotNull(policy);
        assertEquals(2, policy.getData().size());
        assertTrue(policy.getData().containsKey("users"));
        assertTrue(policy.getData().containsKey("resources"));
    }

    @Test
    @DisplayName("Boundary condition - data map is immutable")
    void testDataMapImmutable() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"data\": {\n" +
                "    \"key\": \"value\"\n" +
                "  }\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertThrows(UnsupportedOperationException.class, () -> {
            policy.getData().put("newKey", "newValue");
        });
    }

    @Test
    @DisplayName("Boundary condition - default values for optional fields")
    void testDefaultValuesForOptionalFields() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertEquals("1.0", policy.getVersion());
        assertEquals("default", policy.getPackageName());
        assertEquals("allow", policy.getRuleName());
        assertTrue(policy.getData().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - null description")
    void testNullDescription() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"description\": null\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNull(policy.getDescription());
    }

    @Test
    @DisplayName("Boundary condition - special characters in packageName")
    void testSpecialCharactersInPackageName() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"packageName\": \"my.package.name\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertEquals("my.package.name", policy.getPackageName());
    }

    @Test
    @DisplayName("Boundary condition - special characters in ruleName")
    void testSpecialCharactersInRuleName() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": \"allow\",\n" +
                "  \"ruleName\": \"allow_admin_access\"\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertEquals("allow_admin_access", policy.getRuleName());
    }

    @Test
    @DisplayName("Boundary condition - null regoPolicy")
    void testNullRegoPolicy() throws Exception {
        String json = "{\n" +
                "  \"regoPolicy\": null\n" +
                "}";

        OpaPolicy policy = objectMapper.readValue(json, OpaPolicy.class);

        assertNull(policy.getRegoPolicy());
    }
}