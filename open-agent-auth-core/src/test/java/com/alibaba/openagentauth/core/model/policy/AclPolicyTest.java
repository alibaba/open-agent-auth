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

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link AclPolicy}.
 */
@DisplayName("AclPolicy Tests")
class AclPolicyTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("Constructor - create with all fields via JSON")
    void testConstructorWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": [\n" +
                "    {\n" +
                "      \"principal\": \"user1\",\n" +
                "      \"resource\": \"resource1\",\n" +
                "      \"permissions\": [\"read\", \"write\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"principal\": \"user2\",\n" +
                "      \"resource\": \"resource2\",\n" +
                "      \"permissions\": [\"read\"],\n" +
                "      \"effect\": \"DENY\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);

        assertNotNull(policy);
        assertEquals("1.0", policy.getVersion());
        assertEquals(2, policy.getEntries().size());
        assertEquals("user1", policy.getEntries().get(0).getPrincipal());
        assertEquals("resource1", policy.getEntries().get(0).getResource());
        // The business code returns a Set, not a List
        assertEquals(Set.of("read", "write"), policy.getEntries().get(0).getPermissions());
        assertEquals(AclPolicy.AclEffect.ALLOW, policy.getEntries().get(0).getEffect());
    }

    @Test
    @DisplayName("Constructor - default version when null via JSON")
    void testConstructorDefaultVersion() throws Exception {
        String json = "{\n" +
                "  \"version\": null,\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);

        assertEquals("1.0", policy.getVersion());
    }

    @Test
    @DisplayName("Constructor - empty entries when null via JSON")
    void testConstructorEmptyEntries() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": null\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);

        assertNotNull(policy.getEntries());
        assertTrue(policy.getEntries().isEmpty());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() throws Exception {
        String json = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"entries\": [\n" +
                "    {\n" +
                "      \"principal\": \"user1\",\n" +
                "      \"resource\": \"resource1\",\n" +
                "      \"permissions\": [\"read\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);

        assertEquals("2.0", policy.getVersion());
        assertEquals(1, policy.getEntries().size());
        assertEquals("user1", policy.getEntries().get(0).getPrincipal());
        assertEquals("resource1", policy.getEntries().get(0).getResource());
        // The business code returns a Set, not a List
        assertEquals(Set.of("read"), policy.getEntries().get(0).getPermissions());
        assertEquals(AclPolicy.AclEffect.ALLOW, policy.getEntries().get(0).getEffect());
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        assertEquals(policy, policy);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        assertNotEquals(null, policy);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        assertNotEquals("policy", policy);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": [\n" +
                "    {\n" +
                "      \"principal\": \"user1\",\n" +
                "      \"resource\": \"resource1\",\n" +
                "      \"permissions\": [\"read\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AclPolicy policy1 = objectMapper.readValue(json, AclPolicy.class);
        AclPolicy policy2 = objectMapper.readValue(json, AclPolicy.class);

        assertEquals(policy1, policy2);
    }

    @Test
    @DisplayName("equals - different version returns false")
    void testEqualsDifferentVersion() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy1 = objectMapper.readValue(json1, AclPolicy.class);
        AclPolicy policy2 = objectMapper.readValue(json2, AclPolicy.class);

        assertNotEquals(policy1, policy2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": [\n" +
                "    {\n" +
                "      \"principal\": \"user1\",\n" +
                "      \"resource\": \"resource1\",\n" +
                "      \"permissions\": [\"read\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AclPolicy policy1 = objectMapper.readValue(json, AclPolicy.class);
        AclPolicy policy2 = objectMapper.readValue(json, AclPolicy.class);

        assertEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy1 = objectMapper.readValue(json1, AclPolicy.class);
        AclPolicy policy2 = objectMapper.readValue(json2, AclPolicy.class);

        assertNotEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        String result = policy.toString();

        assertTrue(result.contains("1.0"));
        assertTrue(result.contains("AclPolicy"));
    }

    // AclEntry tests
    @Test
    @DisplayName("AclEntry - create with all fields via JSON")
    void testAclEntryWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\", \"write\", \"delete\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);

        assertEquals("user1", entry.getPrincipal());
        assertEquals("resource1", entry.getResource());
        assertEquals(3, entry.getPermissions().size());
        assertTrue(entry.getPermissions().contains("read"));
        assertEquals(AclPolicy.AclEffect.ALLOW, entry.getEffect());
    }

    @Test
    @DisplayName("AclEntry - default effect when null via JSON")
    void testAclEntryDefaultEffect() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": null\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);

        assertEquals(AclPolicy.AclEffect.ALLOW, entry.getEffect());
    }

    @Test
    @DisplayName("AclEntry - empty permissions when null via JSON")
    void testAclEntryEmptyPermissions() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": null,\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);

        assertNotNull(entry.getPermissions());
        assertTrue(entry.getPermissions().isEmpty());
    }

    @Test
    @DisplayName("AclEntry - permissions are immutable")
    void testAclEntryPermissionsImmutable() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\", \"write\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);

        assertThrows(UnsupportedOperationException.class, () -> {
            entry.getPermissions().add("delete");
        });
    }

    @Test
    @DisplayName("AclEntry equals - equal objects")
    void testAclEntryEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry1 = objectMapper.readValue(json, AclPolicy.AclEntry.class);
        AclPolicy.AclEntry entry2 = objectMapper.readValue(json, AclPolicy.AclEntry.class);

        assertEquals(entry1, entry2);
    }

    @Test
    @DisplayName("AclEntry equals - different principal")
    void testAclEntryEqualsDifferentPrincipal() throws Exception {
        String json1 = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        String json2 = "{\n" +
                "  \"principal\": \"user2\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry1 = objectMapper.readValue(json1, AclPolicy.AclEntry.class);
        AclPolicy.AclEntry entry2 = objectMapper.readValue(json2, AclPolicy.AclEntry.class);

        assertNotEquals(entry1, entry2);
    }

    @Test
    @DisplayName("AclEntry hashCode - equal objects have same hash")
    void testAclEntryHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry1 = objectMapper.readValue(json, AclPolicy.AclEntry.class);
        AclPolicy.AclEntry entry2 = objectMapper.readValue(json, AclPolicy.AclEntry.class);

        assertEquals(entry1.hashCode(), entry2.hashCode());
    }

    @Test
    @DisplayName("AclEntry toString - contains all fields")
    void testAclEntryToString() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);
        String result = entry.toString();

        assertTrue(result.contains("user1"));
        assertTrue(result.contains("resource1"));
        assertTrue(result.contains("read"));
        assertTrue(result.contains("ALLOW"));
    }

    @Test
    @DisplayName("AclEffect enum - has ALLOW and DENY")
    void testAclEffectEnum() {
        assertEquals(2, AclPolicy.AclEffect.values().length);
        assertEquals(AclPolicy.AclEffect.ALLOW, AclPolicy.AclEffect.valueOf("ALLOW"));
        assertEquals(AclPolicy.AclEffect.DENY, AclPolicy.AclEffect.valueOf("DENY"));
    }

    @Test
    @DisplayName("Boundary condition - empty entries list")
    void testEmptyEntriesList() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": []\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        assertNotNull(policy.getEntries());
        assertTrue(policy.getEntries().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - multiple entries")
    void testMultipleEntries() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": [\n" +
                "    {\n" +
                "      \"principal\": \"user1\",\n" +
                "      \"resource\": \"resource1\",\n" +
                "      \"permissions\": [\"read\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"principal\": \"user2\",\n" +
                "      \"resource\": \"resource2\",\n" +
                "      \"permissions\": [\"write\"],\n" +
                "      \"effect\": \"DENY\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"principal\": \"user3\",\n" +
                "      \"resource\": \"resource3\",\n" +
                "      \"permissions\": [\"delete\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        assertEquals(3, policy.getEntries().size());
    }

    @Test
    @DisplayName("Boundary condition - entries list is immutable")
    void testEntriesListImmutable() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"entries\": [\n" +
                "    {\n" +
                "      \"principal\": \"user1\",\n" +
                "      \"resource\": \"resource1\",\n" +
                "      \"permissions\": [\"read\"],\n" +
                "      \"effect\": \"ALLOW\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        AclPolicy policy = objectMapper.readValue(json, AclPolicy.class);
        assertThrows(UnsupportedOperationException.class, () -> {
            policy.getEntries().add(null);
        });
    }

    @Test
    @DisplayName("Boundary condition - null principal")
    void testNullPrincipal() throws Exception {
        String json = "{\n" +
                "  \"principal\": null,\n" +
                "  \"resource\": \"resource1\",\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);
        assertNull(entry.getPrincipal());
    }

    @Test
    @DisplayName("Boundary condition - null resource")
    void testNullResource() throws Exception {
        String json = "{\n" +
                "  \"principal\": \"user1\",\n" +
                "  \"resource\": null,\n" +
                "  \"permissions\": [\"read\"],\n" +
                "  \"effect\": \"ALLOW\"\n" +
                "}";

        AclPolicy.AclEntry entry = objectMapper.readValue(json, AclPolicy.AclEntry.class);
        assertNull(entry.getResource());
    }
}