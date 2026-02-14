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
 * Unit tests for {@link ScopePolicy}.
 */
@DisplayName("ScopePolicy Tests")
class ScopePolicyTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("Constructor - create with all fields via JSON")
    void testConstructorWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"scopes\": [\n" +
                "    {\n" +
                "      \"name\": \"read\",\n" +
                "      \"description\": \"Read access to resources\",\n" +
                "      \"resources\": [\"/api/v1/read/*\"]\n" +
                "    },\n" +
                "    {\n" +
                "      \"name\": \"write\",\n" +
                "      \"description\": \"Write access to resources\",\n" +
                "      \"resources\": [\"/api/v1/write/*\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);

        assertNotNull(policy);
        assertEquals("2.0", policy.getVersion());
        assertEquals(2, policy.getScopes().size());
        assertEquals("read", policy.getScopes().get(0).getName());
        assertEquals("Read access to resources", policy.getScopes().get(0).getDescription());
        assertEquals(List.of("/api/v1/read/*"), policy.getScopes().get(0).getResources());
    }

    @Test
    @DisplayName("Constructor - default version when null via JSON")
    void testConstructorDefaultVersion() throws Exception {
        String json = "{\n" +
                "  \"version\": null,\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);

        assertEquals("1.0", policy.getVersion());
    }

    @Test
    @DisplayName("Constructor - empty scopes when null via JSON")
    void testConstructorEmptyScopes() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": null\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);

        assertNotNull(policy.getScopes());
        assertTrue(policy.getScopes().isEmpty());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() throws Exception {
        String json = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"scopes\": [\n" +
                "    {\n" +
                "      \"name\": \"admin\",\n" +
                "      \"description\": \"Admin access\",\n" +
                "      \"resources\": [\"/api/admin/*\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);

        assertEquals("2.0", policy.getVersion());
        assertEquals(1, policy.getScopes().size());
        assertEquals("admin", policy.getScopes().get(0).getName());
        assertEquals("Admin access", policy.getScopes().get(0).getDescription());
        assertEquals(List.of("/api/admin/*"), policy.getScopes().get(0).getResources());
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        assertEquals(policy, policy);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        assertNotEquals(null, policy);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        assertNotEquals("policy", policy);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": [\n" +
                "    {\n" +
                "      \"name\": \"read\",\n" +
                "      \"description\": \"Read access\",\n" +
                "      \"resources\": [\"/api/read/*\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        ScopePolicy policy1 = objectMapper.readValue(json, ScopePolicy.class);
        ScopePolicy policy2 = objectMapper.readValue(json, ScopePolicy.class);

        assertEquals(policy1, policy2);
    }

    @Test
    @DisplayName("equals - different version returns false")
    void testEqualsDifferentVersion() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy1 = objectMapper.readValue(json1, ScopePolicy.class);
        ScopePolicy policy2 = objectMapper.readValue(json2, ScopePolicy.class);

        assertNotEquals(policy1, policy2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": [\n" +
                "    {\n" +
                "      \"name\": \"read\",\n" +
                "      \"description\": \"Read access\",\n" +
                "      \"resources\": [\"/api/read/*\"]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        ScopePolicy policy1 = objectMapper.readValue(json, ScopePolicy.class);
        ScopePolicy policy2 = objectMapper.readValue(json, ScopePolicy.class);

        assertEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() throws Exception {
        String json1 = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        String json2 = "{\n" +
                "  \"version\": \"2.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy1 = objectMapper.readValue(json1, ScopePolicy.class);
        ScopePolicy policy2 = objectMapper.readValue(json2, ScopePolicy.class);

        assertNotEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        String result = policy.toString();

        assertTrue(result.contains("1.0"));
        assertTrue(result.contains("ScopePolicy"));
    }

    // ScopeDefinition tests
    @Test
    @DisplayName("ScopeDefinition - create with all fields via JSON")
    void testScopeDefinitionWithAllFields() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access to resources\",\n" +
                "  \"resources\": [\"/api/v1/read/*\", \"/api/v2/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);

        assertEquals("read", scope.getName());
        assertEquals("Read access to resources", scope.getDescription());
        assertEquals(2, scope.getResources().size());
        assertTrue(scope.getResources().contains("/api/v1/read/*"));
    }

    @Test
    @DisplayName("ScopeDefinition - empty resources when null via JSON")
    void testScopeDefinitionEmptyResources() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": null\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);

        assertNotNull(scope.getResources());
        assertTrue(scope.getResources().isEmpty());
    }

    @Test
    @DisplayName("ScopeDefinition - resources list is immutable")
    void testScopeDefinitionResourcesImmutable() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);

        assertThrows(UnsupportedOperationException.class, () -> {
            scope.getResources().add("/api/write/*");
        });
    }

    @Test
    @DisplayName("ScopeDefinition equals - equal objects")
    void testScopeDefinitionEqualsEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope1 = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        ScopePolicy.ScopeDefinition scope2 = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);

        assertEquals(scope1, scope2);
    }

    @Test
    @DisplayName("ScopeDefinition equals - different name")
    void testScopeDefinitionEqualsDifferentName() throws Exception {
        String json1 = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        String json2 = "{\n" +
                "  \"name\": \"write\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope1 = objectMapper.readValue(json1, ScopePolicy.ScopeDefinition.class);
        ScopePolicy.ScopeDefinition scope2 = objectMapper.readValue(json2, ScopePolicy.ScopeDefinition.class);

        assertNotEquals(scope1, scope2);
    }

    @Test
    @DisplayName("ScopeDefinition hashCode - equal objects have same hash")
    void testScopeDefinitionHashCodeEqualObjects() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope1 = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        ScopePolicy.ScopeDefinition scope2 = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);

        assertEquals(scope1.hashCode(), scope2.hashCode());
    }

    @Test
    @DisplayName("ScopeDefinition toString - contains all fields")
    void testScopeDefinitionToString() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        String result = scope.toString();

        assertTrue(result.contains("read"));
        assertTrue(result.contains("Read access"));
        assertTrue(result.contains("/api/read/*"));
    }

    @Test
    @DisplayName("Boundary condition - empty scopes list")
    void testEmptyScopesList() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": []\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        assertNotNull(policy.getScopes());
        assertTrue(policy.getScopes().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - multiple scopes")
    void testMultipleScopes() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": [\n" +
                "    {\"name\": \"read\", \"description\": \"Read\", \"resources\": [\"/r\"]},\n" +
                "    {\"name\": \"write\", \"description\": \"Write\", \"resources\": [\"/w\"]},\n" +
                "    {\"name\": \"delete\", \"description\": \"Delete\", \"resources\": [\"/d\"]}\n" +
                "  ]\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        assertEquals(3, policy.getScopes().size());
    }

    @Test
    @DisplayName("Boundary condition - scopes list is immutable")
    void testScopesListImmutable() throws Exception {
        String json = "{\n" +
                "  \"version\": \"1.0\",\n" +
                "  \"scopes\": [\n" +
                "    {\"name\": \"read\", \"description\": \"Read\", \"resources\": [\"/r\"]}\n" +
                "  ]\n" +
                "}";

        ScopePolicy policy = objectMapper.readValue(json, ScopePolicy.class);
        assertThrows(UnsupportedOperationException.class, () -> {
            policy.getScopes().add(null);
        });
    }

    @Test
    @DisplayName("Boundary condition - scope with null description")
    void testScopeWithNullDescription() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": null,\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        assertNull(scope.getDescription());
    }

    @Test
    @DisplayName("Boundary condition - scope with single resource")
    void testScopeWithSingleResource() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        assertEquals(1, scope.getResources().size());
    }

    @Test
    @DisplayName("Boundary condition - scope with multiple resources")
    void testScopeWithMultipleResources() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/v1/read/*\", \"/api/v2/read/*\", \"/api/v3/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        assertEquals(3, scope.getResources().size());
    }

    @Test
    @DisplayName("Boundary condition - scope with wildcard resources")
    void testScopeWithWildcardResources() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"Read access\",\n" +
                "  \"resources\": [\"/api/*\", \"*\", \"*.example.com\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        assertEquals(3, scope.getResources().size());
        assertTrue(scope.getResources().contains("*"));
    }

    @Test
    @DisplayName("Boundary condition - scope name with special characters")
    void testScopeNameWithSpecialCharacters() throws Exception {
        String json = "{\n" +
                "  \"name\": \"scope.read.write\",\n" +
                "  \"description\": \"Read and write access\",\n" +
                "  \"resources\": [\"/api/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        assertEquals("scope.read.write", scope.getName());
    }

    @Test
    @DisplayName("Boundary condition - scope description with unicode characters")
    void testScopeDescriptionWithUnicode() throws Exception {
        String json = "{\n" +
                "  \"name\": \"read\",\n" +
                "  \"description\": \"read permission\",\n" +
                "  \"resources\": [\"/api/read/*\"]\n" +
                "}";

        ScopePolicy.ScopeDefinition scope = objectMapper.readValue(json, ScopePolicy.ScopeDefinition.class);
        assertEquals("read permission", scope.getDescription());
    }
}
