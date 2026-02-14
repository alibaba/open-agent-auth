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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link Policy}.
 */
@DisplayName("Policy Tests")
class PolicyTest {

    @Test
    @DisplayName("Builder pattern - build with all fields")
    void testBuilderWithAllFields() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(Instant.now().plusSeconds(3600))
                .tags(Map.of("environment", "production"))
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-123")
                .regoPolicy("package authz\nallow { true }")
                .description("Test policy")
                .metadata(metadata)
                .build();

        assertNotNull(policy);
        assertEquals("policy-123", policy.getPolicyId());
        assertEquals("package authz\nallow { true }", policy.getRegoPolicy());
        assertEquals("Test policy", policy.getDescription());
        assertEquals(metadata, policy.getMetadata());
    }

    @Test
    @DisplayName("Builder pattern - build with null values")
    void testBuilderWithNullValues() {
        Policy policy = Policy.builder()
                .policyId(null)
                .regoPolicy(null)
                .description(null)
                .metadata(null)
                .build();

        assertNotNull(policy);
        assertNull(policy.getPolicyId());
        assertNull(policy.getRegoPolicy());
        assertNull(policy.getDescription());
        assertNull(policy.getMetadata());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-456")
                .regoPolicy("package authz\nallow { input.user == \"admin\" }")
                .description("Admin policy")
                .metadata(metadata)
                .build();

        assertEquals("policy-456", policy.getPolicyId());
        assertEquals("package authz\nallow { input.user == \"admin\" }", policy.getRegoPolicy());
        assertEquals("Admin policy", policy.getDescription());
        assertEquals(metadata, policy.getMetadata());
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() {
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .build();

        assertEquals(policy, policy);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() {
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .build();

        assertNotEquals(null, policy);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() {
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .build();

        assertNotEquals("policy-001", policy);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        Policy policy1 = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("package authz\nallow { true }")
                .description("Test")
                .metadata(metadata)
                .build();

        Policy policy2 = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("package authz\nallow { true }")
                .description("Test")
                .metadata(metadata)
                .build();

        assertEquals(policy1, policy2);
    }

    @Test
    @DisplayName("equals - different policyId returns false")
    void testEqualsDifferentPolicyId() {
        Policy policy1 = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .build();

        Policy policy2 = Policy.builder()
                .policyId("policy-002")
                .regoPolicy("allow")
                .build();

        assertNotEquals(policy1, policy2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        Policy policy1 = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .description("Test")
                .metadata(metadata)
                .build();

        Policy policy2 = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .description("Test")
                .metadata(metadata)
                .build();

        assertEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() {
        Policy policy1 = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .build();

        Policy policy2 = Policy.builder()
                .policyId("policy-002")
                .regoPolicy("allow")
                .build();

        assertNotEquals(policy1.hashCode(), policy2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() {
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .description("Test policy")
                .build();

        String result = policy.toString();

        assertTrue(result.contains("policy-001"));
        assertTrue(result.contains("allow"));
        assertTrue(result.contains("Test policy"));
        assertTrue(result.contains("Policy"));
    }

    @Test
    @DisplayName("isExpired - returns true when expired")
    void testIsExpiredReturnsTrue() {
        Instant pastTime = Instant.now().minusSeconds(3600);
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(pastTime)
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .metadata(metadata)
                .build();

        assertTrue(policy.isExpired());
    }

    @Test
    @DisplayName("isExpired - returns false when not expired")
    void testIsExpiredReturnsFalse() {
        Instant futureTime = Instant.now().plusSeconds(3600);
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(futureTime)
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .metadata(metadata)
                .build();

        assertFalse(policy.isExpired());
    }

    @Test
    @DisplayName("isExpired - returns false when metadata is null")
    void testIsExpiredWithNullMetadata() {
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .metadata(null)
                .build();

        assertFalse(policy.isExpired());
    }

    @Test
    @DisplayName("isExpired - returns false when expirationTime is null")
    void testIsExpiredWithNullExpirationTime() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(null)
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .metadata(metadata)
                .build();

        assertFalse(policy.isExpired());
    }

    @Test
    @DisplayName("isValid - returns true when not expired")
    void testIsValidReturnsTrue() {
        Instant futureTime = Instant.now().plusSeconds(3600);
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(futureTime)
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .metadata(metadata)
                .build();

        assertTrue(policy.isValid());
    }

    @Test
    @DisplayName("isValid - returns false when expired")
    void testIsValidReturnsFalse() {
        Instant pastTime = Instant.now().minusSeconds(3600);
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(pastTime)
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .metadata(metadata)
                .build();

        assertFalse(policy.isValid());
    }

    @Test
    @DisplayName("Boundary condition - empty regoPolicy")
    void testEmptyRegoPolicy() {
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("")
                .build();

        assertNotNull(policy);
        assertEquals("", policy.getRegoPolicy());
    }

    @Test
    @DisplayName("Boundary condition - very long description")
    void testVeryLongDescription() {
        String longDescription = "A".repeat(10000);
        Policy policy = Policy.builder()
                .policyId("policy-001")
                .regoPolicy("allow")
                .description(longDescription)
                .build();

        assertNotNull(policy);
        assertEquals(longDescription, policy.getDescription());
    }
}
