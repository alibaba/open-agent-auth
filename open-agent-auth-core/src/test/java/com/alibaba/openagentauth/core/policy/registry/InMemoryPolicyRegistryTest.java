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
package com.alibaba.openagentauth.core.policy.registry;

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.exception.policy.PolicyRegistrationException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link InMemoryPolicyRegistry}.
 * <p>
 * Tests the core functionality of the in-memory policy registry including
 * registration, retrieval, update, deletion, and lifecycle management.
 * </p>
 */
class InMemoryPolicyRegistryTest {

    private InMemoryPolicyRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new InMemoryPolicyRegistry();
    }

    @Test
    void testRegisterPolicy() throws PolicyRegistrationException {
        // Given
        String regoPolicy = "package agent\nallow { input.transaction.amount <= 50.0 }";
        String description = "Allow transactions under $50";
        String createdBy = "test-user";

        // When
        PolicyRegistration result = registry.register(regoPolicy, description, createdBy, null);

        // Then
        assertNotNull(result);
        assertTrue(result.isSuccess());
        assertNotNull(result.getPolicy());
        assertEquals(regoPolicy, result.getPolicy().getRegoPolicy());
        assertEquals(description, result.getPolicy().getDescription());
        assertEquals(createdBy, result.getPolicy().getMetadata().getCreatedBy());
    }

    @Test
    void testRegisterPolicyWithEmptyRegoPolicy() {
        // When & Then
        assertThrows(PolicyRegistrationException.class,
                () -> registry.register("", "description", "user", null));
    }

    @Test
    void testRegisterPolicyWithNullCreator() {
        // Given
        String regoPolicy = "package agent\nallow { true }";

        // When & Then
        assertThrows(PolicyRegistrationException.class,
                () -> registry.register(regoPolicy, "description", null, null));
    }

    @Test
    void testGetPolicy() throws PolicyRegistrationException, PolicyNotFoundException {
        // Given
        String regoPolicy = "package agent\nallow { true }";
        PolicyRegistration registration = registry.register(regoPolicy, "Test policy", "user", null);
        String policyId = registration.getPolicy().getPolicyId();

        // When
        Policy policy = registry.get(policyId);

        // Then
        assertNotNull(policy);
        assertEquals(policyId, policy.getPolicyId());
        assertEquals(regoPolicy, policy.getRegoPolicy());
    }

    @Test
    void testGetNonExistentPolicy() {
        // When & Then
        assertThrows(PolicyNotFoundException.class,
                () -> registry.get("non-existent-id"));
    }

    @Test
    void testGetPolicyOpt() throws PolicyRegistrationException {
        // Given
        PolicyRegistration registration = registry.register("package agent\nallow { true }", "Test", "user", null);

        // When
        var result1 = registry.get(registration.getPolicy().getPolicyId(), false);
        var result2 = registry.get("non-existent-id", false);

        // Then
        assertTrue(result1.isPresent());
        assertFalse(result2.isPresent());
        assertEquals(registration.getPolicy().getPolicyId(), result1.get().getPolicyId());
    }

    @Test
    void testExists() throws PolicyRegistrationException {
        // Given
        PolicyRegistration registration = registry.register("package agent\nallow { true }", "Test", "user", null);

        // When & Then
        assertTrue(registry.exists(registration.getPolicy().getPolicyId()));
        assertFalse(registry.exists("non-existent-id"));
    }

    @Test
    void testUpdatePolicy() throws PolicyRegistrationException, PolicyNotFoundException {
        // Given
        PolicyRegistration registration = registry.register("package agent\nallow { true }", "Test", "user", null);
        String policyId = registration.getPolicy().getPolicyId();
        String newRegoPolicy = "package agent\nallow { input.amount <= 100.0 }";
        String newDescription = "Updated policy";

        // When
        Policy updated = registry.update(policyId, newRegoPolicy, newDescription);

        // Then
        assertNotNull(updated);
        assertEquals(newRegoPolicy, updated.getRegoPolicy());
        assertEquals(newDescription, updated.getDescription());
        // Original metadata should be preserved
        assertEquals(registration.getPolicy().getMetadata().getCreatedBy(),
                     updated.getMetadata().getCreatedBy());
    }

    @Test
    void testUpdateNonExistentPolicy() {
        // When & Then
        assertThrows(PolicyNotFoundException.class,
                () -> registry.update("non-existent-id", "package agent\nallow { true }", "desc"));
    }

    @Test
    void testDeletePolicy() throws PolicyRegistrationException, PolicyNotFoundException {
        // Given
        PolicyRegistration registration = registry.register("package agent\nallow { true }", "Test", "user", null);
        String policyId = registration.getPolicy().getPolicyId();

        // When
        registry.delete(policyId);

        // Then
        assertFalse(registry.exists(policyId));
        assertThrows(PolicyNotFoundException.class, () -> registry.get(policyId));
    }

    @Test
    void testDeleteNonExistentPolicy() {
        // When & Then
        assertThrows(PolicyNotFoundException.class,
                () -> registry.delete("non-existent-id"));
    }

    @Test
    void testListAll() throws PolicyRegistrationException {
        // Given
        registry.register("package agent\nallow { true }", "Policy 1", "user1", null);
        registry.register("package agent\nallow { false }", "Policy 2", "user2", null);

        // When
        List<Policy> policies = registry.listAll();

        // Then
        assertNotNull(policies);
        assertEquals(2, policies.size());
    }

    @Test
    void testListByCreator() throws PolicyRegistrationException {
        // Given
        registry.register("package agent\nallow { true }", "Policy 1", "user1", null);
        registry.register("package agent\nallow { false }", "Policy 2", "user1", null);
        registry.register("package agent\nallow { true }", "Policy 3", "user2", null);

        // When
        List<Policy> user1Policies = registry.listByCreator("user1");
        List<Policy> user2Policies = registry.listByCreator("user2");

        // Then
        assertEquals(2, user1Policies.size());
        assertEquals(1, user2Policies.size());
    }

    @Test
    void testListExpired() throws PolicyRegistrationException {
        // Given
        Instant pastExpiration = Instant.now().minusSeconds(3600);
        Instant futureExpiration = Instant.now().plusSeconds(3600);
        
        registry.register("package agent\nallow { true }", "Expired policy", "user", pastExpiration);
        registry.register("package agent\nallow { false }", "Valid policy", "user", futureExpiration);

        // When
        List<Policy> expiredPolicies = registry.listExpired();

        // Then
        assertEquals(1, expiredPolicies.size());
        assertEquals("Expired policy", expiredPolicies.get(0).getDescription());
    }

    @Test
    void testCleanupExpired() throws PolicyRegistrationException {
        // Given
        Instant pastExpiration = Instant.now().minusSeconds(3600);
        Instant futureExpiration = Instant.now().plusSeconds(3600);
        
        registry.register("package agent\nallow { true }", "Expired 1", "user", pastExpiration);
        registry.register("package agent\nallow { false }", "Expired 2", "user", pastExpiration);
        registry.register("package agent\nallow { true }", "Valid", "user", futureExpiration);

        // When
        int cleaned = registry.cleanupExpired();

        // Then
        assertEquals(2, cleaned);
        assertEquals(1, registry.size());
        assertTrue(registry.exists(registry.listAll().get(0).getPolicyId()));
    }

    @Test
    void testSize() throws PolicyRegistrationException {
        // Given
        assertEquals(0, registry.size());
        
        registry.register("package agent\nallow { true }", "Policy 1", "user", null);
        registry.register("package agent\nallow { false }", "Policy 2", "user", null);

        // When & Then
        assertEquals(2, registry.size());
    }

    @Test
    void testClear() throws PolicyRegistrationException {
        // Given
        registry.register("package agent\nallow { true }", "Policy 1", "user", null);
        registry.register("package agent\nallow { false }", "Policy 2", "user", null);

        // When
        registry.clear();

        // Then
        assertEquals(0, registry.size());
        assertTrue(registry.listAll().isEmpty());
    }

    @Test
    void testGetExpiredPolicyIsExcluded() throws PolicyRegistrationException {
        // Given
        Instant pastExpiration = Instant.now().minusSeconds(3600);
        PolicyRegistration registration = registry.register(
                "package agent\nallow { true }", "Expired", "user", pastExpiration);

        // When
        var result = registry.get(registration.getPolicy().getPolicyId(), false);

        // Then
        assertFalse(result.isPresent());
    }

    @Test
    void testGetExpiredPolicyIsIncludedWithFlag() throws PolicyRegistrationException {
        // Given
        Instant pastExpiration = Instant.now().minusSeconds(3600);
        PolicyRegistration registration = registry.register(
                "package agent\nallow { true }", "Expired", "user", pastExpiration);

        // When
        var result = registry.get(registration.getPolicy().getPolicyId(), true);

        // Then
        assertTrue(result.isPresent());
        assertEquals(registration.getPolicy().getPolicyId(), result.get().getPolicyId());
    }
}
