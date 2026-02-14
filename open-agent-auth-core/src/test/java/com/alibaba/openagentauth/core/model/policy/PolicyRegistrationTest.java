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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link PolicyRegistration}.
 */
@DisplayName("PolicyRegistration Tests")
class PolicyRegistrationTest {

    @Test
    @DisplayName("Builder pattern - build with all fields")
    void testBuilderWithAllFields() {
        Instant now = Instant.now();
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-123")
                .regoPolicy("package authz\nallow { true }")
                .description("Test policy")
                .metadata(metadata)
                .build();

        PolicyRegistration registration = PolicyRegistration.builder()
                .policy(policy)
                .originalProposal("package authz\nallow { true }")
                .registeredAt(now)
                .status("SUCCESS")
                .failureReason(null)
                .build();

        assertNotNull(registration);
        assertEquals(policy, registration.getPolicy());
        assertEquals("package authz\nallow { true }", registration.getOriginalProposal());
        assertEquals(now, registration.getRegisteredAt());
        assertEquals("SUCCESS", registration.getStatus());
        assertNull(registration.getFailureReason());
    }

    @Test
    @DisplayName("Builder pattern - build with null values")
    void testBuilderWithNullValues() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .policy(null)
                .originalProposal(null)
                .registeredAt(null)
                .status(null)
                .failureReason(null)
                .build();

        assertNotNull(registration);
        assertNull(registration.getPolicy());
        assertNull(registration.getOriginalProposal());
        assertNull(registration.getRegisteredAt());
        assertNull(registration.getStatus());
        assertNull(registration.getFailureReason());
    }

    @Test
    @DisplayName("Builder pattern - build with failure status")
    void testBuilderWithFailureStatus() {
        Instant now = Instant.now();
        PolicyRegistration registration = PolicyRegistration.builder()
                .policy(null)
                .originalProposal("invalid policy")
                .registeredAt(now)
                .status("FAILED")
                .failureReason("INVALID_SYNTAX")
                .build();

        assertNotNull(registration);
        assertEquals("FAILED", registration.getStatus());
        assertEquals("INVALID_SYNTAX", registration.getFailureReason());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() {
        Instant now = Instant.now();
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-456")
                .regoPolicy("allow")
                .metadata(metadata)
                .build();

        PolicyRegistration registration = PolicyRegistration.builder()
                .policy(policy)
                .originalProposal("original proposal")
                .registeredAt(now)
                .status("SUCCESS")
                .build();

        assertEquals(policy, registration.getPolicy());
        assertEquals("original proposal", registration.getOriginalProposal());
        assertEquals(now, registration.getRegisteredAt());
        assertEquals("SUCCESS", registration.getStatus());
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        assertEquals(registration, registration);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        assertNotEquals(null, registration);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        assertNotEquals("registration", registration);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() {
        Instant now = Instant.now();
        PolicyRegistration registration1 = PolicyRegistration.builder()
                .status("SUCCESS")
                .registeredAt(now)
                .originalProposal("proposal")
                .build();

        PolicyRegistration registration2 = PolicyRegistration.builder()
                .status("SUCCESS")
                .registeredAt(now)
                .originalProposal("proposal")
                .build();

        assertEquals(registration1, registration2);
    }

    @Test
    @DisplayName("equals - different status returns false")
    void testEqualsDifferentStatus() {
        PolicyRegistration registration1 = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        PolicyRegistration registration2 = PolicyRegistration.builder()
                .status("FAILED")
                .build();

        assertNotEquals(registration1, registration2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() {
        Instant now = Instant.now();
        PolicyRegistration registration1 = PolicyRegistration.builder()
                .status("SUCCESS")
                .registeredAt(now)
                .build();

        PolicyRegistration registration2 = PolicyRegistration.builder()
                .status("SUCCESS")
                .registeredAt(now)
                .build();

        assertEquals(registration1.hashCode(), registration2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() {
        PolicyRegistration registration1 = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        PolicyRegistration registration2 = PolicyRegistration.builder()
                .status("FAILED")
                .build();

        assertNotEquals(registration1.hashCode(), registration2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() {
        Instant now = Instant.now();
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("SUCCESS")
                .registeredAt(now)
                .originalProposal("proposal")
                .build();

        String result = registration.toString();

        assertTrue(result.contains("SUCCESS"));
        assertTrue(result.contains("proposal"));
        assertTrue(result.contains("PolicyRegistration"));
    }

    @Test
    @DisplayName("isSuccess - returns true when status is SUCCESS")
    void testIsSuccessReturnsTrue() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        assertTrue(registration.isSuccess());
    }

    @Test
    @DisplayName("isSuccess - returns false when status is not SUCCESS")
    void testIsSuccessReturnsFalse() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("FAILED")
                .build();

        assertFalse(registration.isSuccess());
    }

    @Test
    @DisplayName("isSuccess - returns false when status is null")
    void testIsSuccessWithNullStatus() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status(null)
                .build();

        assertFalse(registration.isSuccess());
    }

    @Test
    @DisplayName("isSuccess - returns false when status is PENDING_VALIDATION")
    void testIsSuccessWithPendingStatus() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("PENDING_VALIDATION")
                .build();

        assertFalse(registration.isSuccess());
    }

    @Test
    @DisplayName("isFailed - returns true when status is FAILED")
    void testIsFailedReturnsTrue() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("FAILED")
                .build();

        assertTrue(registration.isFailed());
    }

    @Test
    @DisplayName("isFailed - returns false when status is not FAILED")
    void testIsFailedReturnsFalse() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("SUCCESS")
                .build();

        assertFalse(registration.isFailed());
    }

    @Test
    @DisplayName("isFailed - returns false when status is null")
    void testIsFailedWithNullStatus() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status(null)
                .build();

        assertFalse(registration.isFailed());
    }

    @Test
    @DisplayName("isFailed - returns false when status is PENDING_VALIDATION")
    void testIsFailedWithPendingStatus() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("PENDING_VALIDATION")
                .build();

        assertFalse(registration.isFailed());
    }

    @Test
    @DisplayName("Boundary condition - very long original proposal")
    void testVeryLongOriginalProposal() {
        String longProposal = "package authz\n" + "allow { true }\n".repeat(100);
        PolicyRegistration registration = PolicyRegistration.builder()
                .originalProposal(longProposal)
                .status("SUCCESS")
                .build();

        assertEquals(longProposal, registration.getOriginalProposal());
    }

    @Test
    @DisplayName("Boundary condition - very long failure reason")
    void testVeryLongFailureReason() {
        String longReason = "A".repeat(10000);
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("FAILED")
                .failureReason(longReason)
                .build();

        assertEquals(longReason, registration.getFailureReason());
    }

    @Test
    @DisplayName("Boundary condition - null policy with SUCCESS status")
    void testNullPolicyWithSuccessStatus() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .policy(null)
                .status("SUCCESS")
                .build();

        assertNull(registration.getPolicy());
        assertTrue(registration.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - empty original proposal")
    void testEmptyOriginalProposal() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .originalProposal("")
                .status("SUCCESS")
                .build();

        assertEquals("", registration.getOriginalProposal());
    }

    @Test
    @DisplayName("Boundary condition - empty failure reason")
    void testEmptyFailureReason() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("FAILED")
                .failureReason("")
                .build();

        assertEquals("", registration.getFailureReason());
    }

    @Test
    @DisplayName("Boundary condition - registered at different times")
    void testRegisteredAtDifferentTimes() {
        Instant time1 = Instant.now();
        Instant time2 = time1.plusSeconds(10);

        PolicyRegistration registration1 = PolicyRegistration.builder()
                .registeredAt(time1)
                .status("SUCCESS")
                .build();

        PolicyRegistration registration2 = PolicyRegistration.builder()
                .registeredAt(time2)
                .status("SUCCESS")
                .build();

        assertEquals(time1, registration1.getRegisteredAt());
        assertEquals(time2, registration2.getRegisteredAt());
        assertNotEquals(registration1, registration2);
    }

    @Test
    @DisplayName("Boundary condition - failure reason with special characters")
    void testFailureReasonWithSpecialCharacters() {
        String specialReason = "Error: Invalid syntax at line 10, column 5. Expected '{' but found '['";
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("FAILED")
                .failureReason(specialReason)
                .build();

        assertEquals(specialReason, registration.getFailureReason());
    }

    @Test
    @DisplayName("Boundary condition - original proposal with unicode characters")
    void testOriginalProposalWithUnicode() {
        String unicodeProposal = "package authz\n# 这是一个中文注释\nallow { input.user == \"管理员\" }";
        PolicyRegistration registration = PolicyRegistration.builder()
                .originalProposal(unicodeProposal)
                .status("SUCCESS")
                .build();

        assertEquals(unicodeProposal, registration.getOriginalProposal());
    }

    @Test
    @DisplayName("Boundary condition - case sensitive status comparison")
    void testCaseSensitiveStatusComparison() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status("success")
                .build();

        assertFalse(registration.isSuccess());
        assertFalse(registration.isFailed());
    }

    @Test
    @DisplayName("Boundary condition - status with whitespace")
    void testStatusWithWhitespace() {
        PolicyRegistration registration = PolicyRegistration.builder()
                .status(" SUCCESS ")
                .build();

        assertFalse(registration.isSuccess());
    }

    @Test
    @DisplayName("Boundary condition - registration with policy and metadata")
    void testRegistrationWithPolicyAndMetadata() {
        Instant now = Instant.now();
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .expirationTime(now.plusSeconds(3600))
                .build();

        Policy policy = Policy.builder()
                .policyId("policy-123")
                .regoPolicy("allow")
                .description("Test")
                .metadata(metadata)
                .build();

        PolicyRegistration registration = PolicyRegistration.builder()
                .policy(policy)
                .originalProposal("allow")
                .registeredAt(now)
                .status("SUCCESS")
                .build();

        assertEquals(policy, registration.getPolicy());
        assertEquals("policy-123", registration.getPolicy().getPolicyId());
        assertNotNull(registration.getPolicy().getMetadata());
        assertFalse(registration.getPolicy().getMetadata().isExpired());
    }
}
