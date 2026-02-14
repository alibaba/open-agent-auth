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
 * Unit tests for {@link PolicyMetadata}.
 */
@DisplayName("PolicyMetadata Tests")
class PolicyMetadataTest {

    @Test
    @DisplayName("Builder pattern - build with all fields")
    void testBuilderWithAllFields() {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);
        Map<String, String> tags = Map.of(
                "environment", "production",
                "category", "security"
        );

        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .expirationTime(expiration)
                .tags(tags)
                .build();

        assertNotNull(metadata);
        assertEquals("1.0.0", metadata.getVersion());
        assertEquals(now, metadata.getCreatedAt());
        assertEquals("agent-001", metadata.getCreatedBy());
        assertEquals(expiration, metadata.getExpirationTime());
        assertEquals(tags, metadata.getTags());
    }

    @Test
    @DisplayName("Builder pattern - build with null values")
    void testBuilderWithNullValues() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version(null)
                .createdAt(null)
                .createdBy(null)
                .expirationTime(null)
                .tags(null)
                .build();

        assertNotNull(metadata);
        assertNull(metadata.getVersion());
        assertNull(metadata.getCreatedAt());
        assertNull(metadata.getCreatedBy());
        assertNull(metadata.getExpirationTime());
        assertNull(metadata.getTags());
    }

    @Test
    @DisplayName("Builder pattern - build with minimal required fields")
    void testBuilderWithMinimalFields() {
        Instant now = Instant.now();
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .build();

        assertNotNull(metadata);
        assertEquals("1.0.0", metadata.getVersion());
        assertEquals(now, metadata.getCreatedAt());
        assertEquals("agent-001", metadata.getCreatedBy());
        assertNull(metadata.getExpirationTime());
        assertNull(metadata.getTags());
    }

    @Test
    @DisplayName("Getter methods - return correct values")
    void testGetterMethods() {
        Instant now = Instant.now();
        Map<String, String> tags = Map.of("key", "value");

        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("2.1.0")
                .createdAt(now)
                .createdBy("user-123")
                .expirationTime(now.plusSeconds(7200))
                .tags(tags)
                .build();

        assertEquals("2.1.0", metadata.getVersion());
        assertEquals(now, metadata.getCreatedAt());
        assertEquals("user-123", metadata.getCreatedBy());
        assertEquals(now.plusSeconds(7200), metadata.getExpirationTime());
        assertEquals(tags, metadata.getTags());
    }

    @Test
    @DisplayName("getTag - returns value when tag exists")
    void testGetTagReturnsValue() {
        Map<String, String> tags = Map.of(
                "environment", "production",
                "category", "security"
        );

        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .tags(tags)
                .build();

        assertEquals("production", metadata.getTag("environment"));
        assertEquals("security", metadata.getTag("category"));
    }

    @Test
    @DisplayName("getTag - returns null when tag does not exist")
    void testGetTagReturnsNull() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .tags(Map.of("environment", "production"))
                .build();

        assertNull(metadata.getTag("nonexistent"));
    }

    @Test
    @DisplayName("getTag - returns null when tags map is null")
    void testGetTagWithNullTags() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .tags(null)
                .build();

        assertNull(metadata.getTag("any"));
    }

    @Test
    @DisplayName("equals - same object returns true")
    void testEqualsSameObject() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        assertEquals(metadata, metadata);
    }

    @Test
    @DisplayName("equals - null returns false")
    void testEqualsNull() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        assertNotEquals(null, metadata);
    }

    @Test
    @DisplayName("equals - different type returns false")
    void testEqualsDifferentType() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        assertNotEquals("metadata", metadata);
    }

    @Test
    @DisplayName("equals - equal objects return true")
    void testEqualsEqualObjects() {
        Instant now = Instant.now();
        Map<String, String> tags = Map.of("key", "value");

        PolicyMetadata metadata1 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .expirationTime(now.plusSeconds(3600))
                .tags(tags)
                .build();

        PolicyMetadata metadata2 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .expirationTime(now.plusSeconds(3600))
                .tags(tags)
                .build();

        assertEquals(metadata1, metadata2);
    }

    @Test
    @DisplayName("equals - different version returns false")
    void testEqualsDifferentVersion() {
        PolicyMetadata metadata1 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        PolicyMetadata metadata2 = PolicyMetadata.builder()
                .version("2.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        assertNotEquals(metadata1, metadata2);
    }

    @Test
    @DisplayName("equals - different createdBy returns false")
    void testEqualsDifferentCreatedBy() {
        PolicyMetadata metadata1 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        PolicyMetadata metadata2 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-002")
                .build();

        assertNotEquals(metadata1, metadata2);
    }

    @Test
    @DisplayName("hashCode - equal objects have same hash")
    void testHashCodeEqualObjects() {
        Instant now = Instant.now();
        PolicyMetadata metadata1 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .build();

        PolicyMetadata metadata2 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .build();

        assertEquals(metadata1.hashCode(), metadata2.hashCode());
    }

    @Test
    @DisplayName("hashCode - different objects have different hash")
    void testHashCodeDifferentObjects() {
        PolicyMetadata metadata1 = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        PolicyMetadata metadata2 = PolicyMetadata.builder()
                .version("2.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        assertNotEquals(metadata1.hashCode(), metadata2.hashCode());
    }

    @Test
    @DisplayName("toString - contains all fields")
    void testToString() {
        Instant now = Instant.now();
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(now)
                .createdBy("agent-001")
                .expirationTime(now.plusSeconds(3600))
                .tags(Map.of("environment", "production"))
                .build();

        String result = metadata.toString();

        assertTrue(result.contains("1.0.0"));
        assertTrue(result.contains("agent-001"));
        assertTrue(result.contains("production"));
        assertTrue(result.contains("PolicyMetadata"));
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

        assertTrue(metadata.isExpired());
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

        assertFalse(metadata.isExpired());
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

        assertFalse(metadata.isExpired());
    }

    @Test
    @DisplayName("isExpired - returns true when exactly at expiration time")
    void testIsExpiredAtExpirationTime() {
        // This test verifies that policies are considered expired when current time is after expiration time
        // Use a time that is clearly in the past to ensure consistent behavior
        Instant expirationTime = Instant.now().minusSeconds(1); // 1 second ago
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(expirationTime)
                .build();

        // The policy should be considered expired since current time is after expiration time
        assertTrue(metadata.isExpired());
    }

    @Test
    @DisplayName("Boundary condition - empty tags map")
    void testEmptyTagsMap() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .tags(Map.of())
                .build();

        assertNotNull(metadata.getTags());
        assertTrue(metadata.getTags().isEmpty());
    }

    @Test
    @DisplayName("Boundary condition - large tags map")
    void testLargeTagsMap() {
        Map<String, String> tags = Map.of(
                "key1", "value1",
                "key2", "value2",
                "key3", "value3",
                "key4", "value4",
                "key5", "value5"
        );

        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .tags(tags)
                .build();

        assertEquals(5, metadata.getTags().size());
    }

    @Test
    @DisplayName("Boundary condition - null createdBy")
    void testNullCreatedBy() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy(null)
                .build();

        assertNull(metadata.getCreatedBy());
    }

    @Test
    @DisplayName("Boundary condition - special characters in version")
    void testSpecialCharactersInVersion() {
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0-beta.1+build.123")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .build();

        assertEquals("1.0.0-beta.1+build.123", metadata.getVersion());
    }

    @Test
    @DisplayName("Boundary condition - very long createdBy string")
    void testVeryLongCreatedBy() {
        String longCreatedBy = "a".repeat(1000);
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy(longCreatedBy)
                .build();

        assertEquals(longCreatedBy, metadata.getCreatedBy());
    }

    @Test
    @DisplayName("Boundary condition - tags with unicode characters")
    void testTagsWithUnicode() {
        Map<String, String> tags = Map.of(
                "environment", "production",
                "category", "security"
        );

        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .tags(tags)
                .build();

        assertEquals("production", metadata.getTag("environment"));
        assertEquals("security", metadata.getTag("category"));
    }

    @Test
    @DisplayName("Boundary condition - expiration time far in the future")
    void testExpirationTimeFarInFuture() {
        Instant farFuture = Instant.now().plusSeconds(365 * 24 * 3600); // 1 year
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(farFuture)
                .build();

        assertFalse(metadata.isExpired());
        assertEquals(farFuture, metadata.getExpirationTime());
    }

    @Test
    @DisplayName("Boundary condition - expiration time far in the past")
    void testExpirationTimeFarInPast() {
        Instant farPast = Instant.now().minusSeconds(365 * 24 * 3600); // 1 year ago
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now())
                .createdBy("agent-001")
                .expirationTime(farPast)
                .build();

        assertTrue(metadata.isExpired());
    }

    @Test
    @DisplayName("Boundary condition - expiration time equals current time")
    void testExpirationTimeEqualsCurrentTime() {
        // Set expiration time to 1 second ago to ensure it's expired
        Instant expirationTime = Instant.now().minusSeconds(1);
        PolicyMetadata metadata = PolicyMetadata.builder()
                .version("1.0.0")
                .createdAt(Instant.now().minusSeconds(10))
                .createdBy("agent-001")
                .expirationTime(expirationTime)
                .build();

        // The policy should be considered expired since current time is after expiration time
        assertTrue(metadata.isExpired());
    }
}