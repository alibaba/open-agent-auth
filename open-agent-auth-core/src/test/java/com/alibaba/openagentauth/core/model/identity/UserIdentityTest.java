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
package com.alibaba.openagentauth.core.model.identity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link UserIdentity}.
 * <p>
 * This test class validates the behavior of the UserIdentity class,
 * which represents user identity information in the authorization framework.
 * </p>
 */
@DisplayName("UserIdentity Tests")
class UserIdentityTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build identity with required field")
        void shouldBuildIdentityWithRequiredField() {
            // Given
            String subject = "user-123";

            // When
            UserIdentity identity = UserIdentity.builder()
                    .subject(subject)
                    .build();

            // Then
            assertNotNull(identity);
            assertEquals(subject, identity.getSubject());
            assertNull(identity.getName());
            assertNull(identity.getEmail());
            assertNull(identity.getEmailVerified());
            assertNull(identity.getAuthTime());
            assertNull(identity.getAttributes());
        }

        @Test
        @DisplayName("Should build identity with all fields")
        void shouldBuildIdentityWithAllFields() {
            // Given
            String subject = "user-456";
            String name = "John Doe";
            String email = "john@example.com";
            Boolean emailVerified = true;
            Instant authTime = Instant.now();
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("role", "admin");
            attributes.put("department", "engineering");

            // When
            UserIdentity identity = UserIdentity.builder()
                    .subject(subject)
                    .name(name)
                    .email(email)
                    .emailVerified(emailVerified)
                    .authTime(authTime)
                    .attributes(attributes)
                    .build();

            // Then
            assertNotNull(identity);
            assertEquals(subject, identity.getSubject());
            assertEquals(name, identity.getName());
            assertEquals(email, identity.getEmail());
            assertEquals(emailVerified, identity.getEmailVerified());
            assertEquals(authTime, identity.getAuthTime());
            assertEquals(attributes, identity.getAttributes());
        }

        @Test
        @DisplayName("Should throw exception when subject is null")
        void shouldThrowExceptionWhenSubjectIsNull() {
            // When & Then
            assertThrows(IllegalArgumentException.class, () -> {
                UserIdentity.builder()
                        .subject(null)
                        .build();
            });
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            // Given
            String subject = "user-789";

            // When
            UserIdentity identity = UserIdentity.builder()
                    .subject(subject)
                    .name("Jane Doe")
                    .email("jane@example.com")
                    .emailVerified(false)
                    .authTime(Instant.now())
                    .attributes(Map.of("key", "value"))
                    .build();

            // Then
            assertNotNull(identity);
            assertEquals(subject, identity.getSubject());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return subject")
        void shouldReturnSubject() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .build();

            // When
            String subject = identity.getSubject();

            // Then
            assertEquals("user-001", subject);
        }

        @Test
        @DisplayName("Should return name")
        void shouldReturnName() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .name("Alice")
                    .build();

            // When
            String name = identity.getName();

            // Then
            assertEquals("Alice", name);
        }

        @Test
        @DisplayName("Should return email")
        void shouldReturnEmail() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .email("alice@example.com")
                    .build();

            // When
            String email = identity.getEmail();

            // Then
            assertEquals("alice@example.com", email);
        }

        @Test
        @DisplayName("Should return email verified status")
        void shouldReturnEmailVerifiedStatus() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .emailVerified(true)
                    .build();

            // When
            Boolean emailVerified = identity.getEmailVerified();

            // Then
            assertTrue(emailVerified);
        }

        @Test
        @DisplayName("Should return auth time")
        void shouldReturnAuthTime() {
            // Given
            Instant authTime = Instant.parse("2024-01-01T00:00:00Z");
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .authTime(authTime)
                    .build();

            // When
            Instant result = identity.getAuthTime();

            // Then
            assertEquals(authTime, result);
        }

        @Test
        @DisplayName("Should return attributes")
        void shouldReturnAttributes() {
            // Given
            Map<String, Object> attributes = Map.of("role", "user", "level", 1);
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .attributes(attributes)
                    .build();

            // When
            Map<String, Object> result = identity.getAttributes();

            // Then
            assertEquals(attributes, result);
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            UserIdentity identity1 = UserIdentity.builder()
                    .subject("user-001")
                    .name("Alice")
                    .email("alice@example.com")
                    .emailVerified(true)
                    .authTime(Instant.parse("2024-01-01T00:00:00Z"))
                    .attributes(Map.of("role", "admin"))
                    .build();

            UserIdentity identity2 = UserIdentity.builder()
                    .subject("user-001")
                    .name("Alice")
                    .email("alice@example.com")
                    .emailVerified(true)
                    .authTime(Instant.parse("2024-01-01T00:00:00Z"))
                    .attributes(Map.of("role", "admin"))
                    .build();

            // Then
            assertEquals(identity1, identity2);
            assertEquals(identity1.hashCode(), identity2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when subjects differ")
        void shouldNotBeEqualWhenSubjectsDiffer() {
            // Given
            UserIdentity identity1 = UserIdentity.builder()
                    .subject("user-001")
                    .build();

            UserIdentity identity2 = UserIdentity.builder()
                    .subject("user-002")
                    .build();

            // Then
            assertNotEquals(identity1, identity2);
        }

        @Test
        @DisplayName("Should not be equal when emails differ")
        void shouldNotBeEqualWhenEmailsDiffer() {
            // Given
            UserIdentity identity1 = UserIdentity.builder()
                    .subject("user-001")
                    .email("alice@example.com")
                    .build();

            UserIdentity identity2 = UserIdentity.builder()
                    .subject("user-001")
                    .email("bob@example.com")
                    .build();

            // Then
            assertNotEquals(identity1, identity2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .build();

            // Then
            assertEquals(identity, identity);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .build();

            // Then
            assertNotEquals(identity, null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .build();

            // Then
            assertNotEquals(identity, "string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include subject in toString")
        void shouldIncludeSubjectInToString() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .build();

            // When
            String result = identity.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("UserIdentity"));
            assertTrue(result.contains("user-001"));
        }

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // Given
            UserIdentity identity = UserIdentity.builder()
                    .subject("user-001")
                    .name("Alice")
                    .email("alice@example.com")
                    .emailVerified(true)
                    .authTime(Instant.parse("2024-01-01T00:00:00Z"))
                    .attributes(Map.of("role", "admin"))
                    .build();

            // When
            String result = identity.toString();

            // Then
            assertNotNull(result);
            assertTrue(result.contains("user-001"));
            assertTrue(result.contains("Alice"));
            assertTrue(result.contains("alice@example.com"));
        }
    }

    @Nested
    @DisplayName("Jackson Deserialization Tests")
    class JacksonDeserializationTests {

        @Test
        @DisplayName("Should handle null values in deserialization")
        void shouldHandleNullValuesInDeserialization() {
            // When
            UserIdentity identity = new UserIdentity(
                    "user-001",
                    null,
                    null,
                    null,
                    null,
                    null
            );

            // Then
            assertNotNull(identity);
            assertEquals("user-001", identity.getSubject());
            assertNull(identity.getName());
            assertNull(identity.getEmail());
            assertNull(identity.getEmailVerified());
            assertNull(identity.getAuthTime());
            assertNull(identity.getAttributes());
        }

        @Test
        @DisplayName("Should handle partial null values in deserialization")
        void shouldHandlePartialNullValuesInDeserialization() {
            // Given
            Instant authTime = Instant.now();

            // When
            UserIdentity identity = new UserIdentity(
                    "user-001",
                    "Alice",
                    null,
                    true,
                    authTime,
                    null
            );

            // Then
            assertNotNull(identity);
            assertEquals("user-001", identity.getSubject());
            assertEquals("Alice", identity.getName());
            assertNull(identity.getEmail());
            assertTrue(identity.getEmailVerified());
            assertEquals(authTime, identity.getAuthTime());
            assertNull(identity.getAttributes());
        }
    }
}
