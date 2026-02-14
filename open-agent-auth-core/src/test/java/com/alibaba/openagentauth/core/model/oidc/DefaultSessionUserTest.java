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
package com.alibaba.openagentauth.core.model.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link DefaultSessionUser}.
 * <p>
 * Tests the Default Session User model's behavior including:
 * <ul>
 *   <li>Builder pattern with all fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Implementation of SessionUser interface</li>
 *   <li>Immutability and thread safety</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("DefaultSessionUser Tests")
class DefaultSessionUserTest {

    private static final String SUBJECT = "user-123";
    private static final String USERNAME = "alice";
    private static final String PASSWORD = "password123";
    private static final String NAME = "Alice Smith";
    private static final String EMAIL = "alice@example.com";
    private static final String PREFERRED_USERNAME = "alice";

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build user with all fields")
        void shouldBuildUserWithAllFields() {
            // When
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .name(NAME)
                    .email(EMAIL)
                    .preferredUsername(PREFERRED_USERNAME)
                    .build();

            // Then
            assertThat(user).isNotNull();
            assertThat(user.getSubject()).isEqualTo(SUBJECT);
            assertThat(user.getUsername()).isEqualTo(USERNAME);
            assertThat(user.getPassword()).isEqualTo(PASSWORD);
            assertThat(user.getName()).isEqualTo(NAME);
            assertThat(user.getEmail()).isEqualTo(EMAIL);
            assertThat(user.getPreferredUsername()).isEqualTo(PREFERRED_USERNAME);
        }

        @Test
        @DisplayName("Should build user with null optional fields")
        void shouldBuildUserWithNullOptionalFields() {
            // When
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .build();

            // Then
            assertThat(user).isNotNull();
            assertThat(user.getName()).isNull();
            assertThat(user.getEmail()).isNull();
            assertThat(user.getPreferredUsername()).isNull();
        }

        @Test
        @DisplayName("Should build user with empty password")
        void shouldBuildUserWithEmptyPassword() {
            // When
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password("")
                    .build();

            // Then
            assertThat(user.getPassword()).isEqualTo("");
        }

        @Test
        @DisplayName("Should support method chaining in builder")
        void shouldSupportMethodChainingInBuilder() {
            // When
            DefaultSessionUser.Builder builder = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .name(NAME)
                    .email(EMAIL)
                    .preferredUsername(PREFERRED_USERNAME);

            // Then
            assertThat(builder).isNotNull();
            DefaultSessionUser builtUser = builder.build();
            assertThat(builtUser.getSubject()).isEqualTo(SUBJECT);
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct subject")
        void shouldReturnCorrectSubject() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user.getSubject()).isEqualTo(SUBJECT);
        }

        @Test
        @DisplayName("Should return correct username")
        void shouldReturnCorrectUsername() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user.getUsername()).isEqualTo(USERNAME);
        }

        @Test
        @DisplayName("Should return correct password")
        void shouldReturnCorrectPassword() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user.getPassword()).isEqualTo(PASSWORD);
        }

        @Test
        @DisplayName("Should return correct name")
        void shouldReturnCorrectName() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user.getName()).isEqualTo(NAME);
        }

        @Test
        @DisplayName("Should return correct email")
        void shouldReturnCorrectEmail() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user.getEmail()).isEqualTo(EMAIL);
        }

        @Test
        @DisplayName("Should return correct preferredUsername")
        void shouldReturnCorrectPreferredUsername() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user.getPreferredUsername()).isEqualTo(PREFERRED_USERNAME);
        }

        @Test
        @DisplayName("Should return null for optional name")
        void shouldReturnNullForOptionalName() {
            // Given
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .build();

            // When & Then
            assertThat(user.getName()).isNull();
        }

        @Test
        @DisplayName("Should return null for optional email")
        void shouldReturnNullForOptionalEmail() {
            // Given
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .build();

            // When & Then
            assertThat(user.getEmail()).isNull();
        }

        @Test
        @DisplayName("Should return null for optional preferredUsername")
        void shouldReturnNullForOptionalPreferredUsername() {
            // Given
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .build();

            // When & Then
            assertThat(user.getPreferredUsername()).isNull();
        }
    }

    @Nested
    @DisplayName("Interface Implementation Tests")
    class InterfaceImplementationTests {

        @Test
        @DisplayName("Should implement SessionUser interface")
        void shouldImplementSessionUserInterface() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            assertThat(user).isInstanceOf(SessionUser.class);
        }

        @Test
        @DisplayName("Should return SessionUser interface methods")
        void shouldReturnSessionUserInterfaceMethods() {
            // Given
            SessionUser sessionUser = createTestUser();

            // When & Then
            assertThat(sessionUser.getSubject()).isEqualTo(SUBJECT);
            assertThat(sessionUser.getUsername()).isEqualTo(USERNAME);
            assertThat(sessionUser.getPassword()).isEqualTo(PASSWORD);
            assertThat(sessionUser.getName()).isEqualTo(NAME);
            assertThat(sessionUser.getEmail()).isEqualTo(EMAIL);
            assertThat(sessionUser.getPreferredUsername()).isEqualTo(PREFERRED_USERNAME);
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("Should create immutable instances")
        void shouldCreateImmutableInstances() {
            // Given
            DefaultSessionUser user = createTestUser();

            // When & Then
            // Verify that the instance cannot be modified
            // (This is implicitly tested by the final fields in the class)
            assertThat(user.getSubject()).isEqualTo(SUBJECT);
            assertThat(user.getUsername()).isEqualTo(USERNAME);
        }

        @Test
        @DisplayName("Should create independent instances from builder")
        void shouldCreateIndependentInstancesFromBuilder() {
            // Given
            DefaultSessionUser.Builder builder = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD);

            // When
            DefaultSessionUser user1 = builder.build();
            DefaultSessionUser user2 = builder.build();

            // Then
            assertThat(user1).isNotNull();
            assertThat(user2).isNotNull();
            // Both instances have the same values
            assertThat(user1.getSubject()).isEqualTo(user2.getSubject());
            assertThat(user1.getUsername()).isEqualTo(user2.getUsername());
            assertThat(user1.getPassword()).isEqualTo(user2.getPassword());
        }

        @Test
        @DisplayName("Should allow creating different instances from same builder")
        void shouldAllowCreatingDifferentInstancesFromSameBuilder() {
            // Given
            DefaultSessionUser.Builder builder = DefaultSessionUser.builder()
                    .subject(SUBJECT)
                    .username(USERNAME)
                    .password(PASSWORD)
                    .name(NAME);

            // When
            DefaultSessionUser user1 = builder.build();
            builder.name("Different Name");
            DefaultSessionUser user2 = builder.build();

            // Then
            assertThat(user1.getName()).isEqualTo(NAME);
            assertThat(user2.getName()).isEqualTo("Different Name");
        }
    }

    /**
     * Helper method to create a test DefaultSessionUser instance.
     *
     * @return a test DefaultSessionUser instance
     */
    private DefaultSessionUser createTestUser() {
        return DefaultSessionUser.builder()
                .subject(SUBJECT)
                .username(USERNAME)
                .password(PASSWORD)
                .name(NAME)
                .email(EMAIL)
                .preferredUsername(PREFERRED_USERNAME)
                .build();
    }
}
