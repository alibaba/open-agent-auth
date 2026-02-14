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
package com.alibaba.openagentauth.core.protocol.oidc.registry;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryUserRegistry}.
 * <p>
 * This test class validates the in-memory user registry implementation,
 * covering authentication, user management, and edge cases.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("InMemoryUserRegistry Tests")
class InMemoryUserRegistryTest {

    private InMemoryUserRegistry userRegistry;

    @BeforeEach
    void setUp() {
        userRegistry = new InMemoryUserRegistry();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create empty registry with default constructor")
        void shouldCreateEmptyRegistryWithDefaultConstructor() {
            assertThat(userRegistry.getUserCount()).isZero();
            assertThat(userRegistry.getUsernames()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Authentication Tests")
    class AuthenticationTests {

        @Test
        @DisplayName("Should authenticate user with valid credentials")
        void shouldAuthenticateUserWithValidCredentials() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            String subject = userRegistry.authenticate("testuser", "testpass123");
            
            assertThat(subject).isEqualTo("user_test_001");
        }

        @Test
        @DisplayName("Should throw exception when username is null")
        void shouldThrowExceptionWhenUsernameIsNull() {
            assertThatThrownBy(() -> userRegistry.authenticate(null, "password"))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should throw exception when username is empty")
        void shouldThrowExceptionWhenUsernameIsEmpty() {
            assertThatThrownBy(() -> userRegistry.authenticate("", "password"))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should throw exception when username is blank")
        void shouldThrowExceptionWhenUsernameIsBlank() {
            assertThatThrownBy(() -> userRegistry.authenticate("   ", "password"))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should throw exception when password is null")
        void shouldThrowExceptionWhenPasswordIsNull() {
            assertThatThrownBy(() -> userRegistry.authenticate("testuser", null))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should throw exception when password is empty")
        void shouldThrowExceptionWhenPasswordIsEmpty() {
            assertThatThrownBy(() -> userRegistry.authenticate("testuser", ""))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should throw exception when password is blank")
        void shouldThrowExceptionWhenPasswordIsBlank() {
            assertThatThrownBy(() -> userRegistry.authenticate("testuser", "   "))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_request");
        }

        @Test
        @DisplayName("Should throw exception when user does not exist")
        void shouldThrowExceptionWhenUserDoesNotExist() {
            assertThatThrownBy(() -> userRegistry.authenticate("nonexistent", "password"))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_grant");
        }

        @Test
        @DisplayName("Should throw exception when password is incorrect")
        void shouldThrowExceptionWhenPasswordIsIncorrect() {
            userRegistry.addUser("testuser", "correctpass", "user_test_001", "testuser@example.com", "Test User");
            
            assertThatThrownBy(() -> userRegistry.authenticate("testuser", "wrongpass"))
                .isInstanceOf(AuthenticationException.class)
                .extracting("rfcErrorCode")
                .isEqualTo("invalid_grant");
        }
    }

    @Nested
    @DisplayName("User Management Tests")
    class UserManagementTests {

        @Test
        @DisplayName("Should add user successfully")
        void shouldAddUserSuccessfully() {
            userRegistry.addUser("newuser", "newpass123", "user_new_001", "newuser@example.com", "New User");
            
            assertThat(userRegistry.getUserCount()).isEqualTo(1);
            assertThat(userRegistry.userExists("newuser")).isTrue();
        }

        @Test
        @DisplayName("Should remove user successfully")
        void shouldRemoveUserSuccessfully() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            userRegistry.removeUser("testuser");
            
            assertThat(userRegistry.getUserCount()).isZero();
            assertThat(userRegistry.userExists("testuser")).isFalse();
        }

        @Test
        @DisplayName("Should handle removing non-existent user")
        void shouldHandleRemovingNonExistentUser() {
            userRegistry.removeUser("nonexistent");
            
            assertThat(userRegistry.getUserCount()).isZero();
        }

        @Test
        @DisplayName("Should update user when adding with same username")
        void shouldUpdateUserWhenAddingWithSameUsername() {
            userRegistry.addUser("testuser", "oldpass", "user_old", "old@example.com", "Old User");
            userRegistry.addUser("testuser", "newpass", "user_new", "new@example.com", "New User");
            
            assertThat(userRegistry.getUserCount()).isEqualTo(1);
            assertThat(userRegistry.getSubject("testuser")).isEqualTo("user_new");
            assertThat(userRegistry.getEmail("testuser")).isEqualTo("new@example.com");
            assertThat(userRegistry.getName("testuser")).isEqualTo("New User");
        }

        @Test
        @DisplayName("Should get user count correctly")
        void shouldGetUserCountCorrectly() {
            assertThat(userRegistry.getUserCount()).isZero();
            
            userRegistry.addUser("user1", "pass1", "sub1", "email1@example.com", "User 1");
            assertThat(userRegistry.getUserCount()).isEqualTo(1);
            
            userRegistry.addUser("user2", "pass2", "sub2", "email2@example.com", "User 2");
            assertThat(userRegistry.getUserCount()).isEqualTo(2);
            
            userRegistry.removeUser("user1");
            assertThat(userRegistry.getUserCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should get all usernames correctly")
        void shouldGetAllUsernamesCorrectly() {
            userRegistry.addUser("user1", "pass1", "sub1", "email1@example.com", "User 1");
            userRegistry.addUser("user2", "pass2", "sub2", "email2@example.com", "User 2");
            userRegistry.addUser("user3", "pass3", "sub3", "email3@example.com", "User 3");
            
            assertThat(userRegistry.getUsernames()).containsExactlyInAnyOrder("user1", "user2", "user3");
        }
    }

    @Nested
    @DisplayName("User Query Tests")
    class UserQueryTests {

        @Test
        @DisplayName("Should check user exists correctly")
        void shouldCheckUserExistsCorrectly() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            assertThat(userRegistry.userExists("testuser")).isTrue();
            assertThat(userRegistry.userExists("nonexistent")).isFalse();
        }

        @Test
        @DisplayName("Should get subject for existing user")
        void shouldGetSubjectForExistingUser() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            assertThat(userRegistry.getSubject("testuser")).isEqualTo("user_test_001");
        }

        @Test
        @DisplayName("Should return null when getting subject for non-existent user")
        void shouldReturnNullWhenGettingSubjectForNonExistentUser() {
            assertThat(userRegistry.getSubject("nonexistent")).isNull();
        }

        @Test
        @DisplayName("Should get email for existing user")
        void shouldGetEmailForExistingUser() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            assertThat(userRegistry.getEmail("testuser")).isEqualTo("testuser@example.com");
        }

        @Test
        @DisplayName("Should return null when getting email for non-existent user")
        void shouldReturnNullWhenGettingEmailForNonExistentUser() {
            assertThat(userRegistry.getEmail("nonexistent")).isNull();
        }

        @Test
        @DisplayName("Should get name for existing user")
        void shouldGetNameForExistingUser() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            assertThat(userRegistry.getName("testuser")).isEqualTo("Test User");
        }

        @Test
        @DisplayName("Should return null when getting name for non-existent user")
        void shouldReturnNullWhenGettingNameForNonExistentUser() {
            assertThat(userRegistry.getName("nonexistent")).isNull();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty password")
        void shouldHandleEmptyPassword() {
            userRegistry.addUser("testuser", "", "user_test_001", "testuser@example.com", "Test User");
            
            assertThatThrownBy(() -> userRegistry.authenticate("testuser", ""))
                .isInstanceOf(AuthenticationException.class);
        }

        @Test
        @DisplayName("Should handle special characters in password")
        void shouldHandleSpecialCharactersInPassword() {
            String specialPassword = "P@ssw0rd!#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`";
            userRegistry.addUser("testuser", specialPassword, "user_test_001", "testuser@example.com", "Test User");
            
            String subject = userRegistry.authenticate("testuser", specialPassword);
            assertThat(subject).isEqualTo("user_test_001");
        }

        @Test
        @DisplayName("Should handle Unicode characters in username")
        void shouldHandleUnicodeCharactersInUsername() {
            String unicodeUsername = "user-test";
            userRegistry.addUser(unicodeUsername, "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            assertThat(userRegistry.userExists(unicodeUsername)).isTrue();
            String subject = userRegistry.authenticate(unicodeUsername, "testpass123");
            assertThat(subject).isEqualTo("user_test_001");
        }

        @Test
        @DisplayName("Should handle very long username")
        void shouldHandleVeryLongUsername() {
            String longUsername = "a".repeat(1000);
            userRegistry.addUser(longUsername, "testpass123", "user_test_001", "testuser@example.com", "Test User");
            
            assertThat(userRegistry.userExists(longUsername)).isTrue();
        }

        @Test
        @DisplayName("Should handle very long password")
        void shouldHandleVeryLongPassword() {
            String longPassword = "a".repeat(1000);
            userRegistry.addUser("testuser", longPassword, "user_test_001", "testuser@example.com", "Test User");
            
            String subject = userRegistry.authenticate("testuser", longPassword);
            assertThat(subject).isEqualTo("user_test_001");
        }

        @Test
        @DisplayName("Should handle null email and name")
        void shouldHandleNullEmailAndName() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", null, null);
            
            assertThat(userRegistry.getEmail("testuser")).isNull();
            assertThat(userRegistry.getName("testuser")).isNull();
        }

        @Test
        @DisplayName("Should handle empty email and name")
        void shouldHandleEmptyEmailAndName() {
            userRegistry.addUser("testuser", "testpass123", "user_test_001", "", "");
            
            assertThat(userRegistry.getEmail("testuser")).isEqualTo("");
            assertThat(userRegistry.getName("testuser")).isEqualTo("");
        }
    }
}