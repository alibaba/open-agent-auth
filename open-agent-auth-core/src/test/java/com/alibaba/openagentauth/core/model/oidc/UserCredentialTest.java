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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link UserCredential}.
 * <p>
 * Tests the User Credential model's behavior including:
 * <ul>
 *   <li>Constructor with required fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Validation logic for required fields</li>
 *   <li>Equals, hashCode, and toString methods</li>
 *   <li>Security considerations</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("UserCredential Tests")
class UserCredentialTest {

    private static final String SUBJECT = "user-123";
    private static final String HASHED_PASSWORD = "$2a$10$N9qo8uLOickgx2ZMRZoMy.MrqK3q3q3q3q3q3q3q3q3q3q3q3q3q";
    private static final String EMAIL = "user@example.com";
    private static final String NAME = "John Doe";

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create UserCredential with all fields")
        void shouldCreateUserCredentialWithAllFields() {
            // When
            UserCredential credential = new UserCredential(SUBJECT, HASHED_PASSWORD, EMAIL, NAME);

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getSubject()).isEqualTo(SUBJECT);
            assertThat(credential.getHashedPassword()).isEqualTo(HASHED_PASSWORD);
            assertThat(credential.getEmail()).isEqualTo(EMAIL);
            assertThat(credential.getName()).isEqualTo(NAME);
        }

        @Test
        @DisplayName("Should create UserCredential with null optional fields")
        void shouldCreateUserCredentialWithNullOptionalFields() {
            // When
            UserCredential credential = new UserCredential(SUBJECT, HASHED_PASSWORD, null, null);

            // Then
            assertThat(credential).isNotNull();
            assertThat(credential.getEmail()).isNull();
            assertThat(credential.getName()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when subject is null")
        void shouldThrowExceptionWhenSubjectIsNull() {
            // When & Then
            assertThatThrownBy(() -> new UserCredential(null, HASHED_PASSWORD, EMAIL, NAME))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Subject");
        }

        @Test
        @DisplayName("Should throw exception when hashedPassword is null")
        void shouldThrowExceptionWhenHashedPasswordIsNull() {
            // When & Then
            assertThatThrownBy(() -> new UserCredential(SUBJECT, null, EMAIL, NAME))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Hashed password");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct subject")
        void shouldReturnCorrectSubject() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential.getSubject()).isEqualTo(SUBJECT);
        }

        @Test
        @DisplayName("Should return correct hashedPassword")
        void shouldReturnCorrectHashedPassword() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential.getHashedPassword()).isEqualTo(HASHED_PASSWORD);
        }

        @Test
        @DisplayName("Should return correct email")
        void shouldReturnCorrectEmail() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential.getEmail()).isEqualTo(EMAIL);
        }

        @Test
        @DisplayName("Should return correct name")
        void shouldReturnCorrectName() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential.getName()).isEqualTo(NAME);
        }

        @Test
        @DisplayName("Should return null for optional email")
        void shouldReturnNullForOptionalEmail() {
            // Given
            UserCredential credential = new UserCredential(SUBJECT, HASHED_PASSWORD, null, NAME);

            // When & Then
            assertThat(credential.getEmail()).isNull();
        }

        @Test
        @DisplayName("Should return null for optional name")
        void shouldReturnNullForOptionalName() {
            // Given
            UserCredential credential = new UserCredential(SUBJECT, HASHED_PASSWORD, EMAIL, null);

            // When & Then
            assertThat(credential.getName()).isNull();
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when subjects match")
        void shouldBeEqualWhenSubjectsMatch() {
            // Given
            UserCredential credential1 = new UserCredential(SUBJECT, HASHED_PASSWORD, EMAIL, NAME);
            UserCredential credential2 = new UserCredential(SUBJECT, "different-hash", "different@email.com", "Different Name");

            // When & Then
            assertThat(credential1).isEqualTo(credential2);
            assertThat(credential1.hashCode()).isEqualTo(credential2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when subjects differ")
        void shouldNotBeEqualWhenSubjectsDiffer() {
            // Given
            UserCredential credential1 = createTestUserCredential();
            UserCredential credential2 = new UserCredential("different-subject", HASHED_PASSWORD, EMAIL, NAME);

            // When & Then
            assertThat(credential1).isNotEqualTo(credential2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential).isEqualTo(credential);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When & Then
            assertThat(credential).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should contain subject, email, and name in toString")
        void shouldContainSubjectEmailAndNameInToString() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When
            String toString = credential.toString();

            // Then
            assertThat(toString).contains("UserCredential");
            assertThat(toString).contains("subject='user-123'");
            assertThat(toString).contains("email='user@example.com'");
            assertThat(toString).contains("name='John Doe'");
        }

        @Test
        @DisplayName("Should not contain hashedPassword in toString")
        void shouldNotContainHashedPasswordInToString() {
            // Given
            UserCredential credential = createTestUserCredential();

            // When
            String toString = credential.toString();

            // Then
            assertThat(toString).doesNotContain("hashedPassword");
            assertThat(toString).doesNotContain(HASHED_PASSWORD);
        }

        @Test
        @DisplayName("Should handle null fields in toString")
        void shouldHandleNullFieldsInToString() {
            // Given
            UserCredential credential = new UserCredential(SUBJECT, HASHED_PASSWORD, null, null);

            // When
            String toString = credential.toString();

            // Then
            assertThat(toString).isNotNull();
            assertThat(toString).contains("UserCredential");
            assertThat(toString).contains("subject='user-123'");
        }
    }

    /**
     * Helper method to create a test UserCredential instance.
     *
     * @return a test UserCredential instance
     */
    private UserCredential createTestUserCredential() {
        return new UserCredential(SUBJECT, HASHED_PASSWORD, EMAIL, NAME);
    }
}
