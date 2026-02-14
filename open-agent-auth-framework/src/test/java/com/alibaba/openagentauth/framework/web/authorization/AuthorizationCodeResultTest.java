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
package com.alibaba.openagentauth.framework.web.authorization;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AuthorizationCodeResult}.
 * <p>
 * This test class verifies the behavior of the AuthorizationCodeResult class,
 * including construction, validation, and immutability.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuthorizationCodeResult Tests")
class AuthorizationCodeResultTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create result with all fields")
        void shouldCreateResultWithAllFields() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "auth-code-123",
                "https://example.com/callback",
                "state-456"
            );

            assertThat(result.getCode()).isEqualTo("auth-code-123");
            assertThat(result.getRedirectUri()).isEqualTo("https://example.com/callback");
            assertThat(result.getState()).isEqualTo("state-456");
        }

        @Test
        @DisplayName("Should create result with null state")
        void shouldCreateResultWithNullState() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "auth-code-123",
                "https://example.com/callback",
                null
            );

            assertThat(result.getCode()).isEqualTo("auth-code-123");
            assertThat(result.getRedirectUri()).isEqualTo("https://example.com/callback");
            assertThat(result.getState()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when code is null")
        void shouldThrowExceptionWhenCodeIsNull() {
            assertThatThrownBy(() -> {
                new AuthorizationCodeResult(null, "https://example.com/callback", "state");
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("code");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            assertThatThrownBy(() -> {
                new AuthorizationCodeResult("auth-code", null, "state");
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("redirectUri");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return code")
        void shouldReturnCode() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state"
            );

            assertThat(result.getCode()).isEqualTo("code-123");
        }

        @Test
        @DisplayName("Should return redirectUri")
        void shouldReturnRedirectUri() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state"
            );

            assertThat(result.getRedirectUri()).isEqualTo("https://example.com/callback");
        }

        @Test
        @DisplayName("Should return state")
        void shouldReturnState() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-456"
            );

            assertThat(result.getState()).isEqualTo("state-456");
        }

        @Test
        @DisplayName("Should return null when state is not provided")
        void shouldReturnNullWhenStateIsNotProvided() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                null
            );

            assertThat(result.getState()).isNull();
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            AuthorizationCodeResult result1 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-456"
            );

            AuthorizationCodeResult result2 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-456"
            );

            assertThat(result1).isEqualTo(result2);
            assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when state differs but both are null")
        void shouldBeEqualWhenStateDiffersButBothAreNull() {
            AuthorizationCodeResult result1 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                null
            );

            AuthorizationCodeResult result2 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                null
            );

            assertThat(result1).isEqualTo(result2);
            assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when code differs")
        void shouldNotBeEqualWhenCodeDiffers() {
            AuthorizationCodeResult result1 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state"
            );

            AuthorizationCodeResult result2 = new AuthorizationCodeResult(
                "code-456",
                "https://example.com/callback",
                "state"
            );

            assertThat(result1).isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should not be equal when redirectUri differs")
        void shouldNotBeEqualWhenRedirectUriDiffers() {
            AuthorizationCodeResult result1 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback1",
                "state"
            );

            AuthorizationCodeResult result2 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback2",
                "state"
            );

            assertThat(result1).isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should not be equal when state differs")
        void shouldNotBeEqualWhenStateDiffers() {
            AuthorizationCodeResult result1 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-1"
            );

            AuthorizationCodeResult result2 = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-2"
            );

            assertThat(result1).isNotEqualTo(result2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state"
            );

            assertThat(result).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state"
            );

            assertThat(result).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-456"
            );

            String toString = result.toString();
            assertThat(toString).contains("code-123");
            assertThat(toString).contains("https://example.com/callback");
            assertThat(toString).contains("state-456");
        }

        @Test
        @DisplayName("Should handle null state in toString")
        void shouldHandleNullStateInToString() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                null
            );

            String toString = result.toString();
            assertThat(toString).contains("code-123");
            assertThat(toString).contains("https://example.com/callback");
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("Should create immutable instances")
        void shouldCreateImmutableInstances() {
            AuthorizationCodeResult result = new AuthorizationCodeResult(
                "code-123",
                "https://example.com/callback",
                "state-456"
            );

            String originalCode = result.getCode();
            String originalRedirectUri = result.getRedirectUri();
            String originalState = result.getState();

            assertThat(result.getCode()).isSameAs(originalCode);
            assertThat(result.getRedirectUri()).isSameAs(originalRedirectUri);
            assertThat(result.getState()).isSameAs(originalState);
        }
    }
}
