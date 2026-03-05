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
package com.alibaba.openagentauth.framework.web.manager;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link SessionAttribute}.
 */
@DisplayName("SessionAttribute Tests")
class SessionAttributeTest {

    private static final String KEY = "test_key";

    @Nested
    @DisplayName("Constructor with key and type")
    class ConstructorWithKeyAndType {

        @Test
        @DisplayName("Should create session attribute with key and type")
        void shouldCreateSessionAttributeWithKeyAndType() {
            // Act
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Assert
            assertThat(attribute).isNotNull();
            assertThat(attribute.getKey()).isEqualTo(KEY);
            assertThat(attribute.getType()).isEqualTo(String.class);
            assertThat(attribute.getDefaultValue()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when key is null")
        void shouldThrowExceptionWhenKeyIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new SessionAttribute<>(null, String.class))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Session attribute key must not be null");
        }

        @Test
        @DisplayName("Should throw exception when type is null")
        void shouldThrowExceptionWhenTypeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new SessionAttribute<>(KEY, null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Session attribute type must not be null");
        }
    }

    @Nested
    @DisplayName("Constructor with key, type, and default value")
    class ConstructorWithKeyTypeAndDefaultValue {

        @Test
        @DisplayName("Should create session attribute with key, type, and default value")
        void shouldCreateSessionAttributeWithKeyAndDefaultValue() {
            // Arrange
            String defaultValue = "default_value";

            // Act
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class, defaultValue);

            // Assert
            assertThat(attribute).isNotNull();
            assertThat(attribute.getKey()).isEqualTo(KEY);
            assertThat(attribute.getType()).isEqualTo(String.class);
            assertThat(attribute.getDefaultValue()).isEqualTo(defaultValue);
        }

        @Test
        @DisplayName("Should create session attribute with null default value")
        void shouldCreateSessionAttributeWithNullDefaultValue() {
            // Act
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class, null);

            // Assert
            assertThat(attribute).isNotNull();
            assertThat(attribute.getKey()).isEqualTo(KEY);
            assertThat(attribute.getType()).isEqualTo(String.class);
            assertThat(attribute.getDefaultValue()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when key is null")
        void shouldThrowExceptionWhenKeyIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new SessionAttribute<>(null, String.class, "default"))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Session attribute key must not be null");
        }

        @Test
        @DisplayName("Should throw exception when type is null")
        void shouldThrowExceptionWhenTypeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new SessionAttribute<>(KEY, null, "default"))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Session attribute type must not be null");
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return key")
        void shouldReturnKey() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute.getKey()).isEqualTo(KEY);
        }

        @Test
        @DisplayName("Should return type")
        void shouldReturnType() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute.getType()).isEqualTo(String.class);
        }

        @Test
        @DisplayName("Should return default value when set")
        void shouldReturnDefaultValueWhenSet() {
            // Arrange
            String defaultValue = "default_value";
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class, defaultValue);

            // Act & Assert
            assertThat(attribute.getDefaultValue()).isEqualTo(defaultValue);
        }

        @Test
        @DisplayName("Should return null default value when not set")
        void shouldReturnNullDefaultValueWhenNotSet() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute.getDefaultValue()).isNull();
        }
    }

    @Nested
    @DisplayName("equals() and hashCode()")
    class EqualsAndHashCode {

        @Test
        @DisplayName("Should be equal when keys match")
        void shouldBeEqualWhenKeysMatch() {
            // Arrange
            SessionAttribute<String> attribute1 = new SessionAttribute<>(KEY, String.class);
            SessionAttribute<String> attribute2 = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute1).isEqualTo(attribute2);
            assertThat(attribute1.hashCode()).isEqualTo(attribute2.hashCode());
        }

        @Test
        @DisplayName("Should be equal when keys match regardless of type")
        void shouldBeEqualWhenKeysMatchRegardlessOfType() {
            // Arrange
            SessionAttribute<String> attribute1 = new SessionAttribute<>(KEY, String.class);
            SessionAttribute<Integer> attribute2 = new SessionAttribute<>(KEY, Integer.class);

            // Act & Assert
            assertThat(attribute1).isEqualTo(attribute2);
            assertThat(attribute1.hashCode()).isEqualTo(attribute2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when keys differ")
        void shouldNotBeEqualWhenKeysDiffer() {
            // Arrange
            SessionAttribute<String> attribute1 = new SessionAttribute<>("key1", String.class);
            SessionAttribute<String> attribute2 = new SessionAttribute<>("key2", String.class);

            // Act & Assert
            assertThat(attribute1).isNotEqualTo(attribute2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute).isEqualTo(attribute);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act & Assert
            assertThat(attribute).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("toString()")
    class ToString {

        @Test
        @DisplayName("Should return string representation")
        void shouldReturnStringRepresentation() {
            // Arrange
            SessionAttribute<String> attribute = new SessionAttribute<>(KEY, String.class);

            // Act
            String toString = attribute.toString();

            // Assert
            assertThat(toString).contains("SessionAttribute");
            assertThat(toString).contains("key='" + KEY + "'");
            assertThat(toString).contains("type=String");
        }

        @Test
        @DisplayName("Should return string representation with Integer type")
        void shouldReturnStringRepresentationWithIntegerType() {
            // Arrange
            SessionAttribute<Integer> attribute = new SessionAttribute<>(KEY, Integer.class);

            // Act
            String toString = attribute.toString();

            // Assert
            assertThat(toString).contains("SessionAttribute");
            assertThat(toString).contains("key='" + KEY + "'");
            assertThat(toString).contains("type=Integer");
        }
    }
}
