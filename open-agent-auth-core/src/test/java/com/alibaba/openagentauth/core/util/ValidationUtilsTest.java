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
package com.alibaba.openagentauth.core.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ValidationUtils}.
 * Tests verify that parameter validation methods work correctly
 * following the fail-fast principle.
 */
@DisplayName("ValidationUtils Tests")
class ValidationUtilsTest {

    @Nested
    @DisplayName("ValidateNotNull Tests")
    class ValidateNotNullTests {

        @Test
        @DisplayName("Should return object when not null")
        void shouldReturnObjectWhenNotNull() {
            // Arrange
            String testObject = "test value";

            // Act
            String result = ValidationUtils.validateNotNull(testObject, "testParam");

            // Assert
            assertThat(result).isSameAs(testObject);
        }

        @Test
        @DisplayName("Should throw exception when object is null")
        void shouldThrowExceptionWhenObjectIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> ValidationUtils.validateNotNull(null, "testParam"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("testParam")
                    .hasMessageContaining("cannot be null");
        }

        @Test
        @DisplayName("Should work with generic types")
        void shouldWorkWithGenericTypes() {
            // Arrange
            Integer testObject = 123;

            // Act
            Integer result = ValidationUtils.validateNotNull(testObject, "number");

            // Assert
            assertThat(result).isEqualTo(123);
        }

        @Test
        @DisplayName("Should work with custom objects")
        void shouldWorkWithCustomObjects() {
            // Arrange
            TestClass testObject = new TestClass("value");

            // Act
            TestClass result = ValidationUtils.validateNotNull(testObject, "customObject");

            // Assert
            assertThat(result).isSameAs(testObject);
        }
    }

    @Nested
    @DisplayName("ValidateNotEmpty Tests")
    class ValidateNotEmptyTests {

        @Test
        @DisplayName("Should return string when not empty")
        void shouldReturnStringWhenNotEmpty() {
            // Arrange
            String testString = "test value";

            // Act
            String result = ValidationUtils.validateNotEmpty(testString, "testParam");

            // Assert
            assertThat(result).isEqualTo(testString);
        }

        @Test
        @DisplayName("Should throw exception when string is null")
        void shouldThrowExceptionWhenStringIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> ValidationUtils.validateNotEmpty(null, "testParam"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("testParam")
                    .hasMessageContaining("cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when string is empty")
        void shouldThrowExceptionWhenStringIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> ValidationUtils.validateNotEmpty("", "testParam"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("testParam")
                    .hasMessageContaining("cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when string is blank")
        void shouldThrowExceptionWhenStringIsBlank() {
            // Act & Assert
            assertThatThrownBy(() -> ValidationUtils.validateNotEmpty("   ", "testParam"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("testParam")
                    .hasMessageContaining("cannot be null or empty");
        }

        @Test
        @DisplayName("Should return string with only whitespace after trimming")
        void shouldReturnStringWithOnlyWhitespaceAfterTrimming() {
            // Arrange
            String testString = "  test  ";

            // Act
            String result = ValidationUtils.validateNotEmpty(testString, "testParam");

            // Assert
            assertThat(result).isEqualTo(testString);
        }

        @Test
        @DisplayName("Should handle single character string")
        void shouldHandleSingleCharacterString() {
            // Arrange
            String testString = "a";

            // Act
            String result = ValidationUtils.validateNotEmpty(testString, "testParam");

            // Assert
            assertThat(result).isEqualTo("a");
        }
    }

    @Nested
    @DisplayName("IsNullOrEmpty Tests")
    class IsNullOrEmptyTests {

        @Test
        @DisplayName("Should return true for null string")
        void shouldReturnTrueForNullString() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty(null)).isTrue();
        }

        @Test
        @DisplayName("Should return true for empty string")
        void shouldReturnTrueForEmptyString() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("")).isTrue();
        }

        @Test
        @DisplayName("Should return true for blank string")
        void shouldReturnTrueForBlankString() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("   ")).isTrue();
        }

        @Test
        @DisplayName("Should return true for string with only tabs")
        void shouldReturnTrueForStringWithOnlyTabs() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("\t\t")).isTrue();
        }

        @Test
        @DisplayName("Should return true for string with only newlines")
        void shouldReturnTrueForStringWithOnlyNewlines() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("\n\n")).isTrue();
        }

        @Test
        @DisplayName("Should return false for non-empty string")
        void shouldReturnFalseForNonEmptyString() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("test")).isFalse();
        }

        @Test
        @DisplayName("Should return false for string with whitespace and content")
        void shouldReturnFalseForStringWithWhitespaceAndContent() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("  test  ")).isFalse();
        }

        @Test
        @DisplayName("Should return false for single character")
        void shouldReturnFalseForSingleCharacter() {
            // Act & Assert
            assertThat(ValidationUtils.isNullOrEmpty("a")).isFalse();
        }
    }

    @Nested
    @DisplayName("IsNull Tests")
    class IsNullTests {

        @Test
        @DisplayName("Should return true for null object")
        void shouldReturnTrueForNullObject() {
            // Act & Assert
            assertThat(ValidationUtils.isNull(null)).isTrue();
        }

        @Test
        @DisplayName("Should return false for non-null object")
        void shouldReturnFalseForNonNullObject() {
            // Arrange
            Object testObject = new Object();

            // Act & Assert
            assertThat(ValidationUtils.isNull(testObject)).isFalse();
        }

        @Test
        @DisplayName("Should return false for empty string")
        void shouldReturnFalseForEmptyString() {
            // Act & Assert
            assertThat(ValidationUtils.isNull("")).isFalse();
        }

        @Test
        @DisplayName("Should return false for zero")
        void shouldReturnFalseForZero() {
            // Act & Assert
            assertThat(ValidationUtils.isNull(0)).isFalse();
        }

        @Test
        @DisplayName("Should return false for false boolean")
        void shouldReturnFalseForFalseBoolean() {
            // Act & Assert
            assertThat(ValidationUtils.isNull(false)).isFalse();
        }
    }

    @Nested
    @DisplayName("Utility Class Tests")
    class UtilityClassTests {

        @Test
        @DisplayName("Should prevent instantiation")
        void shouldPreventInstantiation() {
            // Act & Assert
            assertThatThrownBy(() -> {
                // Use reflection to try to instantiate the utility class
                java.lang.reflect.Constructor<ValidationUtils> constructor = 
                    ValidationUtils.class.getDeclaredConstructor();
                constructor.setAccessible(true);
                constructor.newInstance();
            })
                    .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
                    .hasCauseExactlyInstanceOf(UnsupportedOperationException.class)
                    .hasRootCauseMessage("Utility class cannot be instantiated");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should chain validations in constructor")
        void shouldChainValidationsInConstructor() {
            // Arrange
            String name = "John";
            String email = "john@example.com";

            // Act & Assert
            assertThat(ValidationUtils.validateNotNull(name, "name")).isEqualTo(name);
            assertThat(ValidationUtils.validateNotEmpty(email, "email")).isEqualTo(email);
        }

        @Test
        @DisplayName("Should validate multiple parameters in sequence")
        void shouldValidateMultipleParametersInSequence() {
            // Arrange
            String param1 = "value1";
            String param2 = "value2";
            String param3 = "value3";

            // Act & Assert
            assertThat(ValidationUtils.validateNotEmpty(param1, "param1")).isEqualTo(param1);
            assertThat(ValidationUtils.validateNotEmpty(param2, "param2")).isEqualTo(param2);
            assertThat(ValidationUtils.validateNotEmpty(param3, "param3")).isEqualTo(param3);
        }

        @Test
        @DisplayName("Should fail fast on first invalid parameter")
        void shouldFailFastOnFirstInvalidParameter() {
            // Arrange
            String validParam = "valid";
            String invalidParam = null;
            String anotherValidParam = "another";

            // Act & Assert
            assertThatThrownBy(() -> {
                ValidationUtils.validateNotEmpty(validParam, "validParam");
                ValidationUtils.validateNotEmpty(invalidParam, "invalidParam");
                ValidationUtils.validateNotEmpty(anotherValidParam, "anotherValidParam");
            })
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("invalidParam");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle very long string")
        void shouldHandleVeryLongString() {
            // Arrange
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 10000; i++) {
                sb.append("a");
            }
            String longString = sb.toString();

            // Act
            String result = ValidationUtils.validateNotEmpty(longString, "longParam");

            // Assert
            assertThat(result).hasSize(10000);
        }

        @Test
        @DisplayName("Should handle string with special characters")
        void shouldHandleStringWithSpecialCharacters() {
            // Arrange
            String specialString = "test!@#$%^&*()_+-=[]{}|;':\",./<>?";

            // Act
            String result = ValidationUtils.validateNotEmpty(specialString, "specialParam");

            // Assert
            assertThat(result).isEqualTo(specialString);
        }

        @Test
        @DisplayName("Should handle string with unicode characters")
        void shouldHandleStringWithUnicodeCharacters() {
            // Arrange
            String unicodeString = "测试中文🎉emoji";

            // Act
            String result = ValidationUtils.validateNotEmpty(unicodeString, "unicodeParam");

            // Assert
            assertThat(result).isEqualTo(unicodeString);
        }

        @Test
        @DisplayName("Should handle string with mixed whitespace")
        void shouldHandleStringWithMixedWhitespace() {
            // Arrange
            String mixedString = " \t\n \r test \r\n \t ";

            // Act
            String result = ValidationUtils.validateNotEmpty(mixedString, "mixedParam");

            // Assert
            assertThat(result).isEqualTo(mixedString);
        }
    }

    /**
     * Test class for generic type validation.
     */
    private static class TestClass {
        private final String value;

        TestClass(String value) {
            this.value = value;
        }

        String getValue() {
            return value;
        }
    }
}
