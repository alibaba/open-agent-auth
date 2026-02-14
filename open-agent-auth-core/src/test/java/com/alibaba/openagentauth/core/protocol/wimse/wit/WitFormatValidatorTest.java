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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WitFormatValidator}.
 * Tests verify that WIT format validation works correctly.
 */
@DisplayName("WIT Format Validator Tests")
class WitFormatValidatorTest {

    @Nested
    @DisplayName("Valid Format Tests")
    class ValidFormatTests {

        @Test
        @DisplayName("Should accept valid JWT with three parts")
        void shouldAcceptValidJwtWithThreeParts() throws DcrException {
            // Arrange
            String validJwt = "header.payload.signature";

            // Act & Assert
            WitFormatValidator.validateFormat(validJwt);
        }

        @Test
        @DisplayName("Should return true for valid JWT format")
        void shouldReturnTrueForValidJwtFormat() {
            // Arrange
            String validJwt = "header.payload.signature";

            // Act
            boolean isValid = isValidFormat(validJwt);

            // Assert
            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should accept JWT with base64url characters")
        void shouldAcceptJwtWithBase64urlCharacters() throws DcrException {
            // Arrange
            String validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

            // Act & Assert
            WitFormatValidator.validateFormat(validJwt);
        }

        @Test
        @DisplayName("Should accept JWT with hyphens and underscores")
        void shouldAcceptJwtWithHyphensAndUnderscores() throws DcrException {
            // Arrange
            String jwtWithSpecialChars = "abc-def_ghi.123-456_789.xyz-uvw_rst";

            // Act & Assert
            WitFormatValidator.validateFormat(jwtWithSpecialChars);
        }
    }

    @Nested
    @DisplayName("Invalid Format Tests")
    class InvalidFormatTests {

        @Test
        @DisplayName("Should reject null WIT")
        void shouldRejectNullWit() {
            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject empty WIT")
        void shouldRejectEmptyWit() {
            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject blank WIT")
        void shouldRejectBlankWit() {
            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT cannot be null or empty");
        }

        @Test
        @DisplayName("Should reject JWT with only one part")
        void shouldRejectJwtWithOnlyOnePart() {
            // Arrange
            String invalidJwt = "header";

            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(invalidJwt))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("expected JWT with 3 parts, got 1");
        }

        @Test
        @DisplayName("Should reject JWT with only two parts")
        void shouldRejectJwtWithOnlyTwoParts() {
            // Arrange
            String invalidJwt = "header.payload";

            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(invalidJwt))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("expected JWT with 3 parts, got 2");
        }

        @Test
        @DisplayName("Should reject JWT with four parts")
        void shouldRejectJwtWithFourParts() {
            // Arrange
            String invalidJwt = "header.payload.signature.extra";

            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(invalidJwt))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("expected JWT with 3 parts, got 4");
        }

        @Test
        @DisplayName("Should reject JWT with more than three parts")
        void shouldRejectJwtWithMoreThanThreeParts() {
            // Arrange
            String invalidJwt = "a.b.c.d.e.f";

            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(invalidJwt))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("expected JWT with 3 parts, got 6");
        }

        @Test
        @DisplayName("Should return false for null format")
        void shouldReturnFalseForNullFormat() {
            // Act
            boolean isValid = isValidFormat(null);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for empty format")
        void shouldReturnFalseForEmptyFormat() {
            // Act
            boolean isValid = isValidFormat("");

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for invalid JWT with two parts")
        void shouldReturnFalseForInvalidJwtWithTwoParts() {
            // Arrange
            String invalidJwt = "header.payload";

            // Act
            boolean isValid = isValidFormat(invalidJwt);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should return false for invalid JWT with four parts")
        void shouldReturnFalseForInvalidJwtWithFourParts() {
            // Arrange
            String invalidJwt = "header.payload.signature.extra";

            // Act
            boolean isValid = isValidFormat(invalidJwt);

            // Assert
            assertThat(isValid).isFalse();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should reject JWT with empty parts")
        void shouldRejectJwtWithEmptyParts() {
            // Arrange
            String jwtWithEmptyParts = "..";

            // Act & Assert
            assertThatThrownBy(() -> WitFormatValidator.validateFormat(jwtWithEmptyParts))
                    .isInstanceOf(DcrException.class)
                    .hasMessageContaining("expected JWT with 3 parts, got 0");
        }

        @Test
        @DisplayName("Should handle JWT with special characters in delimiter")
        void shouldHandleJwtWithSpecialCharactersInDelimiter() {
            // Arrange
            String jwtWithExtraDelimiters = "a.b.c.d";

            // Act
            boolean isValid = isValidFormat(jwtWithExtraDelimiters);

            // Assert
            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should not validate JWT content, only structure")
        void shouldNotValidateJwtContentOnlyStructure() throws DcrException {
            // Arrange
            String jwtWithInvalidContent = "not-base64.not-base64.not-base64";

            // Act & Assert
            // Should pass format validation (3 parts)
            WitFormatValidator.validateFormat(jwtWithInvalidContent);
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
                java.lang.reflect.Constructor<WitFormatValidator> constructor = 
                    WitFormatValidator.class.getDeclaredConstructor();
                constructor.setAccessible(true);
                constructor.newInstance();
            })
                    .isInstanceOf(java.lang.reflect.InvocationTargetException.class)
                    .hasCauseExactlyInstanceOf(UnsupportedOperationException.class)
                    .hasRootCauseMessage("Utility class cannot be instantiated");
        }
    }

    /**
     * Helper method to test if a WIT format is valid without throwing exception.
     * This mimics the behavior of the missing isValidFormat method.
     *
     * @param wit the Workload Identity Token to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidFormat(String wit) {
        try {
            WitFormatValidator.validateFormat(wit);
            return true;
        } catch (IllegalArgumentException | DcrException e) {
            return false;
        }
    }
}