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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SessionCookieProperties}.
 * <p>
 * This test class validates the session cookie configuration properties,
 * including default values, getter/setter behavior, and proper initialization.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("SessionCookieProperties Tests")
class SessionCookiePropertiesTest {

    @Nested
    @DisplayName("Default Values Tests")
    class DefaultValuesTests {

        @Test
        @DisplayName("Should have default values")
        void shouldHaveDefaultValues() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();

            // Then
            assertThat(properties.isHttpOnly()).isTrue();
            assertThat(properties.isSecure()).isFalse();
            assertThat(properties.getSameSite()).isEqualTo("Lax");
        }
    }

    @Nested
    @DisplayName("HttpOnly Property Tests")
    class HttpOnlyPropertyTests {

        @Test
        @DisplayName("Should set and get httpOnly")
        void shouldSetAndGetHttpOnly() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();

            // When
            properties.setHttpOnly(false);

            // Then
            assertThat(properties.isHttpOnly()).isFalse();
        }

        @Test
        @DisplayName("Should set httpOnly to true")
        void shouldSetHttpOnlyToTrue() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();
            properties.setHttpOnly(false);

            // When
            properties.setHttpOnly(true);

            // Then
            assertThat(properties.isHttpOnly()).isTrue();
        }
    }

    @Nested
    @DisplayName("Secure Property Tests")
    class SecurePropertyTests {

        @Test
        @DisplayName("Should set and get secure")
        void shouldSetAndGetSecure() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();

            // When
            properties.setSecure(true);

            // Then
            assertThat(properties.isSecure()).isTrue();
        }

        @Test
        @DisplayName("Should set secure to false")
        void shouldSetSecureToFalse() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();
            properties.setSecure(true);

            // When
            properties.setSecure(false);

            // Then
            assertThat(properties.isSecure()).isFalse();
        }
    }

    @Nested
    @DisplayName("SameSite Property Tests")
    class SameSitePropertyTests {

        @Test
        @DisplayName("Should set and get sameSite")
        void shouldSetAndGetSameSite() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();

            // When
            properties.setSameSite("Strict");

            // Then
            assertThat(properties.getSameSite()).isEqualTo("Strict");
        }

        @Test
        @DisplayName("Should set sameSite to None")
        void shouldSetSameSiteToNone() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();

            // When
            properties.setSameSite("None");

            // Then
            assertThat(properties.getSameSite()).isEqualTo("None");
        }

        @Test
        @DisplayName("Should reset sameSite to default Lax")
        void shouldResetSameSiteToDefaultLax() {
            // Given
            SessionCookieProperties properties = new SessionCookieProperties();
            properties.setSameSite("Strict");

            // When
            properties.setSameSite("Lax");

            // Then
            assertThat(properties.getSameSite()).isEqualTo("Lax");
        }
    }
}
