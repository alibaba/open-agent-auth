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
 * Unit tests for {@link SecurityProperties}.
 * <p>
 * This test class validates the security configuration properties,
 * including CSRF, CORS, and session cookie settings.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("SecurityProperties Tests")
class SecurityPropertiesTest {

    @Nested
    @DisplayName("SessionCookie Properties Tests")
    class SessionCookiePropertiesTests {

        @Test
        @DisplayName("Should have default session cookie properties")
        void shouldHaveDefaultSessionCookieProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();

            // When
            SessionCookieProperties sessionCookie = properties.getSessionCookie();

            // Then
            assertThat(sessionCookie).isNotNull();
            assertThat(sessionCookie.isHttpOnly()).isTrue();
            assertThat(sessionCookie.isSecure()).isFalse();
            assertThat(sessionCookie.getSameSite()).isEqualTo("Lax");
        }

        @Test
        @DisplayName("Should set and get session cookie properties")
        void shouldSetAndGetSessionCookieProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();
            SessionCookieProperties customSessionCookie = new SessionCookieProperties();
            customSessionCookie.setHttpOnly(false);
            customSessionCookie.setSecure(true);
            customSessionCookie.setSameSite("Strict");

            // When
            properties.setSessionCookie(customSessionCookie);

            // Then
            assertThat(properties.getSessionCookie()).isSameAs(customSessionCookie);
            assertThat(properties.getSessionCookie().isHttpOnly()).isFalse();
            assertThat(properties.getSessionCookie().isSecure()).isTrue();
            assertThat(properties.getSessionCookie().getSameSite()).isEqualTo("Strict");
        }

        @Test
        @DisplayName("Should allow modifying session cookie properties")
        void shouldAllowModifyingSessionCookieProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();

            // When
            properties.getSessionCookie().setHttpOnly(false);
            properties.getSessionCookie().setSecure(true);
            properties.getSessionCookie().setSameSite("None");

            // Then
            assertThat(properties.getSessionCookie().isHttpOnly()).isFalse();
            assertThat(properties.getSessionCookie().isSecure()).isTrue();
            assertThat(properties.getSessionCookie().getSameSite()).isEqualTo("None");
        }
    }

    @Nested
    @DisplayName("CSRF Properties Tests")
    class CsrfPropertiesTests {

        @Test
        @DisplayName("Should have default CSRF properties")
        void shouldHaveDefaultCsrfProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();

            // Then
            assertThat(properties.getCsrf()).isNotNull();
            assertThat(properties.getCsrf().isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should set and get CSRF properties")
        void shouldSetAndGetCsrfProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();
            SecurityProperties.CsrfProperties customCsrf = new SecurityProperties.CsrfProperties();
            customCsrf.setEnabled(false);

            // When
            properties.setCsrf(customCsrf);

            // Then
            assertThat(properties.getCsrf()).isSameAs(customCsrf);
            assertThat(properties.getCsrf().isEnabled()).isFalse();
        }
    }

    @Nested
    @DisplayName("CORS Properties Tests")
    class CorsPropertiesTests {

        @Test
        @DisplayName("Should have default CORS properties")
        void shouldHaveDefaultCorsProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();

            // Then
            assertThat(properties.getCors()).isNotNull();
            assertThat(properties.getCors().isEnabled()).isFalse();
            assertThat(properties.getCors().getAllowedOrigins()).isEmpty();
        }

        @Test
        @DisplayName("Should set and get CORS properties")
        void shouldSetAndGetCorsProperties() {
            // Given
            SecurityProperties properties = new SecurityProperties();
            SecurityProperties.CorsProperties customCors = new SecurityProperties.CorsProperties();
            customCors.setEnabled(true);

            // When
            properties.setCors(customCors);

            // Then
            assertThat(properties.getCors()).isSameAs(customCors);
            assertThat(properties.getCors().isEnabled()).isTrue();
        }
    }
}
