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
 * Unit tests for {@link AuthorizationUriBuilder}.
 */
@DisplayName("AuthorizationUriBuilder Tests")
class AuthorizationUriBuilderTest {

    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String AUTH_CODE = "auth-code-123";
    private static final String STATE = "random-state-123";

    @Nested
    @DisplayName("buildRedirectUri()")
    class BuildRedirectUri {

        @Test
        @DisplayName("Should build redirect URI with code and state")
        void shouldBuildRedirectUriWithCodeAndState() {
            // Arrange
            AuthorizationCodeResult result = new AuthorizationCodeResult(AUTH_CODE, REDIRECT_URI, STATE);

            // Act
            String uri = AuthorizationUriBuilder.buildRedirectUri(result);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("code=" + AUTH_CODE);
            assertThat(uri).contains("state=" + STATE);
        }

        @Test
        @DisplayName("Should build redirect URI with code without state")
        void shouldBuildRedirectUriWithCodeWithoutState() {
            // Arrange
            AuthorizationCodeResult result = new AuthorizationCodeResult(AUTH_CODE, REDIRECT_URI, null);

            // Act
            String uri = AuthorizationUriBuilder.buildRedirectUri(result);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("code=" + AUTH_CODE);
            assertThat(uri).doesNotContain("state=");
        }

        @Test
        @DisplayName("Should build redirect URI with empty state")
        void shouldBuildRedirectUriWithEmptyState() {
            // Arrange
            AuthorizationCodeResult result = new AuthorizationCodeResult(AUTH_CODE, REDIRECT_URI, "");

            // Act
            String uri = AuthorizationUriBuilder.buildRedirectUri(result);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("code=" + AUTH_CODE);
            assertThat(uri).doesNotContain("state=");
        }

        @Test
        @DisplayName("Should throw exception when result is null")
        void shouldThrowExceptionWhenResultIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> AuthorizationUriBuilder.buildRedirectUri(null))
                    .isInstanceOf(NullPointerException.class);
        }
    }

    @Nested
    @DisplayName("buildErrorRedirectUri()")
    class BuildErrorRedirectUri {

        @Test
        @DisplayName("Should build error redirect URI with all parameters")
        void shouldBuildErrorRedirectUriWithAllParameters() {
            // Act
            String uri = AuthorizationUriBuilder.buildErrorRedirectUri(
                    REDIRECT_URI, "access_denied", "User denied access", STATE);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("error=access_denied");
            assertThat(uri).contains("error_description=User+denied+access");
            assertThat(uri).contains("state=" + STATE);
        }

        @Test
        @DisplayName("Should build error redirect URI without state")
        void shouldBuildErrorRedirectUriWithoutState() {
            // Act
            String uri = AuthorizationUriBuilder.buildErrorRedirectUri(
                    REDIRECT_URI, "access_denied", "User denied access", null);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("error=access_denied");
            assertThat(uri).doesNotContain("state=");
        }

        @Test
        @DisplayName("Should build error redirect URI without error description")
        void shouldBuildErrorRedirectUriWithoutErrorDescription() {
            // Act
            String uri = AuthorizationUriBuilder.buildErrorRedirectUri(
                    REDIRECT_URI, "access_denied", null, STATE);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("error=access_denied");
            assertThat(uri).doesNotContain("error_description=");
        }

        @Test
        @DisplayName("Should build error redirect URI with empty error description")
        void shouldBuildErrorRedirectUriWithEmptyErrorDescription() {
            // Act
            String uri = AuthorizationUriBuilder.buildErrorRedirectUri(
                    REDIRECT_URI, "access_denied", "", STATE);

            // Assert
            assertThat(uri).isNotNull();
            assertThat(uri).contains(REDIRECT_URI);
            assertThat(uri).contains("error=access_denied");
            assertThat(uri).doesNotContain("error_description=");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> AuthorizationUriBuilder.buildErrorRedirectUri(
                    null, "error", "description", STATE))
                    .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should throw exception when errorCode is null")
        void shouldThrowExceptionWhenErrorCodeIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> AuthorizationUriBuilder.buildErrorRedirectUri(
                    REDIRECT_URI, null, "description", STATE))
                    .isInstanceOf(NullPointerException.class);
        }
    }
}
