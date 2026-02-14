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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link NoAuthOAuth2DcrClientAuthentication}.
 * <p>
 * Tests verify compliance with OAuth 2.0 Dynamic Client Registration (RFC 7591)
 * regarding scenarios where authentication is not required for initial registration.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>DCR request building without authentication</li>
 *   <li>HTTP header handling</li>
 *   <li>Input validation</li>
 * </ul>
 * <p>
 * <b>Use Cases:</b></p>
 * <ul>
 *   <li>Initial registration when AS allows unauthenticated requests</li>
 *   <li>Development and testing environments</li>
 *   <li>When TLS mutual authentication is used instead of HTTP headers</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
@DisplayName("NoAuth DCR Client Authentication Tests - RFC 7591")
class NoAuthOAuth2OAuth2DcrClientAuthenticationTest {

    private NoAuthOAuth2DcrClientAuthentication authentication;

    @BeforeEach
    void setUp() {
        authentication = new NoAuthOAuth2DcrClientAuthentication();
    }

    @Nested
    @DisplayName("Constructor - RFC 7591 Section 3")
    class ConstructorTests {

        @Test
        @DisplayName("Should create authentication successfully")
        void shouldCreateAuthenticationSuccessfully() {
            assertThat(authentication).isNotNull();
        }

        @Test
        @DisplayName("Should return correct authentication method")
        void shouldReturnCorrectAuthenticationMethod() {
            assertThat(authentication.getAuthenticationMethod()).isEqualTo("none");
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Happy Path - RFC 7591 Section 3")
    class ApplyAuthenticationHappyPathTests {

        @Test
        @DisplayName("Should not add any authentication headers")
        void shouldNotAddAnyAuthenticationHeaders() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().map()).isEmpty();
        }

        @Test
        @DisplayName("Should return unmodified request builder")
        void shouldReturnUnmodifiedRequestBuilder() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(requestBuilder);
        }

        @Test
        @DisplayName("Should preserve existing headers")
        void shouldPreserveExistingHeaders() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json");
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().firstValue("Content-Type")).hasValue("application/json");
            assertThat(httpRequest.headers().firstValue("Accept")).hasValue("application/json");
        }

        @Test
        @DisplayName("Should handle request with additional parameters")
        void shouldHandleRequestWithAdditionalParameters() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .clientName("Test Client")
                    .tokenEndpointAuthMethod("none")
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest).isNotNull();
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Input Validation - RFC 7591 Section 3.2.2")
    class ApplyAuthenticationValidationTests {

        @Test
        @DisplayName("Should throw exception when request builder is null")
        void shouldThrowExceptionWhenRequestBuilderIsNull() {
            // Given
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When & Then
            assertThatThrownBy(() -> authentication.applyAuthentication(null, request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Request builder");
        }

        @Test
        @DisplayName("Should throw exception when DCR request is null")
        void shouldThrowExceptionWhenDcrRequestIsNull() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));

            // When & Then
            assertThatThrownBy(() -> authentication.applyAuthentication(requestBuilder, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("DCR request");
        }

        @Test
        @DisplayName("Should handle request with minimal parameters")
        void shouldHandleRequestWithMinimalParameters() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest).isNotNull();
        }
    }

    @Nested
    @DisplayName("Authentication Method - RFC 7591 Section 2")
    class AuthenticationMethodTests {

        @Test
        @DisplayName("Should return 'none' as authentication method")
        void shouldReturnNoneAsAuthenticationMethod() {
            // When
            String method = authentication.getAuthenticationMethod();

            // Then
            assertThat(method).isEqualTo("none");
        }

        @Test
        @DisplayName("Should match OAuth 2.0 token_endpoint_auth_method value")
        void shouldMatchOAuth2TokenEndpointAuthMethodValue() {
            // When
            String method = authentication.getAuthenticationMethod();

            // Then - According to RFC 7591, "none" is a valid token_endpoint_auth_method
            // when no authentication is required
            assertThat(method).isEqualTo("none");
        }
    }
}
