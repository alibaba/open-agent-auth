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
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WimseOAuth2DcrClientAuthentication}.
 * <p>
 * Tests verify compliance with OAuth 2.0 Dynamic Client Registration (RFC 7591)
 * and WIMSE Workload Identity Credentials (draft-ietf-wimse-workload-creds) protocols.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>WIMSE WIT inclusion in HTTP headers</li>
 *   <li>HTTP header format validation</li>
 *   <li>DCR request building</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
@DisplayName("WIMSE DCR Client Authentication Tests - RFC 7591 + WIMSE")
class WimseOAuth2OAuth2DcrClientAuthenticationTest {

    private WimseOAuth2DcrClientAuthentication authentication;

    @BeforeEach
    void setUp() {
        authentication = new WimseOAuth2DcrClientAuthentication();
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
            assertThat(authentication.getAuthenticationMethod()).isEqualTo("private_key_jwt");
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Happy Path - WIMSE Protocol")
    class ApplyAuthenticationHappyPathTests {

        @Test
        @DisplayName("Should add WIT header to request when WIT is present")
        void shouldAddWitHeaderToRequestWhenWitIsPresent() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = createDcrRequestWithWit("valid-wit-token");

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then - Build the request to verify headers
            HttpRequest httpRequest = result.build();
            String witHeader = httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME).orElse(null);

            assertThat(witHeader).isEqualTo("valid-wit-token");
        }

        @Test
        @DisplayName("Should not add WIT header when WIT is null")
        void shouldNotAddWitHeaderWhenWitIsNull() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = createDcrRequestWithWit(null);

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME)).isEmpty();
        }

        @Test
        @DisplayName("Should not add WIT header when WIT is empty string")
        void shouldNotAddWitHeaderWhenWitIsEmptyString() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = createDcrRequestWithWit("   ");

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME)).isEmpty();
        }

        @Test
        @DisplayName("Should return modified request builder")
        void shouldReturnModifiedRequestBuilder() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = createDcrRequestWithWit("valid-wit-token");

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(result).isSameAs(requestBuilder);
        }

        @Test
        @DisplayName("Should preserve existing headers when adding WIT header")
        void shouldPreserveExistingHeadersWhenAddingWitHeader() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json");
            DcrRequest request = createDcrRequestWithWit("valid-wit-token");

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().firstValue("Content-Type")).hasValue("application/json");
            assertThat(httpRequest.headers().firstValue("Accept")).hasValue("application/json");
            assertThat(httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME)).hasValue("valid-wit-token");
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Input Validation - RFC 7591 Section 3.2.2")
    class ApplyAuthenticationValidationTests {

        @Test
        @DisplayName("Should throw exception when request builder is null")
        void shouldThrowExceptionWhenRequestBuilderIsNull() {
            // Given
            DcrRequest request = createDcrRequestWithWit("valid-wit-token");

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
        @DisplayName("Should handle request without additional parameters")
        void shouldHandleRequestWithoutAdditionalParameters() {
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
            assertThat(httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME)).isEmpty();
        }

        @Test
        @DisplayName("Should handle request with empty additional parameters")
        void shouldHandleRequestWithEmptyAdditionalParameters() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(new HashMap<>())
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME)).isEmpty();
        }

        @Test
        @DisplayName("Should handle WIT parameter with non-string value")
        void shouldHandleWitParameterWithNonStringValue() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, 12345); // Non-string value
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            HttpRequest httpRequest = result.build();
            assertThat(httpRequest.headers().firstValue(WitConstants.WIT_HEADER_NAME)).isEmpty();
        }
    }

    @Nested
    @DisplayName("WIMSE Protocol Specific Tests - draft-ietf-wimse-workload-creds")
    class WimseProtocolSpecificTests {

        @Test
        @DisplayName("Should use correct header name per WIMSE specification")
        void shouldUseCorrectHeaderNamePerWimseSpecification() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            DcrRequest request = createDcrRequestWithWit("wit-token");

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then - Verify header name matches WIMSE specification
            HttpRequest httpRequest = result.build();
            assertThat(WitConstants.WIT_HEADER_NAME).isEqualTo("Workload-Identity-Token");
            assertThat(httpRequest.headers().map()).containsKey("Workload-Identity-Token");
        }

        @Test
        @DisplayName("Should return private_key_jwt as authentication method")
        void shouldReturnPrivateKeyJwtAsAuthenticationMethod() {
            // When
            String method = authentication.getAuthenticationMethod();

            // Then
            assertThat(method).isEqualTo("private_key_jwt");
        }
    }

    // Helper methods

    private DcrRequest createDcrRequestWithWit(String wit) {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(WitConstants.WIT_PARAM, wit);

        return DcrRequest.builder()
                .redirectUris(List.of("https://example.com/callback"))
                .clientName("Test Client")
                .tokenEndpointAuthMethod("private_key_jwt")
                .additionalParameters(additionalParams)
                .build();
    }
}
