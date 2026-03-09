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
 * using Software Statement mechanism for WIMSE authentication.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>Software statement placement in request body</li>
 *   <li>Backward compatibility with legacy {@code wit} parameter</li>
 *   <li>Request validation and error handling</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
@DisplayName("WIMSE DCR Client Authentication Tests - Software Statement Mode")
class WimseOAuth2DcrClientAuthenticationTest {

    private WimseOAuth2DcrClientAuthentication authentication;

    @BeforeEach
    void setUp() {
        authentication = new WimseOAuth2DcrClientAuthentication();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create authentication successfully")
        void shouldCreateAuthenticationSuccessfully() {
            assertThat(authentication).isNotNull();
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Software Statement Mode")
    class SoftwareStatementModeTests {

        @Test
        @DisplayName("Should clean up wit parameter when softwareStatement is set")
        void shouldCleanUpWitParameterWhenSoftwareStatementIsSet() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "legacy-wit-token");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .softwareStatement("valid-software-statement")
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).doesNotContainKey(WitConstants.WIT_PARAM);
            assertThat(request.getSoftwareStatement()).isEqualTo("valid-software-statement");
        }

        @Test
        @DisplayName("Should preserve softwareStatement when wit parameter is absent")
        void shouldPreserveSoftwareStatementWhenWitParameterIsAbsent() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .softwareStatement("valid-software-statement")
                    .additionalParameters(new HashMap<>())
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(request.getSoftwareStatement()).isEqualTo("valid-software-statement");
        }

        @Test
        @DisplayName("Should handle empty wit parameter when softwareStatement is set")
        void shouldHandleEmptyWitParameterWhenSoftwareStatementIsSet() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .softwareStatement("valid-software-statement")
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).doesNotContainKey(WitConstants.WIT_PARAM);
        }

        @Test
        @DisplayName("Should return same request builder instance")
        void shouldReturnSameRequestBuilderInstance() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .softwareStatement("valid-software-statement")
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isSameAs(requestBuilder);
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Backward Compatibility Mode")
    class BackwardCompatibilityModeTests {

        @Test
        @DisplayName("Should extract WIT from wit parameter when softwareStatement is not set")
        void shouldExtractWitFromWitParameterWhenSoftwareStatementIsNotSet() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "legacy-wit-token");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).doesNotContainKey(WitConstants.WIT_PARAM);
            assertThat(request.getAdditionalParameters()).containsKey("software_statement");
            assertThat(request.getAdditionalParameters().get("software_statement")).isEqualTo("legacy-wit-token");
        }

        @Test
        @DisplayName("Should not modify request when both softwareStatement and wit are absent")
        void shouldNotModifyRequestWhenBothSoftwareStatementAndWitAreAbsent() {
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
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).doesNotContainKey("software_statement");
        }

        @Test
        @DisplayName("Should handle null wit parameter value")
        void shouldHandleNullWitParameterValue() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, null);
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).doesNotContainKey("software_statement");
        }

        @Test
        @DisplayName("Should preserve other additional parameters when extracting WIT")
        void shouldPreserveOtherAdditionalParametersWhenExtractingWit() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "legacy-wit-token");
            additionalParams.put("custom_param", "custom_value");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).containsKey("custom_param");
            assertThat(request.getAdditionalParameters().get("custom_param")).isEqualTo("custom_value");
        }
    }

    @Nested
    @DisplayName("applyAuthentication - Input Validation")
    class InputValidationTests {

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
    }

    @Nested
    @DisplayName("getAuthenticationMethod Tests")
    class GetAuthenticationMethodTests {

        @Test
        @DisplayName("Should return software_statement as authentication method")
        void shouldReturnSoftwareStatementAsAuthenticationMethod() {
            // When
            String method = authentication.getAuthenticationMethod();

            // Then
            assertThat(method).isEqualTo("software_statement");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle blank softwareStatement")
        void shouldHandleBlankSoftwareStatement() {
            // Given
            HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create("https://as.example.com/register"));
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put(WitConstants.WIT_PARAM, "legacy-wit-token");
            
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .softwareStatement("   ")
                    .additionalParameters(additionalParams)
                    .build();

            // When
            HttpRequest.Builder result = authentication.applyAuthentication(requestBuilder, request);

            // Then - Should fall back to extracting from wit parameter
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).doesNotContainKey(WitConstants.WIT_PARAM);
            assertThat(request.getAdditionalParameters()).containsKey("software_statement");
        }

        @Test
        @DisplayName("Should handle request with empty additional parameters map")
        void shouldHandleRequestWithEmptyAdditionalParametersMap() {
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
            assertThat(result).isNotNull();
            assertThat(request.getAdditionalParameters()).isEmpty();
        }
    }
}
