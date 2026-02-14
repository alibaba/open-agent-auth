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
package com.alibaba.openagentauth.core.model.oauth2.dcr;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DcrRequest}.
 * <p>
 * Tests verify compliance with OAuth 2.0 Dynamic Client Registration (RFC 7591)
 * regarding request structure, validation, and serialization.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <ul>
 *   <li>Required fields validation (redirect_uris per RFC 7591 Section 3.1)</li>
 *   <li>Optional fields handling</li>
 *   <li>Builder pattern implementation</li>
 *   <li>Equality and hashCode</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
@DisplayName("DCR Request Tests - RFC 7591")
class DcrRequestTest {

    private DcrRequest.Builder builder;

    @BeforeEach
    void setUp() {
        builder = DcrRequest.builder()
                .redirectUris(List.of("https://example.com/callback"));
    }

    @Nested
    @DisplayName("Builder Pattern - RFC 7591 Section 3")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with required field only")
        void shouldBuildRequestWithRequiredFieldOnly() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getRedirectUris()).isEqualTo(List.of("https://example.com/callback"));
        }

        @Test
        @DisplayName("Should build request with all optional fields")
        void shouldBuildRequestWithAllOptionalFields() {
            // Given
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("custom_param", "custom_value");

            // When
            DcrRequest request = builder
                    .clientName("Test Client")
                    .grantTypes(List.of("authorization_code", "refresh_token"))
                    .responseTypes(List.of("code"))
                    .tokenEndpointAuthMethod("private_key_jwt")
                    .scope("read write")
                    .additionalParameters(additionalParams)
                    .build();

            // Then
            assertThat(request.getClientName()).isEqualTo("Test Client");
            assertThat(request.getGrantTypes()).isEqualTo(List.of("authorization_code", "refresh_token"));
            assertThat(request.getResponseTypes()).isEqualTo(List.of("code"));
            assertThat(request.getTokenEndpointAuthMethod()).isEqualTo("private_key_jwt");
            assertThat(request.getScope()).isEqualTo("read write");
            assertThat(request.getAdditionalParameters()).isEqualTo(additionalParams);
        }

        @Test
        @DisplayName("Should support builder reuse")
        void shouldSupportBuilderReuse() {
            // Given
            DcrRequest request1 = builder
                    .clientName("Client 1")
                    .build();

            // When
            DcrRequest request2 = builder
                    .clientName("Client 2")
                    .build();

            // Then
            assertThat(request1.getClientName()).isEqualTo("Client 1");
            assertThat(request2.getClientName()).isEqualTo("Client 2");
        }
    }

    @Nested
    @DisplayName("Required Field Validation - RFC 7591 Section 3.1")
    class RequiredFieldValidationTests {

        @Test
        @DisplayName("Should throw exception when redirect_uris is null")
        void shouldThrowExceptionWhenRedirectUrisIsNull() {
            // Given
            DcrRequest.Builder invalidBuilder = DcrRequest.builder();

            // When & Then
            assertThatThrownBy(invalidBuilder::build)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uris is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when redirect_uris is empty")
        void shouldThrowExceptionWhenRedirectUrisIsEmpty() {
            // Given
            DcrRequest.Builder invalidBuilder = DcrRequest.builder()
                    .redirectUris(List.of());

            // When & Then
            assertThatThrownBy(invalidBuilder::build)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uris is REQUIRED");
        }

        @Test
        @DisplayName("Should accept valid redirect_uris")
        void shouldAcceptValidRedirectUris() {
            // Given
            List<String> redirectUris = List.of(
                    "https://example.com/callback",
                    "https://app.example.com/redirect"
            );

            // When
            DcrRequest request = DcrRequest.builder()
                    .redirectUris(redirectUris)
                    .build();

            // Then
            assertThat(request.getRedirectUris()).isEqualTo(redirectUris);
        }
    }

    @Nested
    @DisplayName("Optional Fields - RFC 7591 Section 3.1")
    class OptionalFieldsTests {

        @Test
        @DisplayName("Should handle null client_name")
        void shouldHandleNullClientName() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request.getClientName()).isNull();
        }

        @Test
        @DisplayName("Should handle null grant_types")
        void shouldHandleNullGrantTypes() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request.getGrantTypes()).isNull();
        }

        @Test
        @DisplayName("Should handle null response_types")
        void shouldHandleNullResponseTypes() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request.getResponseTypes()).isNull();
        }

        @Test
        @DisplayName("Should handle null token_endpoint_auth_method")
        void shouldHandleNullTokenEndpointAuthMethod() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request.getTokenEndpointAuthMethod()).isNull();
        }

        @Test
        @DisplayName("Should handle null scope")
        void shouldHandleNullScope() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request.getScope()).isNull();
        }

        @Test
        @DisplayName("Should handle null additional_parameters")
        void shouldHandleNullAdditionalParameters() {
            // When
            DcrRequest request = builder.build();

            // Then
            assertThat(request.getAdditionalParameters()).isNull();
        }
    }

    @Nested
    @DisplayName("Equality and HashCode - RFC 7591")
    class EqualityAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Given
            DcrRequest request1 = builder
                    .clientName("Test Client")
                    .grantTypes(List.of("authorization_code"))
                    .build();

            DcrRequest request2 = DcrRequest.builder()
                    .redirectUris(List.of("https://example.com/callback"))
                    .clientName("Test Client")
                    .grantTypes(List.of("authorization_code"))
                    .build();

            // Then
            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when redirect_uris differ")
        void shouldNotBeEqualWhenRedirectUrisDiffer() {
            // Given
            DcrRequest request1 = builder.build();

            DcrRequest request2 = DcrRequest.builder()
                    .redirectUris(List.of("https://other.example.com/callback"))
                    .build();

            // Then
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal when client_name differs")
        void shouldNotBeEqualWhenClientNameDiffers() {
            // Given
            DcrRequest request1 = builder.clientName("Client 1").build();

            DcrRequest request2 = builder.clientName("Client 2").build();

            // Then
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal when grant_types differ")
        void shouldNotBeEqualWhenGrantTypesDiffer() {
            // Given
            DcrRequest request1 = builder.grantTypes(List.of("authorization_code")).build();

            DcrRequest request2 = builder.grantTypes(List.of("client_credentials")).build();

            // Then
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal when token_endpoint_auth_method differs")
        void shouldNotBeEqualWhenTokenEndpointAuthMethodDiffers() {
            // Given
            DcrRequest request1 = builder.tokenEndpointAuthMethod("private_key_jwt").build();

            DcrRequest request2 = builder.tokenEndpointAuthMethod("client_secret_basic").build();

            // Then
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            DcrRequest request = builder.build();

            // Then
            assertThat(request).isEqualTo(request);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            DcrRequest request = builder.build();

            // Then
            assertThat(request).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            DcrRequest request = builder.build();

            // Then
            assertThat(request).isNotEqualTo("not a DcrRequest");
        }
    }

    @Nested
    @DisplayName("Additional Parameters - RFC 7591 Section 3.1")
    class AdditionalParametersTests {

        @Test
        @DisplayName("Should store custom parameters")
        void shouldStoreCustomParameters() {
            // Given
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("software_id", "550e8400-e29b-41d4-a716-446655440000");
            additionalParams.put("software_version", "1.0.0");

            // When
            DcrRequest request = builder
                    .additionalParameters(additionalParams)
                    .build();

            // Then
            assertThat(request.getAdditionalParameters()).isEqualTo(additionalParams);
            assertThat(request.getAdditionalParameters().get("software_id")).isEqualTo("550e8400-e29b-41d4-a716-446655440000");
            assertThat(request.getAdditionalParameters().get("software_version")).isEqualTo("1.0.0");
        }

        @Test
        @DisplayName("Should handle empty additional parameters")
        void shouldHandleEmptyAdditionalParameters() {
            // Given
            Map<String, Object> emptyParams = new HashMap<>();

            // When
            DcrRequest request = builder
                    .additionalParameters(emptyParams)
                    .build();

            // Then
            assertThat(request.getAdditionalParameters()).isEqualTo(emptyParams);
        }

        @Test
        @DisplayName("Should handle complex object values in additional parameters")
        void shouldHandleComplexObjectValuesInAdditionalParameters() {
            // Given
            Map<String, Object> complexParams = new HashMap<>();
            Map<String, String> nestedValue = new HashMap<>();
            nestedValue.put("key", "value");
            complexParams.put("nested_object", nestedValue);

            // When
            DcrRequest request = builder
                    .additionalParameters(complexParams)
                    .build();

            // Then
            assertThat(request.getAdditionalParameters()).isNotNull();
            assertThat(request.getAdditionalParameters().get("nested_object")).isEqualTo(nestedValue);
        }
    }

    @Nested
    @DisplayName("Standard OAuth 2.0 Values - RFC 7591 Section 3.1")
    class StandardOAuth2ValuesTests {

        @Test
        @DisplayName("Should accept standard grant types")
        void shouldAcceptStandardGrantTypes() {
            // Given
            List<String> grantTypes = List.of(
                    "authorization_code",
                    "implicit",
                    "password",
                    "client_credentials",
                    "refresh_token"
            );

            // When
            DcrRequest request = builder
                    .grantTypes(grantTypes)
                    .build();

            // Then
            assertThat(request.getGrantTypes()).isEqualTo(grantTypes);
        }

        @Test
        @DisplayName("Should accept standard response types")
        void shouldAcceptStandardResponseTypes() {
            // Given
            List<String> responseTypes = List.of("code", "token", "id_token");

            // When
            DcrRequest request = builder
                    .responseTypes(responseTypes)
                    .build();

            // Then
            assertThat(request.getResponseTypes()).isEqualTo(responseTypes);
        }

        @Test
        @DisplayName("Should accept standard token endpoint auth methods")
        void shouldAcceptStandardTokenEndpointAuthMethods() {
            // Given
            String authMethod = "private_key_jwt";

            // When
            DcrRequest request = builder
                    .tokenEndpointAuthMethod(authMethod)
                    .build();

            // Then
            assertThat(request.getTokenEndpointAuthMethod()).isEqualTo(authMethod);
        }

        @Test
        @DisplayName("Should accept scope string with multiple values")
        void shouldAcceptScopeStringWithMultipleValues() {
            // Given
            String scope = "read write profile email";

            // When
            DcrRequest request = builder
                    .scope(scope)
                    .build();

            // Then
            assertThat(request.getScope()).isEqualTo(scope);
        }
    }
}
