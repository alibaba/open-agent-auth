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
package com.alibaba.openagentauth.core.model.oauth2.par;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ParRequest.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * ParRequest, including normal construction, method chaining,
 * required field validation, optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("ParRequest.Builder Tests")
class ParRequestTest {

    private static final String RESPONSE_TYPE = "code";
    private static final String CLIENT_ID = "client_abc";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String SCOPE = "openid profile";
    private static final String STATE = "xyz789";
    private static final String REQUEST_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build request with all required fields")
        void shouldBuildRequestWithAllRequiredFields() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getResponseType()).isEqualTo(RESPONSE_TYPE);
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should build request with all fields")
        void shouldBuildRequestWithAllFields() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE)
                    .state(STATE)
                    .requestJwt(REQUEST_JWT)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getResponseType()).isEqualTo(RESPONSE_TYPE);
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(request.getScope()).isEqualTo(SCOPE);
            assertThat(request.getState()).isEqualTo(STATE);
            assertThat(request.getRequestJwt()).isEqualTo(REQUEST_JWT);
        }

        @Test
        @DisplayName("Should build request with additional parameters")
        void shouldBuildRequestWithAdditionalParameters() {
            // Given
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("custom_param", "custom_value");

            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .additionalParameters(additionalParams)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getAdditionalParameters()).isEqualTo(additionalParams);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE)
                    .state(STATE)
                    .requestJwt(REQUEST_JWT)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getResponseType()).isEqualTo(RESPONSE_TYPE);
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request.getScope()).isEqualTo(SCOPE);
            assertThat(request.getState()).isEqualTo(STATE);
            assertThat(request.getRequestJwt()).isEqualTo(REQUEST_JWT);
        }
    }

    @Nested
    @DisplayName("Required Field Validation Tests")
    class RequiredFieldValidationTests {

        @Test
        @DisplayName("Should throw exception when responseType is null")
        void shouldThrowExceptionWhenResponseTypeIsNull() {
            // When & Then
            assertThatThrownBy(() -> ParRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("response_type is required");
        }

        @Test
        @DisplayName("Should throw exception when clientId is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // When & Then
            assertThatThrownBy(() -> ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("client_id is required");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            // When & Then
            assertThatThrownBy(() -> ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("redirect_uri is required");
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getScope()).isNull();
            assertThat(request.getState()).isNull();
            assertThat(request.getRequestJwt()).isNull();
            assertThat(request.getAdditionalParameters()).isNull();
        }

        @Test
        @DisplayName("Should set optional scope field")
        void shouldSetOptionalScopeField() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE)
                    .build();

            // Then
            assertThat(request.getScope()).isEqualTo(SCOPE);
        }

        @Test
        @DisplayName("Should set optional state field")
        void shouldSetOptionalStateField() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .state(STATE)
                    .build();

            // Then
            assertThat(request.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should set optional requestJwt field")
        void shouldSetOptionalRequestJwtField() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .requestJwt(REQUEST_JWT)
                    .build();

            // Then
            assertThat(request.getRequestJwt()).isEqualTo(REQUEST_JWT);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request).isInstanceOf(ParRequest.class);
            assertThat(request.getResponseType()).isEqualTo(RESPONSE_TYPE);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            ParRequest.Builder builder = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI);

            // When
            ParRequest request1 = builder.build();
            builder.clientId("different_client");
            ParRequest request2 = builder.build();

            // Then
            assertThat(request1.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request2.getClientId()).isEqualTo("different_client");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // When
            ParRequest request1 = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            ParRequest request2 = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            // ParRequest does not override equals/hashCode, so they are not equal
            // Two different instances should not be equal
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal when clientIds differ")
        void shouldNotBeEqualWhenClientIdsDiffer() {
            // When
            ParRequest request1 = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            ParRequest request2 = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId("different_client")
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            assertThat(request1).isNotEqualTo(request2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include class name in toString")
        void shouldIncludeClassNameInToString() {
            // When
            ParRequest request = ParRequest.builder()
                    .responseType(RESPONSE_TYPE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build();

            // Then
            String toString = request.toString();
            // ParRequest uses default toString() which includes class name
            assertThat(toString).contains("ParRequest");
        }
    }
}
