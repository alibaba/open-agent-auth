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
package com.alibaba.openagentauth.framework.model.request;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ParRequest}.
 * <p>
 * This test class verifies the behavior of the ParRequest class,
 * including builder pattern and getter methods.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ParRequest Tests")
class ParRequestTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with requestJwt")
        void shouldBuildRequestWithRequestJwt() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .build();

            assertThat(request.getRequestJwt()).isEqualTo("jwt-token");
        }

        @Test
        @DisplayName("Should build request with all fields")
        void shouldBuildRequestWithAllFields() {
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("param1", "value1");
            additionalParams.put("param2", "value2");

            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .clientAssertion("client-assertion")
                .clientAssertionType("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .additionalParameters(additionalParams)
                .state("state-123")
                .build();

            assertThat(request.getRequestJwt()).isEqualTo("jwt-token");
            assertThat(request.getClientAssertion()).isEqualTo("client-assertion");
            assertThat(request.getClientAssertionType()).isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            assertThat(request.getAdditionalParameters()).hasSize(2);
            assertThat(request.getState()).isEqualTo("state-123");
        }

        @Test
        @DisplayName("Should use default clientAssertionType")
        void shouldUseDefaultClientAssertionType() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .build();

            assertThat(request.getClientAssertionType()).isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .clientAssertion("client-assertion")
                .clientAssertionType("custom-type")
                .state("state-123")
                .build();

            assertThat(request).isNotNull();
        }

        @Test
        @DisplayName("Should handle null values")
        void shouldHandleNullValues() {
            ParRequest request = ParRequest.builder()
                .requestJwt(null)
                .clientAssertion(null)
                .additionalParameters(null)
                .state(null)
                .build();

            assertThat(request.getRequestJwt()).isNull();
            assertThat(request.getClientAssertion()).isNull();
            assertThat(request.getAdditionalParameters()).isNull();
            assertThat(request.getState()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return requestJwt")
        void shouldReturnRequestJwt() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .build();

            assertThat(request.getRequestJwt()).isEqualTo("jwt-token");
        }

        @Test
        @DisplayName("Should return clientAssertion")
        void shouldReturnClientAssertion() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .clientAssertion("client-assertion")
                .build();

            assertThat(request.getClientAssertion()).isEqualTo("client-assertion");
        }

        @Test
        @DisplayName("Should return clientAssertionType")
        void shouldReturnClientAssertionType() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .clientAssertionType("custom-type")
                .build();

            assertThat(request.getClientAssertionType()).isEqualTo("custom-type");
        }

        @Test
        @DisplayName("Should return additionalParameters")
        void shouldReturnAdditionalParameters() {
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("key", "value");

            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .additionalParameters(additionalParams)
                .build();

            assertThat(request.getAdditionalParameters()).hasSize(1);
            assertThat(request.getAdditionalParameters().get("key")).isEqualTo("value");
        }

        @Test
        @DisplayName("Should return state")
        void shouldReturnState() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .state("state-123")
                .build();

            assertThat(request.getState()).isEqualTo("state-123");
        }

        @Test
        @DisplayName("Should return null for missing fields")
        void shouldReturnNullForMissingFields() {
            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .build();

            assertThat(request.getClientAssertion()).isNull();
            assertThat(request.getAdditionalParameters()).isNull();
            assertThat(request.getState()).isNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complex additional parameters")
        void shouldHandleComplexAdditionalParameters() {
            Map<String, Object> additionalParams = new HashMap<>();
            additionalParams.put("response_type", "code");
            additionalParams.put("scope", "openid profile");
            additionalParams.put("redirect_uri", "https://example.com/callback");

            ParRequest request = ParRequest.builder()
                .requestJwt("jwt-token")
                .additionalParameters(additionalParams)
                .build();

            assertThat(request.getAdditionalParameters()).hasSize(3);
            assertThat(request.getAdditionalParameters().get("response_type")).isEqualTo("code");
        }

        @Test
        @DisplayName("Should create multiple independent instances")
        void shouldCreateMultipleIndependentInstances() {
            ParRequest request1 = ParRequest.builder()
                .requestJwt("jwt-1")
                .state("state-1")
                .build();

            ParRequest request2 = ParRequest.builder()
                .requestJwt("jwt-2")
                .state("state-2")
                .build();

            assertThat(request1.getRequestJwt()).isEqualTo("jwt-1");
            assertThat(request2.getRequestJwt()).isEqualTo("jwt-2");
            assertThat(request1).isNotSameAs(request2);
        }
    }
}
