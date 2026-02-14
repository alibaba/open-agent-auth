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
package com.alibaba.openagentauth.framework.model.response;

import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RequestAuthUrlResponse}.
 * <p>
 * This test class verifies the behavior of the RequestAuthUrlResponse class,
 * including builder pattern and getter methods.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("RequestAuthUrlResponse Tests")
class RequestAuthUrlResponseTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build response with authorizationUrl")
        void shouldBuildResponseWithAuthorizationUrl() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth.example.com/authorize?request_uri=urn:123")
                .build();

            assertThat(response.getAuthorizationUrl()).isEqualTo("https://auth.example.com/authorize?request_uri=urn:123");
        }

        @Test
        @DisplayName("Should build response with all fields")
        void shouldBuildResponseWithAllFields() {
            WorkloadContext workloadContext = WorkloadContext.builder()
                .wit("wit-token")
                .build();

            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth.example.com/authorize?request_uri=urn:123")
                .requestUri("urn:ietf:params:oauth:request_uri:123")
                .state("state-456")
                .workloadContext(workloadContext)
                .redirectUri("https://example.com/callback")
                .build();

            assertThat(response.getAuthorizationUrl()).isEqualTo("https://auth.example.com/authorize?request_uri=urn:123");
            assertThat(response.getRequestUri()).isEqualTo("urn:ietf:params:oauth:request_uri:123");
            assertThat(response.getState()).isEqualTo("state-456");
            assertThat(response.getWorkloadContext()).isEqualTo(workloadContext);
            assertThat(response.getRedirectUri()).isEqualTo("https://example.com/callback");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth.example.com/authorize")
                .requestUri("urn:123")
                .state("state")
                .redirectUri("https://example.com/callback")
                .build();

            assertThat(response).isNotNull();
        }

        @Test
        @DisplayName("Should handle null values")
        void shouldHandleNullValues() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl(null)
                .requestUri(null)
                .state(null)
                .workloadContext(null)
                .redirectUri(null)
                .build();

            assertThat(response.getAuthorizationUrl()).isNull();
            assertThat(response.getRequestUri()).isNull();
            assertThat(response.getState()).isNull();
            assertThat(response.getWorkloadContext()).isNull();
            assertThat(response.getRedirectUri()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return authorizationUrl")
        void shouldReturnAuthorizationUrl() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth.example.com/authorize?request_uri=urn:123")
                .build();

            assertThat(response.getAuthorizationUrl()).isEqualTo("https://auth.example.com/authorize?request_uri=urn:123");
        }

        @Test
        @DisplayName("Should return requestUri")
        void shouldReturnRequestUri() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .requestUri("urn:ietf:params:oauth:request_uri:123")
                .build();

            assertThat(response.getRequestUri()).isEqualTo("urn:ietf:params:oauth:request_uri:123");
        }

        @Test
        @DisplayName("Should return state")
        void shouldReturnState() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .state("state-456")
                .build();

            assertThat(response.getState()).isEqualTo("state-456");
        }

        @Test
        @DisplayName("Should return workloadContext")
        void shouldReturnWorkloadContext() {
            WorkloadContext workloadContext = WorkloadContext.builder()
                .wit("wit-token")
                .build();

            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .workloadContext(workloadContext)
                .build();

            assertThat(response.getWorkloadContext()).isEqualTo(workloadContext);
        }

        @Test
        @DisplayName("Should return redirectUri")
        void shouldReturnRedirectUri() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .redirectUri("https://example.com/callback")
                .build();

            assertThat(response.getRedirectUri()).isEqualTo("https://example.com/callback");
        }

        @Test
        @DisplayName("Should return null for missing fields")
        void shouldReturnNullForMissingFields() {
            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth.example.com/authorize")
                .build();

            assertThat(response.getRequestUri()).isNull();
            assertThat(response.getState()).isNull();
            assertThat(response.getWorkloadContext()).isNull();
            assertThat(response.getRedirectUri()).isNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complex authorization URL")
        void shouldHandleComplexAuthorizationUrl() {
            String complexUrl = "https://auth.example.com/authorize?request_uri=urn:ietf:params:oauth:request_uri:abc123&client_id=client123&response_type=code";

            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl(complexUrl)
                .build();

            assertThat(response.getAuthorizationUrl()).isEqualTo(complexUrl);
        }

        @Test
        @DisplayName("Should handle different URN formats")
        void shouldHandleDifferentUrnFormats() {
            RequestAuthUrlResponse response1 = RequestAuthUrlResponse.builder()
                .requestUri("urn:ietf:params:oauth:request_uri:123")
                .build();

            RequestAuthUrlResponse response2 = RequestAuthUrlResponse.builder()
                .requestUri("urn:example:custom:456")
                .build();

            assertThat(response1.getRequestUri()).isEqualTo("urn:ietf:params:oauth:request_uri:123");
            assertThat(response2.getRequestUri()).isEqualTo("urn:example:custom:456");
        }

        @Test
        @DisplayName("Should handle complex workload context")
        void shouldHandleComplexWorkloadContext() {
            WorkloadContext workloadContext = WorkloadContext.builder()
                .workloadId("workload-123")
                .userId("user-456")
                .wit("wit-token")
                .publicKey("public-key")
                .privateKey("private-key")
                .build();

            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .workloadContext(workloadContext)
                .build();

            assertThat(response.getWorkloadContext().getWorkloadId()).isEqualTo("workload-123");
            assertThat(response.getWorkloadContext().getUserId()).isEqualTo("user-456");
            assertThat(response.getWorkloadContext().getWit()).isEqualTo("wit-token");
            assertThat(response.getWorkloadContext().getPublicKey()).isEqualTo("public-key");
        }

        @Test
        @DisplayName("Should handle different redirect URIs")
        void shouldHandleDifferentRedirectUris() {
            RequestAuthUrlResponse response1 = RequestAuthUrlResponse.builder()
                .redirectUri("https://example.com/callback")
                .build();

            RequestAuthUrlResponse response2 = RequestAuthUrlResponse.builder()
                .redirectUri("https://app.example.com/oauth/callback")
                .build();

            RequestAuthUrlResponse response3 = RequestAuthUrlResponse.builder()
                .redirectUri("http://localhost:8080/callback")
                .build();

            assertThat(response1.getRedirectUri()).isEqualTo("https://example.com/callback");
            assertThat(response2.getRedirectUri()).isEqualTo("https://app.example.com/oauth/callback");
            assertThat(response3.getRedirectUri()).isEqualTo("http://localhost:8080/callback");
        }

        @Test
        @DisplayName("Should create multiple independent instances")
        void shouldCreateMultipleIndependentInstances() {
            RequestAuthUrlResponse response1 = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth1.example.com")
                .state("state-1")
                .build();

            RequestAuthUrlResponse response2 = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth2.example.com")
                .state("state-2")
                .build();

            assertThat(response1.getAuthorizationUrl()).isEqualTo("https://auth1.example.com");
            assertThat(response2.getAuthorizationUrl()).isEqualTo("https://auth2.example.com");
            assertThat(response1).isNotSameAs(response2);
        }

        @Test
        @DisplayName("Should handle state parameter for CSRF protection")
        void shouldHandleStateParameterForCsrfProtection() {
            String state = "random-state-value-for-csrf-protection";

            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .state(state)
                .build();

            assertThat(response.getState()).isEqualTo(state);
        }

        @Test
        @DisplayName("Should build complete OAuth flow response")
        void shouldBuildCompleteOAuthFlowResponse() {
            WorkloadContext workloadContext = WorkloadContext.builder()
                .wit("wit-token")
                .build();

            RequestAuthUrlResponse response = RequestAuthUrlResponse.builder()
                .authorizationUrl("https://auth.example.com/authorize?request_uri=urn:123")
                .requestUri("urn:ietf:params:oauth:request_uri:123")
                .state("state-456")
                .workloadContext(workloadContext)
                .redirectUri("https://example.com/callback")
                .build();

            assertThat(response.getAuthorizationUrl()).isNotNull();
            assertThat(response.getRequestUri()).isNotNull();
            assertThat(response.getState()).isNotNull();
            assertThat(response.getWorkloadContext()).isNotNull();
            assertThat(response.getRedirectUri()).isNotNull();
        }
    }
}
