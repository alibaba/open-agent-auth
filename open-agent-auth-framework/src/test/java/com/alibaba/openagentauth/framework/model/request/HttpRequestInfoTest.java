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
 * Unit tests for {@link HttpRequestInfo}.
 * <p>
 * This test class verifies the behavior of the HttpRequestInfo class,
 * including builder pattern and getter methods.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("HttpRequestInfo Tests")
class HttpRequestInfoTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with method")
        void shouldBuildRequestWithMethod() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .build();

            assertThat(request.getMethod()).isEqualTo("GET");
        }

        @Test
        @DisplayName("Should build request with method and uri")
        void shouldBuildRequestWithMethodAndUri() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("POST")
                .uri("/api/resource")
                .build();

            assertThat(request.getMethod()).isEqualTo("POST");
            assertThat(request.getUri()).isEqualTo("/api/resource");
        }

        @Test
        @DisplayName("Should build request with all fields")
        void shouldBuildRequestWithAllFields() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("Authorization", "Bearer token");

            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("POST")
                .uri("/api/resource")
                .headers(headers)
                .body("{\"key\":\"value\"}")
                .build();

            assertThat(request.getMethod()).isEqualTo("POST");
            assertThat(request.getUri()).isEqualTo("/api/resource");
            assertThat(request.getHeaders()).hasSize(2);
            assertThat(request.getBody()).isEqualTo("{\"key\":\"value\"}");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource")
                .headers(new HashMap<>())
                .body("")
                .build();

            assertThat(request).isNotNull();
        }

        @Test
        @DisplayName("Should handle null values")
        void shouldHandleNullValues() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method(null)
                .uri(null)
                .headers(null)
                .body(null)
                .build();

            assertThat(request.getMethod()).isNull();
            assertThat(request.getUri()).isNull();
            assertThat(request.getHeaders()).isNull();
            assertThat(request.getBody()).isNull();
        }

        @Test
        @DisplayName("Should handle empty headers")
        void shouldHandleEmptyHeaders() {
            Map<String, String> headers = new HashMap<>();

            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource")
                .headers(headers)
                .build();

            assertThat(request.getHeaders()).isNotNull();
            assertThat(request.getHeaders()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return method")
        void shouldReturnMethod() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .build();

            assertThat(request.getMethod()).isEqualTo("GET");
        }

        @Test
        @DisplayName("Should return uri")
        void shouldReturnUri() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .uri("/api/resource")
                .build();

            assertThat(request.getUri()).isEqualTo("/api/resource");
        }

        @Test
        @DisplayName("Should return headers")
        void shouldReturnHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer token");
            headers.put("Content-Type", "application/json");

            HttpRequestInfo request = HttpRequestInfo.builder()
                .headers(headers)
                .build();

            assertThat(request.getHeaders()).hasSize(2);
            assertThat(request.getHeaders().get("Authorization")).isEqualTo("Bearer token");
            assertThat(request.getHeaders().get("Content-Type")).isEqualTo("application/json");
        }

        @Test
        @DisplayName("Should return body")
        void shouldReturnBody() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .body("{\"key\":\"value\"}")
                .build();

            assertThat(request.getBody()).isEqualTo("{\"key\":\"value\"}");
        }

        @Test
        @DisplayName("Should return null for missing fields")
        void shouldReturnNullForMissingFields() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .build();

            assertThat(request.getUri()).isNull();
            assertThat(request.getHeaders()).isNull();
            assertThat(request.getBody()).isNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complex headers")
        void shouldHandleComplexHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer token123");
            headers.put("Content-Type", "application/json");
            headers.put("User-Agent", "TestAgent/1.0");
            headers.put("X-Custom-Header", "custom-value");

            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("POST")
                .uri("/api/resource")
                .headers(headers)
                .build();

            assertThat(request.getHeaders()).hasSize(4);
            assertThat(request.getHeaders().get("Authorization")).isEqualTo("Bearer token123");
        }

        @Test
        @DisplayName("Should handle empty body")
        void shouldHandleEmptyBody() {
            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource")
                .body("")
                .build();

            assertThat(request.getBody()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle large body")
        void shouldHandleLargeBody() {
            StringBuilder largeBody = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                largeBody.append("data");
            }

            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("POST")
                .uri("/api/resource")
                .body(largeBody.toString())
                .build();

            assertThat(request.getBody()).hasSize(4000);
        }

        @Test
        @DisplayName("Should handle different HTTP methods")
        void shouldHandleDifferentHttpMethods() {
            HttpRequestInfo getRequest = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource")
                .build();

            HttpRequestInfo postRequest = HttpRequestInfo.builder()
                .method("POST")
                .uri("/api/resource")
                .build();

            HttpRequestInfo putRequest = HttpRequestInfo.builder()
                .method("PUT")
                .uri("/api/resource")
                .build();

            HttpRequestInfo deleteRequest = HttpRequestInfo.builder()
                .method("DELETE")
                .uri("/api/resource")
                .build();

            assertThat(getRequest.getMethod()).isEqualTo("GET");
            assertThat(postRequest.getMethod()).isEqualTo("POST");
            assertThat(putRequest.getMethod()).isEqualTo("PUT");
            assertThat(deleteRequest.getMethod()).isEqualTo("DELETE");
        }

        @Test
        @DisplayName("Should handle different URI formats")
        void shouldHandleDifferentUriFormats() {
            HttpRequestInfo request1 = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource")
                .build();

            HttpRequestInfo request2 = HttpRequestInfo.builder()
                .method("GET")
                .uri("https://example.com/api/resource")
                .build();

            HttpRequestInfo request3 = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource?id=123&filter=active")
                .build();

            assertThat(request1.getUri()).isEqualTo("/api/resource");
            assertThat(request2.getUri()).isEqualTo("https://example.com/api/resource");
            assertThat(request3.getUri()).isEqualTo("/api/resource?id=123&filter=active");
        }

        @Test
        @DisplayName("Should create multiple independent instances")
        void shouldCreateMultipleIndependentInstances() {
            HttpRequestInfo request1 = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource1")
                .build();

            HttpRequestInfo request2 = HttpRequestInfo.builder()
                .method("POST")
                .uri("/api/resource2")
                .build();

            assertThat(request1.getMethod()).isEqualTo("GET");
            assertThat(request2.getMethod()).isEqualTo("POST");
            assertThat(request1).isNotSameAs(request2);
        }

        @Test
        @DisplayName("Should handle headers with multiple values")
        void shouldHandleHeadersWithMultipleValues() {
            Map<String, String> headers = new HashMap<>();
            headers.put("Accept", "application/json, text/plain");
            headers.put("Cache-Control", "no-cache, no-store");

            HttpRequestInfo request = HttpRequestInfo.builder()
                .method("GET")
                .uri("/api/resource")
                .headers(headers)
                .build();

            assertThat(request.getHeaders()).hasSize(2);
            assertThat(request.getHeaders().get("Accept")).isEqualTo("application/json, text/plain");
        }
    }
}
