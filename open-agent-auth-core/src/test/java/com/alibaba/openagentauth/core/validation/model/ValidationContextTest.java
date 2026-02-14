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
package com.alibaba.openagentauth.core.validation.model;

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ValidationContext}.
 */
@DisplayName("ValidationContext Tests")
class ValidationContextTest {

    private static final String HTTP_METHOD = "POST";
    private static final String HTTP_URI = "/api/agent/operation";
    private static final String HTTP_BODY = "{\"action\":\"execute\"}";

    @Test
    @DisplayName("Should build context with all fields")
    void shouldBuildContextWithAllFields() {
        // Arrange
        WorkloadIdentityToken wit = WorkloadIdentityToken.builder()
                .claims(WorkloadIdentityToken.Claims.builder()
                        .subject("workload-123")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .build())
                .header(WorkloadIdentityToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .build();
        WorkloadProofToken wpt = WorkloadProofToken.builder()
                .claims(WorkloadProofToken.Claims.builder()
                        .workloadTokenHash("hash123")
                        .build())
                .header(WorkloadProofToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .build();
        AgentOperationAuthToken aoat = AgentOperationAuthToken.builder()
                .claims(AgentOperationAuthToken.Claims.builder()
                        .issuer("https://as.example.com")
                        .subject("user-123")
                        .audience("resource-server")
                        .expirationTime(java.time.Instant.now().plusSeconds(3600))
                        .issuedAt(java.time.Instant.now())
                        .jwtId("jwt-id-123")
                        .agentIdentity(AgentIdentity.builder()
                                .id("urn:uuid:550e8400-e29b-41d4-a716-446655440001")
                                .issuer("https://agent-platform.example.com")
                                .issuedTo("https://agent-platform.example.com|user-123")
                                .build())
                        .authorization(AgentOperationAuthorization.builder()
                                .policyId("policy-123")
                                .build())
                        .build())
                .header(AgentOperationAuthToken.Header.builder()
                        .algorithm("ES256")
                        .build())
                .build();
        Date timestamp = new Date();
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "Bearer token");

        // Act
        ValidationContext context = ValidationContext.builder()
                .wit(wit)
                .wpt(wpt)
                .agentOaToken(aoat)
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .httpHeaders(headers)
                .httpBody(HTTP_BODY)
                .requestTimestamp(timestamp)
                .build();

        // Assert
        assertThat(context).isNotNull();
        assertThat(context.getWit()).isEqualTo(wit);
        assertThat(context.getWpt()).isEqualTo(wpt);
        assertThat(context.getAgentOaToken()).isEqualTo(aoat);
        assertThat(context.getHttpMethod()).isEqualTo(HTTP_METHOD);
        assertThat(context.getHttpUri()).isEqualTo(HTTP_URI);
        assertThat(context.getHttpBody()).isEqualTo(HTTP_BODY);
        assertThat(context.getRequestTimestamp()).isEqualTo(timestamp);
        assertThat(context.getHttpHeaders()).isNotNull();
        assertThat(context.getHttpHeaders()).hasSize(2);
        assertThat(context.getHttpHeader("Content-Type")).isEqualTo("application/json");
    }

    @Test
    @DisplayName("Should build context with minimal fields")
    void shouldBuildContextWithMinimalFields() {
        // Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .build();

        // Assert
        assertThat(context).isNotNull();
        assertThat(context.getWit()).isNull();
        assertThat(context.getWpt()).isNull();
        assertThat(context.getAgentOaToken()).isNull();
        assertThat(context.getHttpMethod()).isEqualTo(HTTP_METHOD);
        assertThat(context.getHttpUri()).isEqualTo(HTTP_URI);
        assertThat(context.getHttpBody()).isNull();
        assertThat(context.getRequestTimestamp()).isNotNull();
        assertThat(context.getHttpHeaders()).isNull();
    }

    @Test
    @DisplayName("Should auto-generate request timestamp if not provided")
    void shouldAutoGenerateRequestTimestampIfNotProvided() {
        // Arrange
        long beforeBuild = System.currentTimeMillis();

        // Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .build();

        long afterBuild = System.currentTimeMillis();

        // Assert
        assertThat(context.getRequestTimestamp()).isNotNull();
        assertThat(context.getRequestTimestamp().getTime()).isBetween(beforeBuild, afterBuild);
    }

    @Test
    @DisplayName("Should return null for non-existent header")
    void shouldReturnNullForNonExistentHeader() {
        // Arrange
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .httpHeaders(headers)
                .build();

        // Act
        String headerValue = context.getHttpHeader("Non-Existent-Header");

        // Assert
        assertThat(headerValue).isNull();
    }

    @Test
    @DisplayName("Should return null for header when headers map is null")
    void shouldReturnNullForHeaderWhenHeadersMapIsNull() {
        // Arrange
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .build();

        // Act
        String headerValue = context.getHttpHeader("Content-Type");

        // Assert
        assertThat(headerValue).isNull();
    }

    @Test
    @DisplayName("Should handle custom attributes")
    void shouldHandleCustomAttributes() {
        // Arrange
        String customKey = "custom-key";
        String customValue = "custom-value";
        Integer customNumber = 42;

        // Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .addAttribute(customKey, customValue)
                .addAttribute("number", customNumber)
                .build();

        // Assert
        assertThat(context.<String>getAttribute(customKey)).isEqualTo(customValue);
        assertThat(context.<Integer>getAttribute("number")).isEqualTo(customNumber);
        assertThat(context.getAttributes()).hasSize(2);
    }

    @Test
    @DisplayName("Should return null for non-existent attribute")
    void shouldReturnNullForNonExistentAttribute() {
        // Arrange
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .addAttribute("key", "value")
                .build();

        // Act
        Object value = context.getAttribute("non-existent-key");

        // Assert
        assertThat(value).isNull();
    }

    @Test
    @DisplayName("Should return null for attributes when attributes map is null")
    void shouldReturnNullForAttributesWhenAttributesMapIsNull() {
        // Arrange
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .build();

        // Act
        Map<String, Object> attributes = context.getAttributes();

        // Assert
        assertThat(attributes).isNull();
    }

    @Test
    @DisplayName("Should return immutable copy of headers")
    void shouldReturnImmutableCopyOfHeaders() {
        // Arrange
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");

        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .httpHeaders(headers)
                .build();

        // Act
        Map<String, String> returnedHeaders = context.getHttpHeaders();
        returnedHeaders.put("New-Header", "new-value");

        // Assert - Original headers should not be modified
        assertThat(context.getHttpHeader("New-Header")).isNull();
    }

    @Test
    @DisplayName("Should return immutable copy of attributes")
    void shouldReturnImmutableCopyOfAttributes() {
        // Arrange
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .addAttribute("key", "value")
                .build();

        // Act
        Map<String, Object> returnedAttributes = context.getAttributes();
        returnedAttributes.put("new-key", "new-value");

        // Assert - Original attributes should not be modified
        assertThat(context.<Object>getAttribute("new-key")).isNull();
    }

    @Test
    @DisplayName("Should support fluent builder pattern")
    void shouldSupportFluentBuilderPattern() {
        // Arrange & Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .httpBody(HTTP_BODY)
                .addAttribute("key1", "value1")
                .addAttribute("key2", "value2")
                .build();

        // Assert
        assertThat(context.getHttpMethod()).isEqualTo(HTTP_METHOD);
        assertThat(context.getHttpUri()).isEqualTo(HTTP_URI);
        assertThat(context.getHttpBody()).isEqualTo(HTTP_BODY);
        assertThat(context.getAttributes()).hasSize(2);
    }

    @Test
    @DisplayName("Should set all custom attributes at once")
    void shouldSetAllCustomAttributesAtOnce() {
        // Arrange
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("key1", "value1");
        attributes.put("key2", 42);

        // Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .attributes(attributes)
                .build();

        // Assert
        assertThat(context.<String>getAttribute("key1")).isEqualTo("value1");
        assertThat(context.<Integer>getAttribute("key2")).isEqualTo(42);
    }

    @Test
    @DisplayName("Should handle empty headers map")
    void shouldHandleEmptyHeadersMap() {
        // Arrange
        Map<String, String> headers = new HashMap<>();

        // Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(HTTP_METHOD)
                .httpUri(HTTP_URI)
                .httpHeaders(headers)
                .build();

        // Assert
        assertThat(context.getHttpHeaders()).isNotNull();
        assertThat(context.getHttpHeaders()).isEmpty();
    }

    @Test
    @DisplayName("Should handle null values in builder")
    void shouldHandleNullValuesInBuilder() {
        // Act
        ValidationContext context = ValidationContext.builder()
                .httpMethod(null)
                .httpUri(null)
                .httpBody(null)
                .build();

        // Assert
        assertThat(context.getHttpMethod()).isNull();
        assertThat(context.getHttpUri()).isNull();
        assertThat(context.getHttpBody()).isNull();
    }
}
