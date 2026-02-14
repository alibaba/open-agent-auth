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
package com.alibaba.openagentauth.framework.executor.strategy;

import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.model.workload.WorkloadRequestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for PolicyBuilder.
 * <p>
 * This test class verifies the functionality of building Rego policy strings.
 * </p>
 */
@DisplayName("PolicyBuilder Tests")
class PolicyBuilderTest {

    private PolicyBuilder defaultBuilder;
    private RequestAuthUrlRequest request;

    @BeforeEach
    void setUp() {
        defaultBuilder = PolicyBuilder.defaultBuilder();
        request = createTestRequest();
    }

    private RequestAuthUrlRequest createTestRequest() {
        return RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("test input")
                .workloadContext(WorkloadRequestContext.builder()
                        .operationType("read")
                        .build())
                .build();
    }

    @Nested
    @DisplayName("Default Builder Tests")
    class DefaultBuilderTests {

        @Test
        @DisplayName("Should create default builder")
        void shouldCreateDefaultBuilder() {
            assertThat(defaultBuilder).isNotNull();
        }

        @Test
        @DisplayName("Should build policy with operation type")
        void shouldBuildPolicyWithOperationType() {
            String policy = defaultBuilder.buildPolicy(request);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("package agent");
            assertThat(policy).contains("input.operationType == \"read\"");
        }

        @Test
        @DisplayName("Should build policy with resource ID")
        void shouldBuildPolicyWithResourceId() {
            RequestAuthUrlRequest requestWithResourceId = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("read")
                            .resourceId("resource-123")
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithResourceId);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.operationType == \"read\"");
            assertThat(policy).contains("input.resourceId == \"resource-123\"");
        }

        @Test
        @DisplayName("Should build policy with metadata")
        void shouldBuildPolicyWithMetadata() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("environment", "production");
            metadata.put("region", "us-west-2");
            
            RequestAuthUrlRequest requestWithMetadata = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("write")
                            .metadata(metadata)
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithMetadata);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.operationType == \"write\"");
            assertThat(policy).contains("input.context.environment == \"production\"");
            assertThat(policy).contains("input.context.region == \"us-west-2\"");
        }

        @Test
        @DisplayName("Should build policy with all fields")
        void shouldBuildPolicyWithAllFields() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("user", "admin");
            metadata.put("ip", "192.168.1.1");
            
            RequestAuthUrlRequest requestWithAllFields = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("delete")
                            .resourceId("resource-456")
                            .metadata(metadata)
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithAllFields);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("package agent");
            assertThat(policy).contains("allow {");
            assertThat(policy).contains("input.operationType == \"delete\"");
            assertThat(policy).contains("input.resourceId == \"resource-456\"");
            assertThat(policy).contains("input.context.user == \"admin\"");
            assertThat(policy).contains("input.context.ip == \"192.168.1.1\"");
            assertThat(policy).contains("}");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle null resource ID")
        void shouldHandleNullResourceId() {
            String policy = defaultBuilder.buildPolicy(request);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.operationType == \"read\"");
            assertThat(policy).doesNotContain("input.resourceId");
        }

        @Test
        @DisplayName("Should handle empty metadata")
        void shouldHandleEmptyMetadata() {
            RequestAuthUrlRequest requestWithEmptyMetadata = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("write")
                            .metadata(new HashMap<>())
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithEmptyMetadata);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.operationType == \"write\"");
            assertThat(policy).doesNotContain("input.context");
        }

        @Test
        @DisplayName("Should handle null metadata")
        void shouldHandleNullMetadata() {
            RequestAuthUrlRequest requestWithNullMetadata = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("delete")
                            .metadata(null)
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithNullMetadata);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.operationType == \"delete\"");
            assertThat(policy).doesNotContain("input.context");
        }

        @Test
        @DisplayName("Should handle special characters in operation type")
        void shouldHandleSpecialCharactersInOperationType() {
            RequestAuthUrlRequest requestWithSpecialChars = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("custom:operation")
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithSpecialChars);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.operationType == \"custom:operation\"");
        }

        @Test
        @DisplayName("Should handle special characters in resource ID")
        void shouldHandleSpecialCharactersInResourceId() {
            RequestAuthUrlRequest requestWithSpecialChars = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("read")
                            .resourceId("path/to/resource-123")
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithSpecialChars);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.resourceId == \"path/to/resource-123\"");
        }

        @Test
        @DisplayName("Should handle special characters in metadata values")
        void shouldHandleSpecialCharactersInMetadataValues() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("url", "https://example.com/path?param=value");
            
            RequestAuthUrlRequest requestWithSpecialChars = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("write")
                            .metadata(metadata)
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithSpecialChars);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("input.context.url == \"https://example.com/path?param=value\"");
        }
    }

    @Nested
    @DisplayName("Functional Interface Tests")
    class FunctionalInterfaceTests {

        @Test
        @DisplayName("Should support custom policy builder")
        void shouldSupportCustomPolicyBuilder() {
            PolicyBuilder customBuilder = req -> {
                return "package custom\nallow {\n  input.operation == \"" + req.getOperationType() + "\"\n}";
            };

            String policy = customBuilder.buildPolicy(request);

            assertThat(policy).isNotNull();
            assertThat(policy).contains("package custom");
            assertThat(policy).contains("input.operation == \"read\"");
        }

        @Test
        @DisplayName("Should support lambda expression")
        void shouldSupportLambdaExpression() {
            PolicyBuilder lambdaBuilder = req -> "custom-rego";

            String policy = lambdaBuilder.buildPolicy(request);

            assertThat(policy).isEqualTo("custom-rego");
        }
    }

    @Nested
    @DisplayName("Policy Format Tests")
    class PolicyFormatTests {

        @Test
        @DisplayName("Should generate valid Rego format")
        void shouldGenerateValidRegoFormat() {
            String policy = defaultBuilder.buildPolicy(request);

            // Verify Rego structure
            assertThat(policy).contains("package agent");
            assertThat(policy).contains("allow {");
            assertThat(policy).contains("}");
            assertThat(policy).contains("input.operationType");
        }

        @Test
        @DisplayName("Should add comment for metadata constraints")
        void shouldAddCommentForMetadataConstraints() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("key", "value");
            
            RequestAuthUrlRequest requestWithMetadata = RequestAuthUrlRequest.builder()
                    .userIdentityToken("test-token")
                    .userOriginalInput("test input")
                    .workloadContext(WorkloadRequestContext.builder()
                            .operationType("write")
                            .metadata(metadata)
                            .build())
                    .build();

            String policy = defaultBuilder.buildPolicy(requestWithMetadata);

            assertThat(policy).contains("# Additional context constraints");
        }
    }
}