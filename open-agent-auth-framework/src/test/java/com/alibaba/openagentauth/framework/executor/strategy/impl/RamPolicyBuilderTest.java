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
package com.alibaba.openagentauth.framework.executor.strategy.impl;

import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;
import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.model.workload.WorkloadRequestContext;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RamPolicyBuilder}.
 * <p>
 * Tests the RAM policy builder functionality including JSON policy generation,
 * statements, actions, resources, and conditions.
 * </p>
 */
class RamPolicyBuilderTest {

    @Test
    void testBuildPolicyWithBasicRequest() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder();
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .resourceId("resource-123")
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then
        assertNotNull(policy);
        assertTrue(policy.contains("\"version\": \"1.0\""));
        assertTrue(policy.contains("\"statement\""));
        assertTrue(policy.contains("\"effect\": \"ALLOW\""));
        assertTrue(policy.contains("\"action\": [\"purchase\"]"));
        assertTrue(policy.contains("\"resource\": [\"resource-123\"]"));
    }

    @Test
    void testBuildPolicyWithMetadata() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("channel", "mobile");
        metadata.put("location", "US");
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .resourceId("resource-123")
                .metadata(metadata)
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then
        assertNotNull(policy);
        assertTrue(policy.contains("\"condition\""));
        assertTrue(policy.contains("\"operator\": \"StringEquals\""));
        assertTrue(policy.contains("\"key\": \"context\""));
        assertTrue(policy.contains("\"channel\": \"mobile\""));
        assertTrue(policy.contains("\"location\": \"US\""));
    }

    @Test
    void testBuildPolicyWithoutResourceId() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder();
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then
        assertNotNull(policy);
        assertTrue(policy.contains("\"resource\": [\"*\"]"));
    }

    @Test
    void testBuildPolicyWithoutMetadata() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder();
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .resourceId("resource-123")
                .metadata(new HashMap<>())
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then
        assertNotNull(policy);
        assertFalse(policy.contains("\"condition\""));
    }

    @Test
    void testBuildPolicyWithCustomVersion() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder("2.0");
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .resourceId("resource-123")
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then
        assertNotNull(policy);
        assertTrue(policy.contains("\"version\": \"2.0\""));
    }

    @Test
    void testCreateWithDefaultSettings() {
        // When
        RamPolicyBuilder builder = RamPolicyBuilder.create();

        // Then
        assertNotNull(builder);
    }

    @Test
    void testCreateWithCustomVersion() {
        // When
        RamPolicyBuilder builder = RamPolicyBuilder.create("2.0");

        // Then
        assertNotNull(builder);
    }

    @Test
    void testBuildPolicyStructure() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder();
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .resourceId("resource-123")
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then - verify JSON structure
        assertTrue(policy.startsWith("{"));
        assertTrue(policy.endsWith("}"));
        assertTrue(policy.contains("\"version\""));
        assertTrue(policy.contains("\"statement\""));
        assertTrue(policy.contains("\"effect\""));
        assertTrue(policy.contains("\"action\""));
        assertTrue(policy.contains("\"resource\""));
    }

    @Test
    void testBuildPolicyWithEmptyMetadata() {
        // Given
        PolicyBuilder builder = new RamPolicyBuilder();
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
                .resourceId("resource-123")
                .metadata(new HashMap<>())
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("buy some books")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then - should not contain condition
        assertNotNull(policy);
        assertFalse(policy.contains("\"condition\""));
    }
}
