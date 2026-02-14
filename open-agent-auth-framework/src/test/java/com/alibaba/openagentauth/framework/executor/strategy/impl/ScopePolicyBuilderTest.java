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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ScopePolicyBuilder}.
 * <p>
 * Tests the OAuth Scope policy builder functionality including scope definitions,
 * resources, and RFC 6749/8707 compliance.
 * </p>
 */
class ScopePolicyBuilderTest {

    @Test
    void testBuildPolicyWithBasicRequest() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder();
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
        assertTrue(policy.contains("\"scopes\""));
        assertTrue(policy.contains("\"name\": \"purchase\""));
        assertTrue(policy.contains("\"description\": \"Scope for operation: purchase\""));
        assertTrue(policy.contains("\"resource-123\""));
    }

    @Test
    void testBuildPolicyWithMultipleResources() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("resources", Arrays.asList("resource-123", "resource-456", "resource-789"));
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
        assertTrue(policy.contains("\"resource-123\""));
        assertTrue(policy.contains("\"resource-456\""));
        assertTrue(policy.contains("\"resource-789\""));
    }

    @Test
    void testBuildPolicyWithoutResourceId() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder();
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
        assertTrue(policy.contains("\"*\""));
    }

    @Test
    void testBuildPolicyWithCustomVersion() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder("2.0");
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
        ScopePolicyBuilder builder = ScopePolicyBuilder.create();

        // Then
        assertNotNull(builder);
    }

    @Test
    void testCreateWithCustomVersion() {
        // When
        ScopePolicyBuilder builder = ScopePolicyBuilder.create("2.0");

        // Then
        assertNotNull(builder);
    }

    @Test
    void testBuildPolicyStructure() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder();
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
        assertTrue(policy.contains("\"scopes\""));
        assertTrue(policy.contains("\"name\""));
        assertTrue(policy.contains("\"description\""));
        assertTrue(policy.contains("\"resources\""));
    }

    @Test
    void testBuildPolicyWithResourcesInMetadata() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("resources", Arrays.asList("resource-456", "resource-789"));
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
        assertTrue(policy.contains("\"resource-123\""));
        assertTrue(policy.contains("\"resource-456\""));
        assertTrue(policy.contains("\"resource-789\""));
    }

    @Test
    void testBuildPolicyDescription() {
        // Given
        PolicyBuilder builder = new ScopePolicyBuilder();
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("read")
                .resourceId("resource-123")
                .build();
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("test-token")
                .userOriginalInput("read some data")
                .workloadContext(workloadContext)
                .build();

        // When
        String policy = builder.buildPolicy(request);

        // Then
        assertNotNull(policy);
        assertTrue(policy.contains("\"description\": \"Scope for operation: read\""));
    }
}
