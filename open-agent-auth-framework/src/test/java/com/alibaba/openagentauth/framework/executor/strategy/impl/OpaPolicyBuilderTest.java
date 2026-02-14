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
 * Unit tests for {@link OpaPolicyBuilder}.
 * <p>
 * Tests the OPA policy builder functionality including Rego policy generation,
 * custom package/rule names, and various request scenarios.
 * </p>
 */
class OpaPolicyBuilderTest {

    @Test
    void testBuildPolicyWithBasicRequest() {
        // Given
        PolicyBuilder builder = new OpaPolicyBuilder();
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
        assertTrue(policy.contains("package agent"));
        assertTrue(policy.contains("allow {"));
        assertTrue(policy.contains("input.operationType == \"purchase\""));
        assertTrue(policy.contains("input.resourceId == \"resource-123\""));
    }

    @Test
    void testBuildPolicyWithMetadata() {
        // Given
        PolicyBuilder builder = new OpaPolicyBuilder();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("channel", "mobile");
        metadata.put("location", "US");
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("purchase")
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
        assertTrue(policy.contains("input.context.channel == \"mobile\""));
        assertTrue(policy.contains("input.context.location == \"US\""));
    }

    @Test
    void testBuildPolicyWithCustomPackageAndRule() {
        // Given
        PolicyBuilder builder = new OpaPolicyBuilder("authz", "authorize");
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
        assertTrue(policy.contains("package authz"));
        assertTrue(policy.contains("authorize {"));
        assertFalse(policy.contains("allow {"));
    }

    @Test
    void testBuildPolicyWithoutResourceId() {
        // Given
        PolicyBuilder builder = new OpaPolicyBuilder();
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
        assertTrue(policy.contains("input.operationType == \"purchase\""));
        assertFalse(policy.contains("input.resourceId"));
    }

    @Test
    void testBuildPolicyWithoutMetadata() {
        // Given
        PolicyBuilder builder = new OpaPolicyBuilder();
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
        assertFalse(policy.contains("input.context"));
    }

    @Test
    void testCreateWithDefaultSettings() {
        // When
        OpaPolicyBuilder builder = OpaPolicyBuilder.create();

        // Then
        assertNotNull(builder);
    }

    @Test
    void testCreateWithCustomPackageName() {
        // When
        OpaPolicyBuilder builder = OpaPolicyBuilder.create("custom-package");

        // Then
        assertNotNull(builder);
    }

    @Test
    void testCreateWithCustomPackageAndRule() {
        // When
        OpaPolicyBuilder builder = OpaPolicyBuilder.create("custom-package", "custom-rule");

        // Then
        assertNotNull(builder);
    }
}
