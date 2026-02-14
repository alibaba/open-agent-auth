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
 * Unit tests for {@link AclPolicyBuilder}.
 * <p>
 * Tests the ACL policy builder functionality including entries,
 * principal-resource-permission mappings, and effect handling.
 * </p>
 */
class AclPolicyBuilderTest {

    @Test
    void testBuildPolicyWithBasicRequest() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
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
        assertTrue(policy.contains("\"entries\""));
        assertTrue(policy.contains("\"principal\": \"purchase\""));
        assertTrue(policy.contains("\"resource\": \"resource-123\""));
        assertTrue(policy.contains("\"permissions\": [\"purchase\"]"));
        assertTrue(policy.contains("\"effect\": \"ALLOW\""));
    }

    @Test
    void testBuildPolicyWithPrincipalInMetadata() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("principal", "user-123");
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
        assertTrue(policy.contains("\"principal\": \"user-123\""));
    }

    @Test
    void testBuildPolicyWithoutResourceId() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
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
        assertTrue(policy.contains("\"resource\": \"*\""));
    }

    @Test
    void testBuildPolicyWithAdditionalEntries() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
        Map<String, Object> aclEntry = new HashMap<>();
        aclEntry.put("principal", "user-456");
        aclEntry.put("resource", "resource-456");
        aclEntry.put("permissions", Arrays.asList("read", "write"));
        aclEntry.put("effect", "ALLOW");

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("acl_entries", Arrays.asList(aclEntry));
        
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
        assertTrue(policy.contains("\"principal\": \"purchase\""));
        assertTrue(policy.contains("\"principal\": \"user-456\""));
        assertTrue(policy.contains("\"resource\": \"resource-456\""));
        assertTrue(policy.contains("\"read\""));
        assertTrue(policy.contains("\"write\""));
    }

    @Test
    void testBuildPolicyWithCustomVersion() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder("2.0");
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
        AclPolicyBuilder builder = AclPolicyBuilder.create();

        // Then
        assertNotNull(builder);
    }

    @Test
    void testCreateWithCustomVersion() {
        // When
        AclPolicyBuilder builder = AclPolicyBuilder.create("2.0");

        // Then
        assertNotNull(builder);
    }

    @Test
    void testBuildPolicyStructure() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
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
        assertTrue(policy.contains("\"entries\""));
        assertTrue(policy.contains("\"principal\""));
        assertTrue(policy.contains("\"resource\""));
        assertTrue(policy.contains("\"permissions\""));
        assertTrue(policy.contains("\"effect\""));
    }

    @Test
    void testBuildPolicyWithMultiplePermissions() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
        Map<String, Object> aclEntry = new HashMap<>();
        aclEntry.put("principal", "user-789");
        aclEntry.put("resource", "resource-789");
        aclEntry.put("permissions", Arrays.asList("read", "write", "delete"));
        aclEntry.put("effect", "DENY");

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("acl_entries", Arrays.asList(aclEntry));
        
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
        assertTrue(policy.contains("\"read\", \"write\", \"delete\""));
        assertTrue(policy.contains("\"effect\": \"DENY\""));
    }

    @Test
    void testBuildPolicyWithDenyEffect() {
        // Given
        PolicyBuilder builder = new AclPolicyBuilder();
        Map<String, Object> aclEntry = new HashMap<>();
        aclEntry.put("principal", "user-999");
        aclEntry.put("resource", "resource-999");
        aclEntry.put("permissions", Arrays.asList("delete"));
        aclEntry.put("effect", "DENY");

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("acl_entries", Arrays.asList(aclEntry));
        
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
        assertTrue(policy.contains("\"effect\": \"DENY\""));
    }
}
