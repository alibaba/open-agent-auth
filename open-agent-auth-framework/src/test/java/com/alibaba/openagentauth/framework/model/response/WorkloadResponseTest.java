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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WorkloadResponse.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("WorkloadResponse.Builder Tests")
class WorkloadResponseTest {

    private static final String TEST_WORKLOAD_ID = "workload-123";
    private static final String TEST_USER_ID = "user-456";
    private static final String TEST_PUBLIC_KEY = "public-key-abc";
    private static final String TEST_STATUS = "ACTIVE";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        Instant createdAt = Instant.now();
        Instant expiresAt = Instant.now().plusSeconds(3600);

        WorkloadResponse response = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .publicKey(TEST_PUBLIC_KEY)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .status(TEST_STATUS)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(response.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(response.getPublicKey()).isEqualTo(TEST_PUBLIC_KEY);
        assertThat(response.getCreatedAt()).isEqualTo(createdAt);
        assertThat(response.getExpiresAt()).isEqualTo(expiresAt);
        assertThat(response.getStatus()).isEqualTo(TEST_STATUS);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        WorkloadResponse.Builder builder = WorkloadResponse.builder();

        // When
        WorkloadResponse response = builder
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .publicKey(TEST_PUBLIC_KEY)
                .status(TEST_STATUS)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(response.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(response.getPublicKey()).isEqualTo(TEST_PUBLIC_KEY);
        assertThat(response.getStatus()).isEqualTo(TEST_STATUS);
    }

    @Test
    @DisplayName("Should build instance with only required fields")
    void shouldBuildInstanceWithOnlyRequiredFieldsWhenOnlyRequiredFieldsAreSet() {
        // Given
        WorkloadResponse response = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(response.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(response.getPublicKey()).isNull();
        assertThat(response.getCreatedAt()).isNull();
        assertThat(response.getExpiresAt()).isNull();
        assertThat(response.getStatus()).isNull();
    }

    @Test
    @DisplayName("Should build instance with null values when setters receive null")
    void shouldBuildInstanceWithNullValuesWhenSettersReceiveNull() {
        // Given
        WorkloadResponse response = WorkloadResponse.builder()
                .workloadId(null)
                .userId(null)
                .publicKey(null)
                .createdAt(null)
                .expiresAt(null)
                .status(null)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getWorkloadId()).isNull();
        assertThat(response.getUserId()).isNull();
        assertThat(response.getPublicKey()).isNull();
        assertThat(response.getCreatedAt()).isNull();
        assertThat(response.getExpiresAt()).isNull();
        assertThat(response.getStatus()).isNull();
    }

    @Test
    @DisplayName("Should allow setting fields after build using setters")
    void shouldAllowSettingFieldsAfterBuildWhenSettersAreUsed() {
        // Given
        WorkloadResponse response = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .build();

        // When
        response.setUserId(TEST_USER_ID);
        response.setPublicKey(TEST_PUBLIC_KEY);
        response.setStatus(TEST_STATUS);

        // Then
        assertThat(response.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(response.getPublicKey()).isEqualTo(TEST_PUBLIC_KEY);
        assertThat(response.getStatus()).isEqualTo(TEST_STATUS);
    }

    @Test
    @DisplayName("Should handle Instant for createdAt and expiresAt fields")
    void shouldHandleInstantForCreatedAtAndExpiresAtFields() {
        // Given
        Instant createdAt = Instant.now();
        Instant expiresAt = Instant.now().plusSeconds(7200);

        WorkloadResponse response = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .createdAt(createdAt)
                .expiresAt(expiresAt)
                .build();

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getCreatedAt()).isEqualTo(createdAt);
        assertThat(response.getExpiresAt()).isEqualTo(expiresAt);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        WorkloadResponse.Builder builder1 = WorkloadResponse.builder();
        WorkloadResponse.Builder builder2 = WorkloadResponse.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        WorkloadResponse.Builder builder = WorkloadResponse.builder();

        // When
        WorkloadResponse response1 = builder
                .workloadId("workload-1")
                .userId("user-1")
                .status("ACTIVE")
                .build();

        WorkloadResponse response2 = builder
                .workloadId("workload-2")
                .userId("user-2")
                .status("INACTIVE")
                .build();

        // Then
        assertThat(response1).isNotNull();
        assertThat(response2).isNotNull();
        assertThat(response1.getWorkloadId()).isEqualTo("workload-1");
        assertThat(response2.getWorkloadId()).isEqualTo("workload-2");
        assertThat(response1.getStatus()).isEqualTo("ACTIVE");
        assertThat(response2.getStatus()).isEqualTo("INACTIVE");
    }

    @Test
    @DisplayName("Should handle different status values")
    void shouldHandleDifferentStatusValuesWhenDifferentStatusesAreSet() {
        // Given
        WorkloadResponse activeResponse = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .status("ACTIVE")
                .build();

        WorkloadResponse inactiveResponse = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .status("INACTIVE")
                .build();

        WorkloadResponse expiredResponse = WorkloadResponse.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .status("EXPIRED")
                .build();

        // Then
        assertThat(activeResponse.getStatus()).isEqualTo("ACTIVE");
        assertThat(inactiveResponse.getStatus()).isEqualTo("INACTIVE");
        assertThat(expiredResponse.getStatus()).isEqualTo("EXPIRED");
    }
}
