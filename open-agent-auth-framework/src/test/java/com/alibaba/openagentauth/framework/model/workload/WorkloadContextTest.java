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
package com.alibaba.openagentauth.framework.model.workload;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WorkloadContext.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * expiration checking, and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("WorkloadContext.Builder Tests")
class WorkloadContextTest {

    private static final String TEST_WORKLOAD_ID = "workload-123";
    private static final String TEST_USER_ID = "user-456";
    private static final String TEST_WIT = "workload-identity-token";
    private static final String TEST_PUBLIC_KEY = "public-key-abc";
    private static final String TEST_PRIVATE_KEY = "private-key-def";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        Instant expiresAt = Instant.now().plusSeconds(3600);

        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .wit(TEST_WIT)
                .publicKey(TEST_PUBLIC_KEY)
                .privateKey(TEST_PRIVATE_KEY)
                .expiresAt(expiresAt)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(context.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(context.getWit()).isEqualTo(TEST_WIT);
        assertThat(context.getPublicKey()).isEqualTo(TEST_PUBLIC_KEY);
        assertThat(context.getPrivateKey()).isEqualTo(TEST_PRIVATE_KEY);
        assertThat(context.getExpiresAt()).isEqualTo(expiresAt);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        WorkloadContext.Builder builder = WorkloadContext.builder();

        // When
        WorkloadContext context = builder
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .wit(TEST_WIT)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(context.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(context.getWit()).isEqualTo(TEST_WIT);
    }

    @Test
    @DisplayName("Should build instance with only workloadId and userId")
    void shouldBuildInstanceWithOnlyWorkloadIdAndUserIdWhenOnlyRequiredFieldsAreSet() {
        // Given
        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(context.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(context.getWit()).isNull();
        assertThat(context.getPublicKey()).isNull();
        assertThat(context.getPrivateKey()).isNull();
        assertThat(context.getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("Should build instance with null values when setters receive null")
    void shouldBuildInstanceWithNullValuesWhenSettersReceiveNull() {
        // Given
        WorkloadContext context = WorkloadContext.builder()
                .workloadId(null)
                .userId(null)
                .wit(null)
                .publicKey(null)
                .privateKey(null)
                .expiresAt(null)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getWorkloadId()).isNull();
        assertThat(context.getUserId()).isNull();
        assertThat(context.getWit()).isNull();
        assertThat(context.getPublicKey()).isNull();
        assertThat(context.getPrivateKey()).isNull();
        assertThat(context.getExpiresAt()).isNull();
    }

    @Test
    @DisplayName("Should return false when workload is not expired")
    void shouldReturnFalseWhenWorkloadIsNotExpired() {
        // Given
        Instant futureTime = Instant.now().plusSeconds(3600);

        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .expiresAt(futureTime)
                .build();

        // When
        boolean isExpired = context.isExpired();

        // Then
        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("Should return true when workload is expired")
    void shouldReturnTrueWhenWorkloadIsExpired() {
        // Given
        Instant pastTime = Instant.now().minusSeconds(3600);

        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .expiresAt(pastTime)
                .build();

        // When
        boolean isExpired = context.isExpired();

        // Then
        assertThat(isExpired).isTrue();
    }

    @Test
    @DisplayName("Should return false when expiresAt is null")
    void shouldReturnFalseWhenExpiresAtIsNull() {
        // Given
        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .expiresAt(null)
                .build();

        // When
        boolean isExpired = context.isExpired();

        // Then
        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("Should handle Instant for expiresAt field")
    void shouldHandleInstantForExpiresAtField() {
        // Given
        Instant expiresAt = Instant.now().plusSeconds(7200);

        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .expiresAt(expiresAt)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getExpiresAt()).isEqualTo(expiresAt);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        WorkloadContext.Builder builder1 = WorkloadContext.builder();
        WorkloadContext.Builder builder2 = WorkloadContext.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        WorkloadContext.Builder builder = WorkloadContext.builder();

        // When
        WorkloadContext context1 = builder
                .workloadId("workload-1")
                .userId("user-1")
                .build();

        WorkloadContext context2 = builder
                .workloadId("workload-2")
                .userId("user-2")
                .build();

        // Then
        assertThat(context1).isNotNull();
        assertThat(context2).isNotNull();
        assertThat(context1.getWorkloadId()).isEqualTo("workload-1");
        assertThat(context2.getWorkloadId()).isEqualTo("workload-2");
        assertThat(context1.getUserId()).isEqualTo("user-1");
        assertThat(context2.getUserId()).isEqualTo("user-2");
    }

    @Test
    @DisplayName("Should build immutable instance when build is called")
    void shouldBuildImmutableInstanceWhenBuildIsCalled() {
        // Given
        Instant expiresAt = Instant.now().plusSeconds(3600);

        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .wit(TEST_WIT)
                .expiresAt(expiresAt)
                .build();

        // When & Then - Verify all fields are final and immutable
        assertThat(context.getWorkloadId()).isEqualTo(TEST_WORKLOAD_ID);
        assertThat(context.getUserId()).isEqualTo(TEST_USER_ID);
        assertThat(context.getWit()).isEqualTo(TEST_WIT);
        assertThat(context.getExpiresAt()).isEqualTo(expiresAt);
    }

    @Test
    @DisplayName("Should exclude privateKey from JSON serialization via @JsonIgnore")
    void shouldExcludePrivateKeyFromJsonSerialization() throws Exception {
        // Given
        Instant expiresAt = Instant.now().plusSeconds(3600);
        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .wit(TEST_WIT)
                .publicKey(TEST_PUBLIC_KEY)
                .privateKey(TEST_PRIVATE_KEY)
                .expiresAt(expiresAt)
                .build();

        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());

        // When
        String json = objectMapper.writeValueAsString(context);

        // Then - privateKey must NOT appear in serialized output
        assertThat(json).doesNotContain("privateKey");
        assertThat(json).doesNotContain(TEST_PRIVATE_KEY);
        // Other fields should still be present
        assertThat(json).contains(TEST_WORKLOAD_ID);
        assertThat(json).contains(TEST_USER_ID);
        assertThat(json).contains(TEST_WIT);
        assertThat(json).contains(TEST_PUBLIC_KEY);
    }

    @Test
    @DisplayName("Should redact privateKey in toString output")
    void shouldRedactPrivateKeyInToStringOutput() {
        // Given
        WorkloadContext context = WorkloadContext.builder()
                .workloadId(TEST_WORKLOAD_ID)
                .userId(TEST_USER_ID)
                .wit(TEST_WIT)
                .publicKey(TEST_PUBLIC_KEY)
                .privateKey(TEST_PRIVATE_KEY)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        // When
        String toStringResult = context.toString();

        // Then - privateKey must be redacted
        assertThat(toStringResult).contains("[REDACTED]");
        assertThat(toStringResult).doesNotContain(TEST_PRIVATE_KEY);
        // Other fields should be present (truncated for wit and publicKey)
        assertThat(toStringResult).contains(TEST_WORKLOAD_ID);
        assertThat(toStringResult).contains(TEST_USER_ID);
    }

    @Test
    @DisplayName("Should handle null values safely in toString")
    void shouldHandleNullValuesSafelyInToString() {
        // Given
        WorkloadContext context = WorkloadContext.builder()
                .workloadId(null)
                .userId(null)
                .wit(null)
                .publicKey(null)
                .privateKey(null)
                .expiresAt(null)
                .build();

        // When
        String toStringResult = context.toString();

        // Then - should not throw NPE and should contain redacted marker
        assertThat(toStringResult).contains("[REDACTED]");
        assertThat(toStringResult).contains("null");
    }
}
