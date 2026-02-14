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
package com.alibaba.openagentauth.core.protocol.wimse.workload.store;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryWorkloadRegistry}.
 * Tests verify the in-memory workload registry implementation following WIMSE protocol.
 */
@DisplayName("InMemoryWorkloadRegistry Tests - WIMSE Workload Registry")
class InMemoryWorkloadRegistryTest {

    private InMemoryWorkloadRegistry registry;
    private WorkloadInfo testWorkload;

    @BeforeEach
    void setUp() {
        registry = new InMemoryWorkloadRegistry();
        
        OperationRequestContext context = OperationRequestContext.builder()
                .channel("web")
                .deviceFingerprint("device-001")
                .language("en-US")
                .user(OperationRequestContext.UserContext.builder().id("user-123").build())
                .agent(OperationRequestContext.AgentContext.builder()
                        .instance("agent-001")
                        .platform("platform-001")
                        .client("client-001")
                        .build())
                .build();
        
        testWorkload = new WorkloadInfo(
                "workload-001",
                "user-123",
                "example.com",
                "https://issuer.example.com",
                "public-key-jwk",
                "private-key-jwk",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                "active",
                context,
                null // metadata
        );
    }

    @Nested
    @DisplayName("save() Tests")
    class SaveTests {

        @Test
        @DisplayName("Should save workload successfully")
        void shouldSaveWorkloadSuccessfully() {
            // When
            registry.save(testWorkload);

            // Then
            Optional<WorkloadInfo> found = registry.findById("workload-001");
            assertThat(found).isPresent();
            assertThat(found.get().getWorkloadId()).isEqualTo("workload-001");
        }

        @Test
        @DisplayName("Should throw exception when workload is null")
        void shouldThrowExceptionWhenWorkloadIsNull() {
            // When & Then
            assertThatThrownBy(() -> registry.save(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WorkloadInfo cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Given
            WorkloadInfo invalidWorkload = new WorkloadInfo(
                    null,
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );

            // When & Then
            assertThatThrownBy(() -> registry.save(invalidWorkload))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // Given
            WorkloadInfo invalidWorkload = new WorkloadInfo(
                    "   ",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );

            // When & Then
            assertThatThrownBy(() -> registry.save(invalidWorkload))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should replace existing workload with same ID")
        void shouldReplaceExistingWorkloadWithSameId() {
            // Given
            registry.save(testWorkload);
            
            WorkloadInfo updatedWorkload = new WorkloadInfo(
                    "workload-001",
                    "user-456",
                    "example.com",
                    "https://issuer.example.com",
                    "new-public-key",
                    "new-private-key",
                    Instant.now(),
                    Instant.now().plusSeconds(7200),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );

            // When
            registry.save(updatedWorkload);

            // Then
            Optional<WorkloadInfo> found = registry.findById("workload-001");
            assertThat(found).isPresent();
            assertThat(found.get().getUserId()).isEqualTo("user-456");
            assertThat(found.get().getPublicKey()).isEqualTo("new-public-key");
        }
    }

    @Nested
    @DisplayName("findById() Tests")
    class FindByIdTests {

        @Test
        @DisplayName("Should find workload by ID")
        void shouldFindWorkloadById() {
            // Given
            registry.save(testWorkload);

            // When
            Optional<WorkloadInfo> found = registry.findById("workload-001");

            // Then
            assertThat(found).isPresent();
            assertThat(found.get().getWorkloadId()).isEqualTo("workload-001");
        }

        @Test
        @DisplayName("Should return empty when workload not found")
        void shouldReturnEmptyWhenWorkloadNotFound() {
            // When
            Optional<WorkloadInfo> found = registry.findById("non-existent");

            // Then
            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // When & Then
            assertThatThrownBy(() -> registry.findById(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> registry.findById("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should return empty for expired workload")
        void shouldReturnEmptyForExpiredWorkload() {
            // Given
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    "expired-workload",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(expiredWorkload);

            // When
            Optional<WorkloadInfo> found = registry.findById("expired-workload");

            // Then
            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("Should return workload that is not expired")
        void shouldReturnWorkloadThatIsNotExpired() {
            // Given
            WorkloadInfo activeWorkload = new WorkloadInfo(
                    "active-workload",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(activeWorkload);

            // When
            Optional<WorkloadInfo> found = registry.findById("active-workload");

            // Then
            assertThat(found).isPresent();
        }
    }

    @Nested
    @DisplayName("delete() Tests")
    class DeleteTests {

        @Test
        @DisplayName("Should delete workload successfully")
        void shouldDeleteWorkloadSuccessfully() {
            // Given
            registry.save(testWorkload);

            // When
            registry.delete("workload-001");

            // Then
            Optional<WorkloadInfo> found = registry.findById("workload-001");
            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("Should complete silently when workload does not exist")
        void shouldCompleteSilentlyWhenWorkloadDoesNotExist() {
            // When & Then - should not throw exception
            registry.delete("non-existent");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // When & Then
            assertThatThrownBy(() -> registry.delete(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> registry.delete("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("exists() Tests")
    class ExistsTests {

        @Test
        @DisplayName("Should return true when workload exists")
        void shouldReturnTrueWhenWorkloadExists() {
            // Given
            registry.save(testWorkload);

            // When
            boolean exists = registry.exists("workload-001");

            // Then
            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("Should return false when workload does not exist")
        void shouldReturnFalseWhenWorkloadDoesNotExist() {
            // When
            boolean exists = registry.exists("non-existent");

            // Then
            assertThat(exists).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when workload ID is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // When & Then
            assertThatThrownBy(() -> registry.exists(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when workload ID is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> registry.exists("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should return false for expired workload")
        void shouldReturnFalseForExpiredWorkload() {
            // Given
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    "expired-workload",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(expiredWorkload);

            // When
            boolean exists = registry.exists("expired-workload");

            // Then
            assertThat(exists).isFalse();
        }
    }

    @Nested
    @DisplayName("cleanupExpiredWorkloads() Tests")
    class CleanupExpiredWorkloadsTests {

        @Test
        @DisplayName("Should cleanup expired workloads")
        void shouldCleanupExpiredWorkloads() {
            // Given
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    "expired-workload",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            WorkloadInfo activeWorkload = new WorkloadInfo(
                    "active-workload",
                    "user-456",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(expiredWorkload);
            registry.save(activeWorkload);

            // When
            int cleanedCount = registry.cleanupExpiredWorkloads();

            // Then
            assertThat(cleanedCount).isEqualTo(1);
            assertThat(registry.exists("expired-workload")).isFalse();
            assertThat(registry.exists("active-workload")).isTrue();
        }

        @Test
        @DisplayName("Should return zero when no expired workloads")
        void shouldReturnZeroWhenNoExpiredWorkloads() {
            // Given
            registry.save(testWorkload);

            // When
            int cleanedCount = registry.cleanupExpiredWorkloads();

            // Then
            assertThat(cleanedCount).isEqualTo(0);
            assertThat(registry.exists("workload-001")).isTrue();
        }

        @Test
        @DisplayName("Should cleanup all expired workloads")
        void shouldCleanupAllExpiredWorkloads() {
            // Given
            WorkloadInfo expiredWorkload1 = new WorkloadInfo(
                    "expired-1",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            WorkloadInfo expiredWorkload2 = new WorkloadInfo(
                    "expired-2",
                    "user-456",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            WorkloadInfo activeWorkload = new WorkloadInfo(
                    "active-workload",
                    "user-789",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(expiredWorkload1);
            registry.save(expiredWorkload2);
            registry.save(activeWorkload);

            // When
            int cleanedCount = registry.cleanupExpiredWorkloads();

            // Then
            assertThat(cleanedCount).isEqualTo(2);
            assertThat(registry.exists("expired-1")).isFalse();
            assertThat(registry.exists("expired-2")).isFalse();
            assertThat(registry.exists("active-workload")).isTrue();
        }
    }

    @Nested
    @DisplayName("getActiveWorkloadCount() Tests")
    class GetActiveWorkloadCountTests {

        @Test
        @DisplayName("Should return count of active workloads")
        void shouldReturnCountOfActiveWorkloads() {
            // Given
            WorkloadInfo activeWorkload1 = new WorkloadInfo(
                    "active-1",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            WorkloadInfo activeWorkload2 = new WorkloadInfo(
                    "active-2",
                    "user-456",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now(),
                    Instant.now().plusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            WorkloadInfo expiredWorkload = new WorkloadInfo(
                    "expired-workload",
                    "user-789",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(activeWorkload1);
            registry.save(activeWorkload2);
            registry.save(expiredWorkload);

            // When
            int count = registry.getActiveWorkloadCount();

            // Then
            assertThat(count).isEqualTo(2);
        }

        @Test
        @DisplayName("Should return zero when no workloads")
        void shouldReturnZeroWhenNoWorkloads() {
            // When
            int count = registry.getActiveWorkloadCount();

            // Then
            assertThat(count).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return zero when all workloads are expired")
        void shouldReturnZeroWhenAllWorkloadsAreExpired() {
            // Given
            WorkloadInfo expiredWorkload1 = new WorkloadInfo(
                    "expired-1",
                    "user-123",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            WorkloadInfo expiredWorkload2 = new WorkloadInfo(
                    "expired-2",
                    "user-456",
                    "example.com",
                    "https://issuer.example.com",
                    "public-key-jwk",
                    "private-key-jwk",
                    Instant.now().minusSeconds(7200),
                    Instant.now().minusSeconds(3600),
                    "active",
                    OperationRequestContext.builder().build(),
                    null // metadata
            );
            registry.save(expiredWorkload1);
            registry.save(expiredWorkload2);

            // When
            int count = registry.getActiveWorkloadCount();

            // Then
            assertThat(count).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Concurrency Tests")
    class ConcurrencyTests {

        @Test
        @DisplayName("Should handle concurrent save operations")
        void shouldHandleConcurrentSaveOperations() throws InterruptedException {
            // Given
            int threadCount = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            // When
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executor.submit(() -> {
                    WorkloadInfo workload = new WorkloadInfo(
                            "workload-" + index,
                            "user-" + index,
                            "example.com",
                            "https://issuer.example.com",
                            "public-key-jwk",
                            "private-key-jwk",
                            Instant.now(),
                            Instant.now().plusSeconds(3600),
                            "active",
                            OperationRequestContext.builder().build(),
                            null // metadata
                    );
                    registry.save(workload);
                    latch.countDown();
                });
            }

            latch.await(5, TimeUnit.SECONDS);
            executor.shutdown();

            // Then
            int count = registry.getActiveWorkloadCount();
            assertThat(count).isEqualTo(threadCount);
        }

        @Test
        @DisplayName("Should handle concurrent read operations")
        void shouldHandleConcurrentReadOperations() throws InterruptedException {
            // Given
            registry.save(testWorkload);
            int threadCount = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            // When
            for (int i = 0; i < threadCount; i++) {
                executor.submit(() -> {
                    Optional<WorkloadInfo> found = registry.findById("workload-001");
                    assertThat(found).isPresent();
                    latch.countDown();
                });
            }

            latch.await(5, TimeUnit.SECONDS);
            executor.shutdown();

            // Then - all reads should succeed
            assertThat(registry.exists("workload-001")).isTrue();
        }

        @Test
        @DisplayName("Should handle concurrent save and delete operations")
        void shouldHandleConcurrentSaveAndDeleteOperations() throws InterruptedException {
            // Given
            int threadCount = 10;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount * 2);

            // When
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                // Save operations
                executor.submit(() -> {
                    WorkloadInfo workload = new WorkloadInfo(
                            "workload-" + index,
                            "user-" + index,
                            "example.com",
                            "https://issuer.example.com",
                            "public-key-jwk",
                            "private-key-jwk",
                            Instant.now(),
                            Instant.now().plusSeconds(3600),
                            "active",
                            OperationRequestContext.builder().build(),
                            null // metadata
                    );
                    registry.save(workload);
                    latch.countDown();
                });
                // Delete operations
                executor.submit(() -> {
                    registry.delete("workload-" + index);
                    latch.countDown();
                });
            }

            latch.await(5, TimeUnit.SECONDS);
            executor.shutdown();

            // Then - should not throw exceptions
            // The final state depends on the order of operations
        }
    }
}
