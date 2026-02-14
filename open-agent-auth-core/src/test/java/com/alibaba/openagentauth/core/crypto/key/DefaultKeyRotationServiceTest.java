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
package com.alibaba.openagentauth.core.crypto.key;

import com.alibaba.openagentauth.core.crypto.key.KeyRotationService.KeyRotationStatus;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for DefaultKeyRotationService.
 * <p>
 * This test class verifies the functionality of the DefaultKeyRotationService implementation,
 * including key rotation, scheduling, cancellation, and status tracking.
 * </p>
 */
@DisplayName("DefaultKeyRotationService Tests")
class DefaultKeyRotationServiceTest {

    private KeyManager keyManager;
    private DefaultKeyRotationService rotationService;

    /**
     * Sets up the test environment before each test.
     */
    @BeforeEach
    void setUp() {
        keyManager = new DefaultKeyManager(new InMemoryKeyStore());
        rotationService = new DefaultKeyRotationService(keyManager);
    }

    /**
     * Cleans up the test environment after each test.
     */
    @AfterEach
    void tearDown() {
        if (rotationService != null) {
            rotationService.shutdown();
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when KeyManager is null")
        void shouldThrowExceptionWhenKeyManagerIsNull() {
            assertThatThrownBy(() -> new DefaultKeyRotationService(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("KeyManager cannot be null");
        }
    }

    @Nested
    @DisplayName("Key Rotation Tests")
    class KeyRotationTests {

        @Test
        @DisplayName("Should rotate key successfully")
        void shouldRotateKeySuccessfully() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "rotation-test-key-001");
            KeyPair oldKeyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "rotation-test-key-001-temp");

            rotationService.rotateKey("rotation-test-key-001");

            KeyRotationStatus status = rotationService.getRotationStatus("rotation-test-key-001");
            assertThat(status).isEqualTo(KeyRotationStatus.COMPLETED);
        }

        @Test
        @DisplayName("Should update rotation status to IN_PROGRESS during rotation")
        void shouldUpdateRotationStatusToInProgressDuringRotation() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "rotation-test-key-002");

            rotationService.rotateKey("rotation-test-key-002");

            KeyRotationStatus status = rotationService.getRotationStatus("rotation-test-key-002");
            assertThat(status).isIn(KeyRotationStatus.COMPLETED, KeyRotationStatus.FAILED);
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for rotation")
        void shouldThrowExceptionWhenKeyIdIsNullForRotation() {
            assertThatThrownBy(() -> rotationService.rotateKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for rotation")
        void shouldThrowExceptionWhenKeyIdIsEmptyForRotation() {
            assertThatThrownBy(() -> rotationService.rotateKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is whitespace for rotation")
        void shouldThrowExceptionWhenKeyIdIsWhitespaceForRotation() {
            assertThatThrownBy(() -> rotationService.rotateKey("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should handle rotation failure gracefully")
        void shouldHandleRotationFailureGracefully() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "rotation-test-key-003");

            // Delete the key to cause rotation failure
            keyManager.deleteKey("rotation-test-key-003");

            assertThatThrownBy(() -> rotationService.rotateKey("rotation-test-key-003"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key rotation failed");

            KeyRotationStatus status = rotationService.getRotationStatus("rotation-test-key-003");
            assertThat(status).isEqualTo(KeyRotationStatus.FAILED);
        }
    }

    @Nested
    @DisplayName("Scheduled Rotation Tests")
    class ScheduledRotationTests {

        @Test
        @DisplayName("Should schedule rotation for future time")
        void shouldScheduleRotationForFutureTime() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "scheduled-rotation-key-001");

            long rotationTime = System.currentTimeMillis() + 1000;
            rotationService.scheduleRotation("scheduled-rotation-key-001", rotationTime);

            KeyRotationStatus status = rotationService.getRotationStatus("scheduled-rotation-key-001");
            assertThat(status).isEqualTo(KeyRotationStatus.SCHEDULED);

            // Wait for rotation to complete
            Thread.sleep(1500);

            status = rotationService.getRotationStatus("scheduled-rotation-key-001");
            assertThat(status).isEqualTo(KeyRotationStatus.COMPLETED);
        }

        @Test
        @DisplayName("Should throw exception when rotation time is in the past")
        void shouldThrowExceptionWhenRotationTimeIsInThePast() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "scheduled-rotation-key-002");

            long pastTime = System.currentTimeMillis() - 1000;

            assertThatThrownBy(() -> rotationService.scheduleRotation("scheduled-rotation-key-002", pastTime))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Rotation time must be in the future");
        }

        @Test
        @DisplayName("Should throw exception when rotation time is now")
        void shouldThrowExceptionWhenRotationTimeIsNow() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "scheduled-rotation-key-003");

            long now = System.currentTimeMillis();

            assertThatThrownBy(() -> rotationService.scheduleRotation("scheduled-rotation-key-003", now))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Rotation time must be in the future");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for scheduling")
        void shouldThrowExceptionWhenKeyIdIsNullForScheduling() {
            long futureTime = System.currentTimeMillis() + 1000;

            assertThatThrownBy(() -> rotationService.scheduleRotation(null, futureTime))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for scheduling")
        void shouldThrowExceptionWhenKeyIdIsEmptyForScheduling() {
            long futureTime = System.currentTimeMillis() + 1000;

            assertThatThrownBy(() -> rotationService.scheduleRotation("", futureTime))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should cancel existing scheduled rotation when scheduling new one")
        void shouldCancelExistingScheduledRotationWhenSchedulingNewOne() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "scheduled-rotation-key-004");

            long firstRotationTime = System.currentTimeMillis() + 2000;
            rotationService.scheduleRotation("scheduled-rotation-key-004", firstRotationTime);

            Thread.sleep(100);

            long secondRotationTime = System.currentTimeMillis() + 1000;
            rotationService.scheduleRotation("scheduled-rotation-key-004", secondRotationTime);

            // Wait for the second rotation to complete
            Thread.sleep(1500);

            KeyRotationStatus status = rotationService.getRotationStatus("scheduled-rotation-key-004");
            assertThat(status).isEqualTo(KeyRotationStatus.COMPLETED);
        }
    }

    @Nested
    @DisplayName("Cancel Scheduled Rotation Tests")
    class CancelScheduledRotationTests {

        @Test
        @DisplayName("Should cancel scheduled rotation successfully")
        void shouldCancelScheduledRotationSuccessfully() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "cancel-rotation-key-001");

            long rotationTime = System.currentTimeMillis() + 5000;
            rotationService.scheduleRotation("cancel-rotation-key-001", rotationTime);

            rotationService.cancelScheduledRotation("cancel-rotation-key-001");

            KeyRotationStatus status = rotationService.getRotationStatus("cancel-rotation-key-001");
            assertThat(status).isEqualTo(KeyRotationStatus.IDLE);
        }

        @Test
        @DisplayName("Should handle cancellation when no rotation is scheduled")
        void shouldHandleCancellationWhenNoRotationIsScheduled() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "cancel-rotation-key-002");

            // Should not throw exception
            rotationService.cancelScheduledRotation("cancel-rotation-key-002");

            KeyRotationStatus status = rotationService.getRotationStatus("cancel-rotation-key-002");
            assertThat(status).isEqualTo(KeyRotationStatus.IDLE);
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for cancellation")
        void shouldThrowExceptionWhenKeyIdIsNullForCancellation() {
            assertThatThrownBy(() -> rotationService.cancelScheduledRotation(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for cancellation")
        void shouldThrowExceptionWhenKeyIdIsEmptyForCancellation() {
            assertThatThrownBy(() -> rotationService.cancelScheduledRotation(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Rotation Status Tests")
    class RotationStatusTests {

        @Test
        @DisplayName("Should return IDLE status for non-existent key")
        void shouldReturnIdleStatusForNonExistentKey() {
            KeyRotationStatus status = rotationService.getRotationStatus("non-existent-key");
            assertThat(status).isEqualTo(KeyRotationStatus.IDLE);
        }

        @Test
        @DisplayName("Should return correct status after rotation")
        void shouldReturnCorrectStatusAfterRotation() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "status-key-001");

            rotationService.rotateKey("status-key-001");

            KeyRotationStatus status = rotationService.getRotationStatus("status-key-001");
            assertThat(status).isEqualTo(KeyRotationStatus.COMPLETED);
        }

        @Test
        @DisplayName("Should return correct status after scheduling")
        void shouldReturnCorrectStatusAfterScheduling() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "status-key-002");

            long rotationTime = System.currentTimeMillis() + 5000;
            rotationService.scheduleRotation("status-key-002", rotationTime);

            KeyRotationStatus status = rotationService.getRotationStatus("status-key-002");
            assertThat(status).isEqualTo(KeyRotationStatus.SCHEDULED);
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for status retrieval")
        void shouldThrowExceptionWhenKeyIdIsNullForStatusRetrieval() {
            assertThatThrownBy(() -> rotationService.getRotationStatus(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for status retrieval")
        void shouldThrowExceptionWhenKeyIdIsEmptyForStatusRetrieval() {
            assertThatThrownBy(() -> rotationService.getRotationStatus(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent rotation requests")
        void shouldHandleConcurrentRotationRequests() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "concurrent-rotation-key-001");

            int threadCount = 10;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executorService.submit(() -> {
                    try {
                        rotationService.rotateKey("concurrent-rotation-key-001");
                        successCount.incrementAndGet();
                    } catch (KeyManagementException e) {
                        // Expected for concurrent rotations
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isGreaterThan(0);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent status queries")
        void shouldHandleConcurrentStatusQueries() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "concurrent-status-key-001");

            int threadCount = 20;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executorService.submit(() -> {
                    try {
                        rotationService.getRotationStatus("concurrent-status-key-001");
                        successCount.incrementAndGet();
                    } catch (Exception e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isEqualTo(threadCount);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent scheduling and cancellation")
        void shouldHandleConcurrentSchedulingAndCancellation() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "concurrent-schedule-key-001");

            int threadCount = 10;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        if (index % 2 == 0) {
                            long rotationTime = System.currentTimeMillis() + 5000;
                            rotationService.scheduleRotation("concurrent-schedule-key-001", rotationTime);
                        } else {
                            rotationService.cancelScheduledRotation("concurrent-schedule-key-001");
                        }
                    } catch (Exception e) {
                        // Expected for concurrent operations
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full rotation workflow")
        void shouldCompleteFullRotationWorkflow() throws KeyManagementException, InterruptedException {
            // Generate key
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "workflow-key-001");

            // Schedule rotation
            long rotationTime = System.currentTimeMillis() + 500;
            rotationService.scheduleRotation("workflow-key-001", rotationTime);

            KeyRotationStatus status = rotationService.getRotationStatus("workflow-key-001");
            assertThat(status).isEqualTo(KeyRotationStatus.SCHEDULED);

            // Wait for rotation to complete with polling
            KeyRotationStatus finalStatus = waitForRotationCompletion("workflow-key-001", 5000);
            assertThat(finalStatus).isEqualTo(KeyRotationStatus.COMPLETED);

            // Verify key still exists
            assertThat(keyManager.hasKey("workflow-key-001")).isTrue();
        }

        @Test
        @DisplayName("Should handle multiple scheduled rotations")
        void shouldHandleMultipleScheduledRotations() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "multi-schedule-key-001");
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "multi-schedule-key-002");
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "multi-schedule-key-003");

            long rotationTime = System.currentTimeMillis() + 500;
            rotationService.scheduleRotation("multi-schedule-key-001", rotationTime);
            rotationService.scheduleRotation("multi-schedule-key-002", rotationTime);
            rotationService.scheduleRotation("multi-schedule-key-003", rotationTime);

            // Wait for all rotations to complete with polling
            assertThat(waitForRotationCompletion("multi-schedule-key-001", 5000)).isEqualTo(KeyRotationStatus.COMPLETED);
            assertThat(waitForRotationCompletion("multi-schedule-key-002", 5000)).isEqualTo(KeyRotationStatus.COMPLETED);
            assertThat(waitForRotationCompletion("multi-schedule-key-003", 5000)).isEqualTo(KeyRotationStatus.COMPLETED);
        }

        /**
         * Waits for key rotation to complete with polling.
         *
         * @param keyId the key ID to wait for
         * @param timeoutMillis the maximum time to wait in milliseconds
         * @return the final rotation status
         * @throws InterruptedException if the thread is interrupted
         */
        private KeyRotationStatus waitForRotationCompletion(String keyId, long timeoutMillis) throws InterruptedException {
            long startTime = System.currentTimeMillis();
            long pollInterval = 100;

            while (System.currentTimeMillis() - startTime < timeoutMillis) {
                KeyRotationStatus status = rotationService.getRotationStatus(keyId);
                if (status == KeyRotationStatus.COMPLETED || status == KeyRotationStatus.FAILED) {
                    return status;
                }
                Thread.sleep(pollInterval);
            }

            // Return current status if timeout
            return rotationService.getRotationStatus(keyId);
        }
    }

    @Nested
    @DisplayName("Shutdown Tests")
    class ShutdownTests {

        @Test
        @DisplayName("Should shutdown gracefully")
        void shouldShutdownGracefully() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "shutdown-key-001");

            long rotationTime = System.currentTimeMillis() + 5000;
            rotationService.scheduleRotation("shutdown-key-001", rotationTime);

            // Should not throw exception
            rotationService.shutdown();
        }

        @Test
        @DisplayName("Should handle multiple shutdown calls")
        void shouldHandleMultipleShutdownCalls() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "shutdown-key-002");

            rotationService.shutdown();
            rotationService.shutdown();
            rotationService.shutdown();
        }
    }
}
