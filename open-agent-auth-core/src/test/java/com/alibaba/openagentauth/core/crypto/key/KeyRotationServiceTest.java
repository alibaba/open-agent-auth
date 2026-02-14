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

import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for KeyRotationService.
 */
class KeyRotationServiceTest {

    private KeyManager mockKeyManager;
    private KeyStore mockKeyStore;
    private DefaultKeyRotationService rotationService;

    @BeforeEach
    void setUp() {
        mockKeyManager = mock(KeyManager.class);
        mockKeyStore = mock(KeyStore.class);
        rotationService = new DefaultKeyRotationService(mockKeyManager);
    }

    @AfterEach
    void tearDown() {
        if (rotationService != null) {
            rotationService.shutdown();
        }
    }

    @Test
    @DisplayName("Should rotate key successfully")
    void testRotateKey_WhenKeyExists_ShouldSucceed() throws KeyManagementException {
        // Arrange
        String keyId = "test-key";
        doNothing().when(mockKeyManager).rotateKey(keyId);

        // Act
        rotationService.rotateKey(keyId);

        // Assert
        verify(mockKeyManager, times(1)).rotateKey(keyId);
        assertEquals(KeyRotationService.KeyRotationStatus.COMPLETED, 
                rotationService.getRotationStatus(keyId));
    }

    @Test
    @DisplayName("Should throw exception when rotating non-existent key")
    void testRotateKey_WhenKeyNotFound_ShouldThrowException() throws KeyManagementException {
        // Arrange
        String keyId = "non-existent-key";
        doThrow(new KeyManagementException("Key not found"))
                .when(mockKeyManager).rotateKey(keyId);

        // Act & Assert
        KeyManagementException exception = assertThrows(
            KeyManagementException.class,
            () -> rotationService.rotateKey(keyId)
        );
        assertTrue(exception.getMessage().contains("Key rotation failed"));
        assertEquals(KeyRotationService.KeyRotationStatus.FAILED, 
                rotationService.getRotationStatus(keyId));
    }

    @Test
    @DisplayName("Should throw exception when key ID is null")
    void testRotateKey_WhenKeyIdIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> rotationService.rotateKey(null));
    }

    @Test
    @DisplayName("Should throw exception when key ID is empty")
    void testRotateKey_WhenKeyIdIsEmpty_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> rotationService.rotateKey(""));
    }

    @Test
    @DisplayName("Should schedule rotation successfully")
    void testScheduleRotation_WhenValidTime_ShouldSucceed() throws KeyManagementException {
        // Arrange
        String keyId = "test-key";
        long rotationTime = System.currentTimeMillis() + 1000;
        doNothing().when(mockKeyManager).rotateKey(keyId);

        // Act
        rotationService.scheduleRotation(keyId, rotationTime);

        // Assert
        assertEquals(KeyRotationService.KeyRotationStatus.SCHEDULED, 
                rotationService.getRotationStatus(keyId));
    }

    @Test
    @DisplayName("Should throw exception when scheduling rotation with past time")
    void testScheduleRotation_WhenTimeIsPast_ShouldThrowException() {
        // Arrange
        String keyId = "test-key";
        long rotationTime = System.currentTimeMillis() - 1000;

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> rotationService.scheduleRotation(keyId, rotationTime));
    }

    @Test
    @DisplayName("Should throw exception when scheduling rotation with null key ID")
    void testScheduleRotation_WhenKeyIdIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> rotationService.scheduleRotation(null, System.currentTimeMillis() + 1000));
    }

    @Test
    @DisplayName("Should cancel scheduled rotation successfully")
    void testCancelScheduledRotation_WhenRotationExists_ShouldSucceed() throws KeyManagementException {
        // Arrange
        String keyId = "test-key";
        long rotationTime = System.currentTimeMillis() + 1000;
        doNothing().when(mockKeyManager).rotateKey(keyId);
        rotationService.scheduleRotation(keyId, rotationTime);

        // Act
        rotationService.cancelScheduledRotation(keyId);

        // Assert
        assertEquals(KeyRotationService.KeyRotationStatus.IDLE, 
                rotationService.getRotationStatus(keyId));
    }

    @Test
    @DisplayName("Should handle cancel of non-existent rotation gracefully")
    void testCancelScheduledRotation_WhenRotationNotExists_ShouldCompleteWithoutException() {
        // Arrange
        String keyId = "non-existent-key";

        // Act & Assert
        assertDoesNotThrow(() -> rotationService.cancelScheduledRotation(keyId));
    }

    @Test
    @DisplayName("Should throw exception when cancelling rotation with null key ID")
    void testCancelScheduledRotation_WhenKeyIdIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> rotationService.cancelScheduledRotation(null));
    }

    @Test
    @DisplayName("Should get rotation status successfully")
    void testGetRotationStatus_WhenStatusExists_ShouldReturnCorrectStatus() throws KeyManagementException {
        // Arrange
        String keyId = "test-key";
        doNothing().when(mockKeyManager).rotateKey(keyId);
        rotationService.rotateKey(keyId);

        // Act
        KeyRotationService.KeyRotationStatus status = rotationService.getRotationStatus(keyId);

        // Assert
        assertEquals(KeyRotationService.KeyRotationStatus.COMPLETED, status);
    }

    @Test
    @DisplayName("Should return IDLE status when no rotation exists")
    void testGetRotationStatus_WhenNoRotationExists_ShouldReturnIdle() {
        // Arrange
        String keyId = "non-existent-key";

        // Act
        KeyRotationService.KeyRotationStatus status = rotationService.getRotationStatus(keyId);

        // Assert
        assertEquals(KeyRotationService.KeyRotationStatus.IDLE, status);
    }

    @Test
    @DisplayName("Should throw exception when getting status with null key ID")
    void testGetRotationStatus_WhenKeyIdIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> rotationService.getRotationStatus(null));
    }

    @Test
    @DisplayName("Should replace existing scheduled rotation with new one")
    void testScheduleRotation_WhenRotationAlreadyExists_ShouldReplace() throws KeyManagementException {
        // Arrange
        String keyId = "test-key";
        long firstRotationTime = System.currentTimeMillis() + 5000;
        long secondRotationTime = System.currentTimeMillis() + 1000;
        doNothing().when(mockKeyManager).rotateKey(keyId);
        
        rotationService.scheduleRotation(keyId, firstRotationTime);

        // Act
        rotationService.scheduleRotation(keyId, secondRotationTime);

        // Assert
        assertEquals(KeyRotationService.KeyRotationStatus.SCHEDULED, 
                rotationService.getRotationStatus(keyId));
    }

    @Test
    @DisplayName("Should shutdown gracefully")
    void testShutdown_ShouldCompleteWithoutException() {
        // Act & Assert
        assertDoesNotThrow(() -> rotationService.shutdown());
    }

    @Test
    @DisplayName("Should handle concurrent rotation requests")
    void testRotateKey_ConcurrentRequests_ShouldHandleGracefully() throws KeyManagementException {
        // Arrange
        String keyId = "test-key";
        doNothing().when(mockKeyManager).rotateKey(keyId);

        // Act
        Runnable rotationTask = () -> {
            try {
                rotationService.rotateKey(keyId);
            } catch (KeyManagementException e) {
                fail("Rotation should not fail");
            }
        };

        Thread thread1 = new Thread(rotationTask);
        Thread thread2 = new Thread(rotationTask);
        thread1.start();
        thread2.start();

        // Assert
        assertDoesNotThrow(() -> {
            thread1.join();
            thread2.join();
        });
    }
}
