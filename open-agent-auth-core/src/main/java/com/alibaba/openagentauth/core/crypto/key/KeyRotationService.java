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

import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;

/**
 * Service interface for managing key rotation lifecycle.
 * <p>
 * This interface provides methods for managing the rotation of cryptographic keys,
 * including scheduling rotations, monitoring rotation status, and handling graceful
 * transitions between old and new keys.
 * </p>
 * <p>
 * <b>Key Rotation Best Practices:</b></p>
 * <ul>
 *   <li>Rotate keys periodically (recommended: every 90 days)</li>
 *   <li>Maintain a grace period for old keys (recommended: 7 days)</li>
 *   <li>Monitor rotation status and alert on failures</li>
 *   <li>Keep audit logs of all rotation events</li>
 * </ul>
 * <p>
 * <b>Rotation Process:</b></p>
 * <ol>
 *   <li>Generate new key pair</li>
 *   <li>Activate new key for signing operations</li>
 *   <li>Maintain old key for verification during grace period</li>
 *   <li>Deactivate old key after grace period expires</li>
 *   <li>Archive or delete old key based on policy</li>
 * </ol>
 * </p>
 *
 * @see KeyManager
 * @see KeyInfo
 * @since 1.0
 */
public interface KeyRotationService {
    
    /**
     * Rotates the key with the specified ID.
     * <p>
     * This method generates a new key pair with the same algorithm as the old key,
     * activates it for signing operations, and marks the old key for graceful deactivation.
     * </p>
     *
     * @param keyId the key identifier to rotate
     * @throws KeyManagementException if rotation fails
     */
    void rotateKey(String keyId) throws KeyManagementException;
    
    /**
     * Schedules a key rotation for the specified key ID at a future time.
     *
     * @param keyId the key identifier to rotate
     * @param rotationTime the time when the rotation should occur
     * @throws KeyManagementException if scheduling fails
     */
    void scheduleRotation(String keyId, long rotationTime) throws KeyManagementException;
    
    /**
     * Cancels a scheduled rotation for the specified key ID.
     *
     * @param keyId the key identifier
     * @throws KeyManagementException if cancellation fails
     */
    void cancelScheduledRotation(String keyId) throws KeyManagementException;
    
    /**
     * Gets the rotation status for the specified key ID.
     *
     * @param keyId the key identifier
     * @return the rotation status
     * @throws KeyManagementException if status retrieval fails
     */
    KeyRotationStatus getRotationStatus(String keyId) throws KeyManagementException;
    
    /**
     * Represents the status of a key rotation operation.
     */
    enum KeyRotationStatus {
        /**
         * No rotation scheduled or in progress.
         */
        IDLE,
        
        /**
         * Rotation is scheduled for a future time.
         */
        SCHEDULED,
        
        /**
         * Rotation is currently in progress.
         */
        IN_PROGRESS,
        
        /**
         * Rotation completed successfully.
         */
        COMPLETED,
        
        /**
         * Rotation failed.
         */
        FAILED
    }
}
