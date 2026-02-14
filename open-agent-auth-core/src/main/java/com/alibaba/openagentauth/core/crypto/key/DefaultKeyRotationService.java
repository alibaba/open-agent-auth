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

import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of KeyRotationService.
 * <p>
 * This implementation provides key rotation scheduling and management capabilities.
 * It uses a scheduler to execute rotations at specified times and maintains
 * rotation status tracking.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can handle concurrent rotation requests.
 * </p>
 *
 * @see KeyRotationService
 * @since 1.0
 */
public class DefaultKeyRotationService implements KeyRotationService {
    
    private static final Logger logger = LoggerFactory.getLogger(DefaultKeyRotationService.class);
    
    /**
     * The key manager for performing rotations.
     */
    private final KeyManager keyManager;
    
    /**
     * Scheduler for executing rotations.
     */
    private final ScheduledExecutorService scheduler;
    
    /**
     * Map of scheduled rotations.
     */
    private final Map<String, ScheduledFuture<?>> scheduledRotations;
    
    /**
     * Map of rotation statuses.
     */
    private final Map<String, KeyRotationStatus> rotationStatuses;
    
    /**
     * Creates a new DefaultKeyRotationService.
     *
     * @param keyManager the key manager
     * @throws IllegalArgumentException if keyManager is null
     */
    public DefaultKeyRotationService(KeyManager keyManager) {
        ValidationUtils.validateNotNull(keyManager, "KeyManager");
        this.keyManager = keyManager;
        this.scheduler = Executors.newScheduledThreadPool(1);
        this.scheduledRotations = new ConcurrentHashMap<>();
        this.rotationStatuses = new ConcurrentHashMap<>();
        logger.info("DefaultKeyRotationService initialized");
    }
    
    @Override
    public void rotateKey(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        rotationStatuses.put(keyId, KeyRotationStatus.IN_PROGRESS);
        
        try {
            logger.info("Starting key rotation: keyId={}", keyId);
            keyManager.rotateKey(keyId);
            rotationStatuses.put(keyId, KeyRotationStatus.COMPLETED);
            logger.info("Key rotation completed successfully: keyId={}", keyId);
        } catch (Exception e) {
            rotationStatuses.put(keyId, KeyRotationStatus.FAILED);
            logger.error("Key rotation failed: keyId={}", keyId, e);
            throw new KeyManagementException("Key rotation failed: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void scheduleRotation(String keyId, long rotationTime) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        // Cancel existing rotation if any
        cancelScheduledRotation(keyId);
        
        long delay = rotationTime - System.currentTimeMillis();
        if (delay <= 0) {
            throw new IllegalArgumentException("Rotation time must be in the future");
        }
        
        ScheduledFuture<?> future = scheduler.schedule(() -> {
            try {
                rotateKey(keyId);
            } catch (KeyManagementException e) {
                logger.error("Scheduled rotation failed: keyId={}", keyId, e);
            }
        }, delay, TimeUnit.MILLISECONDS);
        
        scheduledRotations.put(keyId, future);
        rotationStatuses.put(keyId, KeyRotationStatus.SCHEDULED);
        
        logger.info("Scheduled key rotation: keyId={}, delay={}ms", keyId, delay);
    }
    
    @Override
    public void cancelScheduledRotation(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        ScheduledFuture<?> future = scheduledRotations.remove(keyId);
        if (future != null) {
            future.cancel(false);
            rotationStatuses.put(keyId, KeyRotationStatus.IDLE);
            logger.info("Cancelled scheduled rotation: keyId={}", keyId);
        }
    }
    
    @Override
    public KeyRotationStatus getRotationStatus(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        return rotationStatuses.getOrDefault(keyId, KeyRotationStatus.IDLE);
    }
    
    /**
     * Shuts down the rotation service.
     * <p>
     * This method should be called when the service is no longer needed.
     * </p>
     */
    public void shutdown() {
        logger.info("Shutting down DefaultKeyRotationService");
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(10, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}