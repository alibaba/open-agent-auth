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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * In-memory implementation of {@link OAuth2AuthorizationCodeStorage}.
 * <p>
 * This implementation stores authorization codes in a thread-safe in-memory map.
 * It is suitable for development and testing purposes, but should not be used
 * in production environments where persistence across restarts is required.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Thread-safe storage using ConcurrentHashMap</li>
 *   <li>Automatic cleanup of expired codes</li>
 *   <li>Configurable cleanup interval</li>
 *   <li>Single-use enforcement</li>
 * </ul>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Data is lost on application restart</li>
 *   <li>Not suitable for distributed environments</li>
 *   <li>Memory consumption grows with number of codes</li>
 *   <li>No persistence layer</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">RFC 6749 - Authorization Code</a>
 * @since 1.0
 */
public class InMemoryOAuth2AuthorizationCodeStorage implements OAuth2AuthorizationCodeStorage {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(InMemoryOAuth2AuthorizationCodeStorage.class);

    /**
     * The default cleanup interval in seconds (5 minutes).
     */
    private static final long DEFAULT_CLEANUP_INTERVAL_SECONDS = 300;

    /**
     * The storage map for authorization codes.
     */
    private final Map<String, AuthorizationCode> codeStorage;

    /**
     * The scheduled executor for cleanup tasks.
     */
    private final ScheduledExecutorService cleanupExecutor;

    /**
     * The cleanup interval in seconds.
     */
    private final long cleanupIntervalSeconds;

    /**
     * Creates a new InMemoryAuthorizationCodeStorage with default cleanup interval.
     */
    public InMemoryOAuth2AuthorizationCodeStorage() {
        this(DEFAULT_CLEANUP_INTERVAL_SECONDS);
    }

    /**
     * Creates a new InMemoryAuthorizationCodeStorage with custom cleanup interval.
     *
     * @param cleanupIntervalSeconds the cleanup interval in seconds
     */
    public InMemoryOAuth2AuthorizationCodeStorage(long cleanupIntervalSeconds) {
        this.codeStorage = new ConcurrentHashMap<>();
        this.cleanupIntervalSeconds = cleanupIntervalSeconds;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
        
        // Start periodic cleanup task
        startCleanupTask();
        
        logger.info("InMemoryAuthorizationCodeStorage initialized with cleanup interval: {} seconds", 
                cleanupIntervalSeconds);
    }

    @Override
    public void store(AuthorizationCode authorizationCode) {
        ValidationUtils.validateNotNull(authorizationCode, "Authorization code");

        String code = authorizationCode.getCode();
        logger.debug("Storing authorization code: {}", code);

        codeStorage.put(code, authorizationCode);
        logger.info("Authorization code stored successfully: {}", code);
    }

    @Override
    public AuthorizationCode retrieve(String code) {
        if (ValidationUtils.isNullOrEmpty(code)) {
            throw new IllegalArgumentException("Code cannot be null or empty");
        }
        logger.debug("Retrieving authorization code: {}", code);

        AuthorizationCode authCode = codeStorage.get(code);
        
        if (authCode == null) {
            logger.debug("Authorization code not found: {}", code);
            return null;
        }

        // Check if code is expired
        if (authCode.isExpired()) {
            logger.warn("Authorization code has expired: {}", code);
            // Optionally remove expired code
            codeStorage.remove(code);
            return null;
        }

        // Check if code is already used
        if (authCode.isUsed()) {
            logger.warn("Authorization code has already been used: {}", code);
            return null;
        }

        logger.debug("Authorization code retrieved successfully: {}", code);
        return authCode;
    }

    @Override
    public AuthorizationCode consume(String code) {

        if (ValidationUtils.isNullOrEmpty(code)) {
            throw new IllegalArgumentException("Code cannot be null or empty");
        }
        logger.info("Consuming authorization code: {}", code);

        AuthorizationCode authCode = codeStorage.get(code);
        if (authCode == null) {
            logger.error("Authorization code not found for consumption: {}", code);
            throw OAuth2AuthorizationException.invalidRequest("Authorization code not found");
        }

        // Check if code is expired
        if (authCode.isExpired()) {
            logger.error("Cannot consume expired authorization code: {}", code);
            codeStorage.remove(code);
            throw OAuth2AuthorizationException.invalidRequest("Authorization code has expired");
        }

        // Check if code is already used
        if (authCode.isUsed()) {
            logger.error("Cannot consume already used authorization code: {}", code);
            throw OAuth2AuthorizationException.invalidRequest("Authorization code has already been used");
        }

        // Mark code as used
        AuthorizationCode consumedCode = AuthorizationCode.builder()
                .code(authCode.getCode())
                .clientId(authCode.getClientId())
                .redirectUri(authCode.getRedirectUri())
                .requestUri(authCode.getRequestUri())
                .state(authCode.getState())
                .subject(authCode.getSubject())
                .scope(authCode.getScope())
                .issuedAt(authCode.getIssuedAt())
                .expiresAt(authCode.getExpiresAt())
                .used(true)
                .build();

        codeStorage.put(code, consumedCode);
        
        logger.info("Authorization code consumed successfully: {}", code);
        return consumedCode;
    }

    @Override
    public void delete(String code) {
        if (ValidationUtils.isNullOrEmpty(code)) {
            throw new IllegalArgumentException("Code cannot be null or empty");
        }

        logger.debug("Deleting authorization code: {}", code);
        
        codeStorage.remove(code);
        logger.info("Authorization code deleted: {}", code);
    }

    @Override
    public boolean isValid(String code) {
        if (ValidationUtils.isNullOrEmpty(code)) {
            throw new IllegalArgumentException("Code cannot be null or empty");
        }

        logger.debug("Checking validity of authorization code: {}", code);

        AuthorizationCode authCode = codeStorage.get(code);
        
        if (authCode == null) {
            return false;
        }

        boolean isValid = authCode.isValid();
        logger.debug("Authorization code validity: {} for code: {}", isValid, code);
        
        return isValid;
    }

    @Override
    public int cleanupExpired() {
        logger.info("Starting cleanup of expired authorization codes");
        
        int removedCount = 0;
        Instant now = Instant.now();
        
        for (Map.Entry<String, AuthorizationCode> entry : codeStorage.entrySet()) {
            AuthorizationCode authCode = entry.getValue();
            
            // Remove if expired or already used
            if (authCode.getExpiresAt() != null && authCode.getExpiresAt().isBefore(now)) {
                codeStorage.remove(entry.getKey());
                removedCount++;
                logger.debug("Removed expired authorization code: {}", entry.getKey());
            } else if (authCode.isUsed()) {
                codeStorage.remove(entry.getKey());
                removedCount++;
                logger.debug("Removed used authorization code: {}", entry.getKey());
            }
        }
        
        logger.info("Cleanup completed: {} authorization codes removed", removedCount);
        return removedCount;
    }

    /**
     * Starts the periodic cleanup task.
     */
    private void startCleanupTask() {
        cleanupExecutor.scheduleAtFixedRate(
                this::cleanupExpired,
                cleanupIntervalSeconds,
                cleanupIntervalSeconds,
                TimeUnit.SECONDS
        );
        
        logger.info("Scheduled cleanup task with interval: {} seconds", cleanupIntervalSeconds);
    }

    /**
     * Shuts down the storage and releases resources.
     * <p>
     * This method should be called when the storage is no longer needed to
     * properly release the cleanup executor.
     * </p>
     */
    public void shutdown() {
        logger.info("Shutting down InMemoryAuthorizationCodeStorage");
        
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        // Clear storage
        int size = codeStorage.size();
        codeStorage.clear();
        
        logger.info("InMemoryAuthorizationCodeStorage shutdown complete, cleared {} codes", size);
    }

    /**
     * Gets the current number of stored authorization codes.
     *
     * @return the number of stored codes
     */
    public int size() {
        return codeStorage.size();
    }

    /**
     * Checks if the storage is empty.
     *
     * @return true if empty, false otherwise
     */
    public boolean isEmpty() {
        return codeStorage.isEmpty();
    }

}