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
package com.alibaba.openagentauth.core.protocol.oauth2.par.store;

import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * In-memory implementation of {@link OAuth2ParRequestStore}.
 * <p>
 * This implementation uses a ConcurrentHashMap for thread-safe storage
 * and a scheduled executor for cleanup of expired entries.
 * </p>
 * <p>
 * <b>Warning:</b> This implementation is suitable for development and
 * testing only. For production use, consider using a distributed cache
 * like Redis or a database for persistence and scalability.
 * </p>
 *
 * @since 1.0
 */
public class InMemoryOAuth2ParRequestStore implements OAuth2ParRequestStore {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryOAuth2ParRequestStore.class);

    private final Map<String, StoredRequest> store;
    private final ScheduledExecutorService cleanupExecutor;

    /**
     * Creates a new InMemoryParRequestStore.
     */
    public InMemoryOAuth2ParRequestStore() {
        this.store = new ConcurrentHashMap<>();
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor();
        
        // Schedule cleanup every 60 seconds
        cleanupExecutor.scheduleAtFixedRate(
                this::cleanupExpiredRequests,
                60,
                60,
                TimeUnit.SECONDS
        );
        
        logger.info("InMemoryParRequestStore initialized");
    }

    @Override
    public void store(String requestUri, ParRequest request, long expiresIn) {
        ValidationUtils.validateNotNull(requestUri, "requestUri");
        ValidationUtils.validateNotNull(request, "Request");
        
        if (expiresIn <= 0) {
            throw new IllegalArgumentException("expiresIn must be positive");
        }
        
        long expirationTime = System.currentTimeMillis() + (expiresIn * 1000);
        StoredRequest storedRequest = new StoredRequest(request, expirationTime);
        
        store.put(requestUri, storedRequest);
        
        logger.debug("Stored PAR request: request_uri={}, expires_in={} seconds", 
                requestUri, expiresIn);
    }

    @Override
    public ParRequest retrieve(String requestUri) {
        ValidationUtils.validateNotNull(requestUri, "requestUri");
        
        StoredRequest storedRequest = store.get(requestUri);
        
        if (storedRequest == null) {
            logger.debug("PAR request not found: {}", requestUri);
            return null;
        }
        
        // Check if expired
        if (System.currentTimeMillis() > storedRequest.expirationTime) {
            logger.debug("PAR request expired: {}", requestUri);
            store.remove(requestUri);
            return null;
        }
        
        logger.debug("Retrieved PAR request: {}", requestUri);
        return storedRequest.request;
    }

    @Override
    public boolean remove(String requestUri) {
        ValidationUtils.validateNotNull(requestUri, "requestUri");
        
        StoredRequest removed = store.remove(requestUri);
        
        if (removed != null) {
            logger.debug("Removed PAR request: {}", requestUri);
        }
        
        return removed != null;
    }

    /**
     * Cleans up expired requests from the store.
     */
    private void cleanupExpiredRequests() {
        long now = System.currentTimeMillis();
        int removedCount = 0;
        
        for (Map.Entry<String, StoredRequest> entry : store.entrySet()) {
            if (now > entry.getValue().expirationTime) {
                store.remove(entry.getKey());
                removedCount++;
            }
        }
        
        if (removedCount > 0) {
            logger.debug("Cleaned up {} expired PAR requests", removedCount);
        }
    }

    /**
     * Internal class to store request with expiration time.
     */
    private static class StoredRequest {
        final ParRequest request;
        final long expirationTime;

        StoredRequest(ParRequest request, long expirationTime) {
            this.request = request;
            this.expirationTime = expirationTime;
        }
    }

    /**
     * Shuts down the cleanup executor.
     */
    public void shutdown() {
        cleanupExecutor.shutdown();
        logger.info("InMemoryParRequestStore shutdown");
    }
}