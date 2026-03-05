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
package com.alibaba.openagentauth.framework.web.store.impl;

import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * In-memory implementation of SessionMappingStore with TTL-based expiration.
 * <p>
 * This implementation uses a ConcurrentHashMap for thread-safe in-memory storage
 * with automatic expiration of stale entries. A background cleanup task periodically
 * removes expired entries to prevent memory leaks.
 * </p>
 * <p>
 * <b>Thread Safety:</b> This implementation is thread-safe and can be used in
 * multi-threaded environments without additional synchronization.
 * </p>
 * <p>
 * <b>TTL Behavior:</b> Each stored session mapping has a time-to-live (TTL).
 * After the TTL expires, the entry is eligible for removal during the next
 * cleanup cycle. The default TTL is 10 minutes, which is sufficient for
 * typical OAuth authorization flows.
 * </p>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Not suitable for distributed deployments (use Redis-based implementation instead)</li>
 *   <li>Session data is lost on application restart</li>
 * </ul>
 *
 * @since 1.0
 */
public class InMemorySessionMappingStore implements SessionMappingStore {
    
    private static final Logger logger = LoggerFactory.getLogger(InMemorySessionMappingStore.class);

    /**
     * Default time-to-live for session mappings: 10 minutes.
     * <p>
     * This is sufficient for typical OAuth authorization flows where the user
     * is redirected to the IDP for login and then back to the authorization endpoint.
     * </p>
     */
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(10);

    /**
     * Default interval for the cleanup task: 5 minutes.
     */
    private static final Duration DEFAULT_CLEANUP_INTERVAL = Duration.ofMinutes(5);

    private final Map<String, TimestampedSession> sessionMap = new ConcurrentHashMap<>();
    private final Duration timeToLive;
    private final ScheduledExecutorService cleanupExecutor;

    /**
     * Creates a new InMemorySessionMappingStore with default TTL and cleanup interval.
     */
    public InMemorySessionMappingStore() {
        this(DEFAULT_TTL, DEFAULT_CLEANUP_INTERVAL);
    }

    /**
     * Creates a new InMemorySessionMappingStore with custom TTL and cleanup interval.
     *
     * @param timeToLive the time-to-live for session mappings
     * @param cleanupInterval the interval between cleanup cycles
     */
    public InMemorySessionMappingStore(Duration timeToLive, Duration cleanupInterval) {
        this.timeToLive = timeToLive;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "session-mapping-cleanup");
            thread.setDaemon(true);
            return thread;
        });
        this.cleanupExecutor.scheduleAtFixedRate(
                this::removeExpiredEntries,
                cleanupInterval.toSeconds(),
                cleanupInterval.toSeconds(),
                TimeUnit.SECONDS
        );
        logger.info("InMemorySessionMappingStore initialized with TTL={}, cleanupInterval={}",
                timeToLive, cleanupInterval);
    }
    
    @Override
    public void store(String sessionId, HttpSession session) {
        if (sessionId == null || session == null) {
            logger.warn("Attempted to store null session or session ID");
            return;
        }
        sessionMap.put(sessionId, new TimestampedSession(session, Instant.now()));
        logger.debug("Session stored in mapping: {} (TTL: {})", sessionId, timeToLive);
    }
    
    @Override
    public HttpSession retrieve(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        TimestampedSession entry = sessionMap.get(sessionId);
        if (entry == null) {
            logger.debug("Session not found in mapping: {}", sessionId);
            return null;
        }
        
        // Check if the entry has expired
        if (isExpired(entry)) {
            logger.debug("Session mapping expired, removing: {}", sessionId);
            sessionMap.remove(sessionId);
            return null;
        }
        
        logger.debug("Session retrieved from mapping: {}", sessionId);
        return entry.session();
    }
    
    @Override
    public void remove(String sessionId) {
        if (sessionId == null) {
            return;
        }
        sessionMap.remove(sessionId);
        logger.debug("Session removed from mapping: {}", sessionId);
    }
    
    @Override
    public void clearAll() {
        int size = sessionMap.size();
        sessionMap.clear();
        logger.info("All session mappings cleared (removed {} entries)", size);
    }

    /**
     * Removes expired entries from the session map.
     * <p>
     * This method is called periodically by the cleanup executor.
     * It iterates over all entries and removes those that have exceeded
     * the configured time-to-live.
     * </p>
     */
    private void removeExpiredEntries() {
        int removedCount = 0;
        Iterator<Map.Entry<String, TimestampedSession>> iterator = sessionMap.entrySet().iterator();
        
        while (iterator.hasNext()) {
            Map.Entry<String, TimestampedSession> entry = iterator.next();
            if (isExpired(entry.getValue())) {
                iterator.remove();
                removedCount++;
            }
        }
        
        if (removedCount > 0) {
            logger.info("Cleaned up {} expired session mappings, {} remaining", removedCount, sessionMap.size());
        }
    }

    /**
     * Checks if a timestamped session entry has expired.
     *
     * @param entry the timestamped session entry
     * @return true if the entry has expired, false otherwise
     */
    private boolean isExpired(TimestampedSession entry) {
        return Duration.between(entry.storedAt(), Instant.now()).compareTo(timeToLive) > 0;
    }

    /**
     * A session entry with a timestamp recording when it was stored.
     *
     * @param session the HTTP session
     * @param storedAt the instant when the session was stored
     */
    private record TimestampedSession(HttpSession session, Instant storedAt) {
    }
}
