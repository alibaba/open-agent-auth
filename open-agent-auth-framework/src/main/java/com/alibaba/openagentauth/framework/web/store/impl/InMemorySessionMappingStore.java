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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of SessionMappingStore.
 * <p>
 * This implementation uses a ConcurrentHashMap for thread-safe
 * in-memory storage. Suitable for single-instance deployments.
 * For distributed systems, consider implementing a custom
 * {@link SessionMappingStore} with distributed storage.
 * </p>
 * <p>
 * <b>Thread Safety:</b> This implementation is thread-safe and can be
 * used in multi-threaded environments without additional synchronization.
 * </p>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Not suitable for distributed deployments</li>
 *   <li>Session data is lost on application restart</li>
 *   <li>Memory usage grows with number of active sessions</li>
 * </ul>
 *
 * @since 1.0
 */
public class InMemorySessionMappingStore implements SessionMappingStore {
    
    private static final Logger logger = LoggerFactory.getLogger(InMemorySessionMappingStore.class);
    
    private final Map<String, HttpSession> sessionMap = new ConcurrentHashMap<>();
    
    @Override
    public void store(String sessionId, HttpSession session) {
        if (sessionId == null || session == null) {
            logger.warn("Attempted to store null session or session ID");
            return;
        }
        sessionMap.put(sessionId, session);
        logger.debug("Session stored in mapping: {}", sessionId);
    }
    
    @Override
    public HttpSession retrieve(String sessionId) {
        if (sessionId == null) {
            return null;
        }
        HttpSession session = sessionMap.get(sessionId);
        if (session != null) {
            logger.debug("Session retrieved from mapping: {}", sessionId);
        } else {
            logger.warn("Session not found in mapping: {}", sessionId);
        }
        return session;
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
        sessionMap.clear();
        logger.info("All session mappings cleared");
    }
}
