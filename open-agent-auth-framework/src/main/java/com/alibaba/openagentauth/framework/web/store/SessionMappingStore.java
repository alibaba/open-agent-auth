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
package com.alibaba.openagentauth.framework.web.store;

import jakarta.servlet.http.HttpSession;

/**
 * Store interface for session mappings.
 * <p>
 * This interface defines the contract for storing and retrieving
 * session mappings. Implementations can use in-memory storage,
 * Redis, or any other storage mechanism.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern
 * </p>
 * <p>
 * <b>Use Cases:</b></p>
 * <ul>
 *   <li>In-memory storage for single-instance deployments</li>
 *   <li>Redis for distributed systems</li>
 *   <li>Database for persistence requirements</li>
 *   <li>Custom cache implementations</li>
 * </ul>
 *
 * @since 1.0
 */
public interface SessionMappingStore {
    
    /**
     * Stores a session mapping.
     *
     * @param sessionId the session ID
     * @param session the session object
     */
    void store(String sessionId, HttpSession session);
    
    /**
     * Retrieves a session by ID.
     *
     * @param sessionId the session ID
     * @return the session object, or null if not found
     */
    HttpSession retrieve(String sessionId);
    
    /**
     * Removes a session mapping.
     *
     * @param sessionId the session ID
     */
    void remove(String sessionId);
    
    /**
     * Clears all session mappings.
     * <p>
     * This method should be called periodically or during application shutdown
     * to prevent memory leaks.
     * </p>
     */
    void clearAll();
}
