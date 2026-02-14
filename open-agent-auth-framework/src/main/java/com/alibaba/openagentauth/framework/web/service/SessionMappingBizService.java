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
package com.alibaba.openagentauth.framework.web.service;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Business service for session mapping operations.
 * <p>
 * This service provides high-level session mapping operations with
 * business logic such as session restoration, synchronization, and
 * validation. It delegates storage operations to the underlying
 * SessionMappingStore.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Facade Pattern + Delegation Pattern
 * </p>
 * <p>
 * <b>Responsibilities:</b></p>
 * <ul>
 *   <li>Store and retrieve session mappings</li>
 *   <li>Restore sessions with fallback handling</li>
 *   <li>Synchronize session attributes between sessions</li>
 *   <li>Clean up session mappings</li>
 * </ul>
 *
 * @since 1.0
 */
public class SessionMappingBizService {
    
    private static final Logger logger = LoggerFactory.getLogger(SessionMappingBizService.class);
    
    private final SessionMappingStore store;
    
    /**
     * Creates a new SessionMappingBizService.
     *
     * @param store the session mapping store
     * @throws NullPointerException if store is null
     */
    public SessionMappingBizService(SessionMappingStore store) {
        this.store = ValidationUtils.validateNotNull(store, "SessionMappingStore ");
    }
    
    /**
     * Stores a session with business validation.
     *
     * @param sessionId the session ID
     * @param session the session object
     */
    public void storeSession(String sessionId, HttpSession session) {
        if (sessionId == null || session == null) {
            logger.warn("Cannot store session: sessionId or session is null");
            return;
        }
        
        // Store in underlying storage
        store.store(sessionId, session);
        logger.info("Session stored in business service: {}", sessionId);
    }
    
    /**
     * Restores a session by ID with fallback handling.
     * <p>
     * This method attempts to restore the session from the store.
     * If the session is not found and {@code createIfNotFound} is true,
     * a new session is created.
     * </p>
     *
     * @param sessionId the session ID to restore
     * @param createIfNotFound whether to create a new session if not found
     * @param request the HTTP request (used to create new session if needed)
     * @return the restored session, or null if restoration failed
     */
    public HttpSession restoreSession(String sessionId, boolean createIfNotFound, HttpServletRequest request) {
        if (sessionId == null) {
            if (createIfNotFound) {
                logger.warn("Session ID is null, creating new session");
                return request.getSession(true);
            }
            return null;
        }
        
        // Retrieve from storage
        HttpSession session = store.retrieve(sessionId);
        
        if (session == null) {
            if (createIfNotFound) {
                logger.warn("Session not found in store: {}, creating new session", sessionId);
                return request.getSession(true);
            } else {
                logger.error("Session not found in store: {}", sessionId);
                return null;
            }
        }
        
        logger.info("Session restored from business service: {}", sessionId);
        return session;
    }
    
    /**
     * Removes a session and cleans up associated state.
     *
     * @param sessionId the session ID
     */
    public void removeSession(String sessionId) {
        if (sessionId == null) {
            return;
        }
        
        // Remove from storage
        store.remove(sessionId);
        logger.info("Session removed from business service: {}", sessionId);
    }
    
    /**
     * Synchronizes all attributes from source session to target session.
     * <p>
     * This method copies all attributes from the source session to the target session,
     * preserving the complete session state. This is useful for OAuth callbacks
     * where the session needs to be restored after cross-domain redirects.
     * </p>
     *
     * @param sourceSession the source session
     * @param targetSession the target session
     */
    public void syncSessionAttributes(HttpSession sourceSession, HttpSession targetSession) {
        if (sourceSession == null || targetSession == null) {
            logger.warn("Cannot sync session attributes: source or target session is null");
            return;
        }
        
        logger.debug("Syncing session attributes from {} to {}", 
                    sourceSession.getId(), targetSession.getId());
        
        java.util.Enumeration<String> attributeNames = sourceSession.getAttributeNames();
        int syncedCount = 0;
        
        while (attributeNames.hasMoreElements()) {
            String attributeName = attributeNames.nextElement();
            Object attributeValue = sourceSession.getAttribute(attributeName);
            
            if (attributeValue != null) {
                targetSession.setAttribute(attributeName, attributeValue);
                syncedCount++;
                logger.debug("Synced session attribute: {}", attributeName);
            }
        }
        
        logger.info("Synced {} session attributes from {} to {}", 
                    syncedCount, sourceSession.getId(), targetSession.getId());
    }
}