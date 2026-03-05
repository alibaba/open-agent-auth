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
package com.alibaba.openagentauth.framework.web.manager;

import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;

import java.util.List;
import java.util.Map;

/**
 * Centralized registry of all session attribute definitions.
 * <p>
 * This class provides type-safe constants for all session attributes
 * used across the application. It provides compile-time type safety
 * by combining string keys with type information.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Registry Pattern + Type Token Pattern
 * </p>
 * <p>
 * <b>Usage:</b></p>
 * <pre>
 * // Get attribute with type safety
 * String userId = sessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER);
 * 
 * // Set attribute with compile-time type checking
 * sessionManager.setAttribute(session, SessionAttributes.AUTHENTICATED_USER, "user123");
 * 
 * // Remove attribute using SessionManager
 * sessionManager.removeAttribute(session, SessionAttributes.OAUTH_STATE);
 * </pre>
 *
 * @since 1.0
 */
public final class SessionAttributes {
    
    private SessionAttributes() {
        // Utility class - prevent instantiation
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
    
    // ==================== User Authentication ====================
    
    /**
     * Key for storing the authenticated user ID (subject) in session.
     */
    public static final SessionAttribute<String> AUTHENTICATED_USER = new SessionAttribute<>("authenticated_user", String.class);
    
    /**
     * Key for storing the ID Token in session.
     */
    public static final SessionAttribute<String> ID_TOKEN = new SessionAttribute<>("id_token", String.class);
    
    /**
     * Key for storing the OAuth state parameter in session.
     */
    public static final SessionAttribute<String> OAUTH_STATE = new SessionAttribute<>("oauth_state", String.class);
    
    /**
     * Key for storing the Agent Operation Authorization (OA) Token in session.
     */
    public static final SessionAttribute<String> AGENT_OA_TOKEN = new SessionAttribute<>("agent_oa_token", String.class);
    
    // ==================== Session Mapping ====================
    
    /**
     * Key for storing the redirect URI in session during OAuth flow.
     */
    public static final SessionAttribute<String> REDIRECT_URI = new SessionAttribute<>("open_agent_auth_redirect_uri", String.class);

    // ==================== Security ====================

    /**
     * Key for storing the CSRF token in session.
     * <p>
     * The CSRF token is generated when the login page is rendered and validated
     * when the login form is submitted. This provides protection against
     * Cross-Site Request Forgery attacks on the login endpoint.
     * </p>
     */
    public static final SessionAttribute<String> CSRF_TOKEN = new SessionAttribute<>("open_agent_auth_csrf_token", String.class);

    // ==================== Conversation Context ====================
    
    /**
     * Key for storing conversation history in session.
     * Note: Stored as raw List for flexibility to support different message types.
     * Since ChatMessage is defined in sample module, we use raw List here.
     */
    @SuppressWarnings("rawtypes")
    public static final SessionAttribute<List> CONVERSATION_HISTORY = new SessionAttribute<>("conversation_history", List.class);
    
    /**
     * Key for storing workload context in session.
     */
    public static final SessionAttribute<WorkloadContext> WORKLOAD_CONTEXT = new SessionAttribute<>("workloadContext", WorkloadContext.class);
    
    /**
     * Key for storing pending tool request in session.
     * This is used when a tool requires authentication, storing the request
     * until the user is authenticated and can resume the tool execution.
     */
    public static final SessionAttribute<Map<String, Object>> PENDING_TOOL_REQUEST =
            new SessionAttribute<>("pending_tool_request", (Class<Map<String, Object>>) (Class<?>) Map.class);
}
