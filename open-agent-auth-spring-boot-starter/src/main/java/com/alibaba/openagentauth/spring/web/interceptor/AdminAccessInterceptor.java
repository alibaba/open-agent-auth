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
package com.alibaba.openagentauth.spring.web.interceptor;

import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.spring.autoconfigure.properties.AdminProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;
import java.util.Objects;

/**
 * Interceptor that enforces access control on admin endpoints.
 * <p>
 * When access control is enabled, this interceptor checks that the current
 * HTTP session contains an authenticated user whose subject matches one of
 * the configured {@code allowedSessionSubjects}. If the user is not
 * authenticated or not authorized, the request is rejected with HTTP 403 Forbidden.
 * </p>
 * <p>
 * This interceptor integrates with the framework's existing session-based
 * authentication mechanism, reading the authenticated user subject from the
 * session attribute {@code "authenticated_user"} (as defined by
 * {@code SessionAttributes.AUTHENTICATED_USER}).
 * </p>
 * <p>
 * <b>Security Model:</b>
 * </p>
 * <ul>
 *   <li>If access control is disabled, all requests are allowed (pass-through)</li>
 *   <li>If access control is enabled but no subjects are configured, all requests
 *       are denied (fail-closed)</li>
 *   <li>If access control is enabled with subjects configured, only matching
 *       authenticated users are allowed</li>
 * </ul>
 *
 * @since 1.0
 * @see AdminProperties.AccessControlProperties
 */
public class AdminAccessInterceptor implements HandlerInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(AdminAccessInterceptor.class);

    /**
     * Session attribute key for the authenticated user subject.
     * References the canonical key defined in {@link SessionAttributes#AUTHENTICATED_USER}.
     */
    private static final String AUTHENTICATED_USER_KEY = SessionAttributes.AUTHENTICATED_USER.getKey();

    private final boolean accessControlEnabled;
    private final List<String> allowedSubjects;

    /**
     * Creates a new AdminAccessInterceptor.
     *
     * @param accessControlProperties the access control configuration
     * @throws NullPointerException if accessControlProperties is null
     */
    public AdminAccessInterceptor(AdminProperties.AccessControlProperties accessControlProperties) {
        Objects.requireNonNull(accessControlProperties, "accessControlProperties must not be null");
        this.accessControlEnabled = accessControlProperties.isEnabled();
        List<String> subjects = accessControlProperties.getAllowedSessionSubjects();
        this.allowedSubjects = (subjects != null) ? List.copyOf(subjects) : List.of();

        if (accessControlEnabled) {
            if (allowedSubjects.isEmpty()) {
                logger.warn("Admin access control is enabled but no allowed subjects are configured. "
                        + "All admin requests will be denied (fail-closed). "
                        + "Configure 'open-agent-auth.admin.access-control.allowed-session-subjects' "
                        + "to grant access.");
            } else {
                logger.info("Admin access control enabled for {} subject(s)", allowedSubjects.size());
            }
        } else {
            logger.warn("Admin access control is DISABLED. Admin endpoints are accessible without authentication. "
                    + "This is NOT recommended for production environments.");
        }
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) throws Exception {
        if (!accessControlEnabled) {
            return true;
        }

        HttpSession session = request.getSession(false);
        if (session == null) {
            logger.debug("Admin access denied: no active session for {}", request.getRequestURI());
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Authentication required");
            return false;
        }

        Object subjectAttribute = session.getAttribute(AUTHENTICATED_USER_KEY);
        if (!(subjectAttribute instanceof String authenticatedSubject) || authenticatedSubject.isBlank()) {
            logger.debug("Admin access denied: no authenticated user in session for {}", request.getRequestURI());
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied: Authentication required");
            return false;
        }

        if (!allowedSubjects.contains(authenticatedSubject)) {
            logger.warn("Admin access denied: user '{}' is not in the allowed subjects list for {}",
                    authenticatedSubject, request.getRequestURI());
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "Access Denied: Insufficient privileges");
            return false;
        }

        logger.debug("Admin access granted for user '{}' to {}", authenticatedSubject, request.getRequestURI());
        return true;
    }
}
