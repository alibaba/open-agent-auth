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
package com.alibaba.openagentauth.framework.web.interceptor;

import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Unified user authentication interceptor for both Authorization Server and Agent roles.
 * <p>
 * This interceptor provides a consistent user authentication flow that can be used in two scenarios:
 * </p>
 * <ul>
 *   <li><b>Interceptor Mode:</b> Automatically intercepts requests and redirects unauthenticated users to User IDP</li>
 *   <li><b>Provider Mode:</b> Provides login URL for Authorization Server to redirect unauthenticated users</li>
 * </ul>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern + Template Method Pattern
 * </p>
 * <p>
 * This class follows the Template Method Pattern, defining the skeleton of the authentication
 * flow while allowing subclasses to customize specific steps (e.g., build authorization URL).
 * </p>
 *
 * <h3>Authentication Flow:</h3>
 * <ol>
 *   <li>Check if request URI is in excluded paths</li>
 *   <li>Check session for authenticated user</li>
 *   <li>If not authenticated:
 *     <ul>
 *       <li>Create/get session</li>
 *       <li>Store session mapping</li>
 *       <li>Generate state parameter (format: "user:state:sessionId")</li>
 *       <li>Build authorization URL</li>
 *       <li>Redirect to User IDP (Interceptor mode) or return URL (Provider mode)</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <h3>Usage Example (Interceptor Mode):</h3>
 * <pre>
 * // In Spring configuration
 * @Bean
 * public UserAuthenticationInterceptor userAuthInterceptor(
 *         SessionMappingBizService sessionMappingBizService) {
 *     List<String> excludedPaths = List.of("/login", "/callback", "/public/**");
 *     return new AsUserIdpUserAuthInterceptor(sessionMappingBizService, excludedPaths);
 * }
 *
 * // Register as Spring HandlerInterceptor
 * @Override
 * public void addInterceptors(InterceptorRegistry registry) {
 *     registry.addInterceptor(userAuthInterceptor);
 * }
 * </pre>
 *
 * <h3>Usage Example (Provider Mode):</h3>
 * <pre>
 * // In UserAuthenticationProvider implementation
 * @Component
 * public class AsUserIdpUserAuthenticationProvider implements UserAuthenticationProvider {
 *     private final UserAuthenticationInterceptor interceptor;
 *
 *     @Override
 *     public String getLoginUrl(HttpServletRequest request) {
 *         return interceptor.getLoginUrl(request);
 *     }
 *
 *     @Override
 *     public String authenticate(HttpServletRequest request) {
 *         return interceptor.authenticate(request);
 *     }
 * }
 * </pre>
 *
 * @since 1.0
 */
public class UserAuthenticationInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(UserAuthenticationInterceptor.class);

    /**
     * The session mapping business service.
     */
    private final SessionMappingBizService sessionMappingBizService;

    /**
     * The list of paths to exclude from authentication.
     */
    private final List<String> excludedPaths;

    /**
     * Constructs a new UserAuthenticationInterceptor.
     *
     * @param sessionMappingBizService the session mapping business service
     * @param excludedPaths the list of paths to exclude from authentication
     */
    public UserAuthenticationInterceptor(
            SessionMappingBizService sessionMappingBizService,
            List<String> excludedPaths
    ) {
        this.sessionMappingBizService = sessionMappingBizService;
        this.excludedPaths = excludedPaths != null ? excludedPaths : new ArrayList<>();
        logger.info("UserAuthenticationInterceptor initialized with excluded paths: {}", this.excludedPaths);
    }

    /**
     * Interceptor pre-handle method for checking authentication.
     * <p>
     * This method checks if the user is authenticated before allowing access to protected resources.
     * If the user is not authenticated, it redirects to the User IDP for login.
     * </p>
     *
     * @param request the HTTP request
     * @param response the HTTP response
     * @return true if the request should proceed, false if it was handled (redirected)
     * @throws IOException if an I/O error occurs during redirect
     */
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String requestUri = request.getRequestURI();
        logger.info("Checking authentication for request: {}", requestUri);

        // Check if the request URI is in the excluded paths
        if (isExcludedPath(requestUri)) {
            logger.info("Request URI is excluded from authentication: {}", requestUri);
            return true;
        }

        // Check if user is authenticated
        String subject = authenticate(request);
        if (subject != null) {
            logger.debug("User is already authenticated: {}", subject);
            return true;
        }

        logger.info("User not authenticated, redirecting to User IDP");

        // Get login URL and redirect
        String loginUrl = getLoginUrl(request);
        if (loginUrl == null) {
            logger.error("No login URL available");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication required");
            return false;
        }

        response.sendRedirect(loginUrl);
        return false;
    }

    /**
     * Authenticates the user by checking the session.
     * <p>
     * This method can be used by UserAuthenticationProvider implementations.
     * </p>
     *
     * @param request the HTTP request
     * @return the authenticated user subject, or null if not authenticated
     */
    public String authenticate(HttpServletRequest request) {

        if (request == null) {
            return null;
        }

        // Get the current session
        HttpSession session = request.getSession(false);
        if (session == null) {
            logger.debug("No session found in request");
            return null;
        }

        // Try to restore session attributes from the mapping store
        String sessionId = session.getId();
        HttpSession restoredSession = sessionMappingBizService.restoreSession(sessionId, false, request);
        if (restoredSession != null && !restoredSession.getId().equals(session.getId())) {
            // Sync attributes from restored session to current session
            sessionMappingBizService.syncSessionAttributes(restoredSession, session);
            logger.debug("Session attributes synced from mapping store: {}", sessionId);
        }

        // Get authenticated user using SessionManager
        String subject = SessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER);
        if (subject != null) {
            logger.debug("User authenticated: {}", subject);
            return subject;
        }

        logger.debug("No authenticated user found in session");
        return null;
    }

    /**
     * Gets the login URL for unauthenticated users.
     * <p>
     * This method can be used by UserAuthenticationProvider implementations.
     * </p>
     *
     * @param request the HTTP request
     * @return the login URL, or null if not available
     */
    public String getLoginUrl(HttpServletRequest request) {
        // Get or create session
        HttpSession session = request.getSession(true);
        
        // Generate state parameter with session ID
        String originalSessionId = session.getId();
        String state = "user:" + generateState() + ":" + originalSessionId;
        SessionManager.setAttribute(session, SessionAttributes.OAUTH_STATE, state);
        
        logger.debug("Generated state parameter for User IDP login: {}", state);
        logger.debug("Embedded session ID in state: {}", originalSessionId);
        
        // Store session mapping
        sessionMappingBizService.storeSession(session.getId(), session);
        logger.debug("Session stored in mapping: {}", session.getId());
        
        // Build authorization URL
        String authorizationUrl = buildAuthorizationUrl(request, state);
        
        logger.info("Generated login URL redirecting to User IDP");
        return authorizationUrl;
    }

    /**
     * Builds the authorization URL for User IDP.
     * <p>
     * This method should be overridden by subclasses to provide User IDP-specific
     * authorization URL construction logic.
     * </p>
     *
     * @param request the HTTP request
     * @param state the state parameter for CSRF protection
     * @return the authorization URL
     */
    protected String buildAuthorizationUrl(HttpServletRequest request, String state) {
        // Default implementation returns null
        // Subclasses should override this method
        logger.warn("buildAuthorizationUrl() not implemented, returning null");
        return null;
    }

    /**
     * Generates a secure random state parameter for CSRF protection.
     *
     * @return the state string
     */
    protected String generateState() {
        return UUID.randomUUID().toString();
    }

    /**
     * Checks if the request URI is in the excluded paths.
     * <p>
     * Excluded paths bypass authentication checks. This includes callback endpoints,
     * logout endpoints, and public resources.
     * </p>
     *
     * @param requestUri the request URI
     * @return true if the path is excluded, false otherwise
     */
    protected boolean isExcludedPath(String requestUri) {
        for (String excludedPath : excludedPaths) {
            if (matchesPattern(excludedPath, requestUri)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Matches a path pattern against a request URI.
     * <p>
     * This method supports Ant-style path patterns:
     * </p>
     <ul>
     *   <li><code>*</code> matches zero or more characters within a single path segment</li>
     *   <li><code>**</code> matches zero or more path segments</li>
     *   <li><code>?</code> matches exactly one character</li>
     * </ul>
     *
     * @param pattern the path pattern (e.g., <code>/public/**</code>, <code>/api/*</code>)
     * @param path the request URI to match
     * @return true if the path matches the pattern, false otherwise
     */
    protected boolean matchesPattern(String pattern, String path) {
        // Exact match
        if (pattern.equals(path)) {
            return true;
        }

        // Handle ** wildcard (matches zero or more path segments)
        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.equals(prefix) || path.startsWith(prefix + "/");
        }

        // Handle ** wildcard in the middle (e.g., /public/**/images)
        int doubleStarIndex = pattern.indexOf("/**");
        if (doubleStarIndex >= 0) {
            String prefix = pattern.substring(0, doubleStarIndex);
            String suffix = pattern.substring(doubleStarIndex + 3);

            if (path.startsWith(prefix)) {
                String remaining = path.substring(prefix.length());
                return remaining.equals(suffix) ||
                       remaining.startsWith("/") && remaining.substring(1).startsWith(suffix) ||
                       remaining.endsWith(suffix) &&
                       remaining.substring(0, remaining.length() - suffix.length()).contains("/");
            }
        }

        // Handle * wildcard (matches zero or more characters within a single path segment)
        if (pattern.contains("*")) {
            return matchesSingleStarPattern(pattern, path);
        }

        // Handle ? wildcard (matches exactly one character)
        if (pattern.contains("?")) {
            return matchesQuestionMarkPattern(pattern, path);
        }

        // Prefix match (pattern must end with / for proper prefix matching)
        if (pattern.endsWith("/")) {
            return path.startsWith(pattern);
        }

        return false;
    }

    /**
     * Matches a pattern containing * wildcards.
     *
     * @param pattern the pattern containing * wildcards
     * @param path the path to match
     * @return true if matches, false otherwise
     */
    private boolean matchesSingleStarPattern(String pattern, String path) {
        String[] patternParts = pattern.split("/");
        String[] pathParts = path.split("/");

        if (patternParts.length != pathParts.length) {
            return false;
        }

        for (int i = 0; i < patternParts.length; i++) {
            String patternPart = patternParts[i];
            String pathPart = pathParts[i];

            if (!patternPart.equals("*") && !patternPart.equals(pathPart)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Matches a pattern containing ? wildcards.
     *
     * @param pattern the pattern containing ? wildcards
     * @param path the path to match
     * @return true if matches, false otherwise
     */
    private boolean matchesQuestionMarkPattern(String pattern, String path) {
        String[] patternParts = pattern.split("/");
        String[] pathParts = path.split("/");

        if (patternParts.length != pathParts.length) {
            return false;
        }

        for (int i = 0; i < patternParts.length; i++) {
            String patternPart = patternParts[i];
            String pathPart = pathParts[i];

            if (!patternPart.equals(pathPart)) {
                if (patternPart.length() != pathPart.length()) {
                    return false;
                }

                for (int j = 0; j < patternPart.length(); j++) {
                    char patternChar = patternPart.charAt(j);
                    char pathChar = pathPart.charAt(j);

                    if (patternChar != '?' && patternChar != pathChar) {
                        return false;
                    }
                }
            }
        }

        return true;
    }
}
