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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.model.oidc.DefaultSessionUser;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default controller for user authentication and login/logout functionality in Identity Provider (IDP) scenarios.
 * <p>
 * This controller provides a ready-to-use login page and authentication flow for IDP roles
 * (agent-user-idp and as-user-idp). It integrates seamlessly with the OAuth 2.0 authorization flow
 * by storing the authorization URL in the session and redirecting back after successful authentication.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Standard username/password authentication using {@link UserRegistry}</li>
 *   <li>Automatic redirect to authorization endpoint after login</li>
 *   <li>Session-based authorization URL preservation</li>
 *   <li>Configurable login page template</li>
 *   <li>Logout functionality</li>
 * </ul>
 * <p>
 * <b>Customization:</b></p>
 * Developers can override this controller by providing their own implementation
 * with the same mapping paths, or customize the login page by providing a custom
 * {@code login.html} template in their application's {@code templates} directory.
 * </p>
 * <p>
 * <b>Configuration:</b></p>
 * The controller is automatically enabled for {@code agent-user-idp} and {@code as-user-idp} roles.
 * It can be disabled by setting {@code open-agent-auth.login.enabled=false}.
 * </p>
 *
 * @since 1.0
 */
@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(UserRegistry.class)
public class UserLoginController {

    /**
     * The logger for the IDP Login controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(UserLoginController.class);

    /**
     * Cryptographically secure random number generator for CSRF token generation.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Length of the CSRF token in bytes (32 bytes = 256 bits of entropy).
     */
    private static final int CSRF_TOKEN_BYTE_LENGTH = 32;

    /**
     * The user registry for authentication.
     */
    private final UserRegistry userRegistry;

    /**
     * The session mapping business service for managing session mappings.
     */
    private final SessionMappingBizService sessionMappingBizService;

    /**
     * The user authentication interceptor for session restoration.
     * <p>
     * This is optional because not all IDP deployments use the interceptor-based
     * authentication flow. When available, it provides session restoration
     * capabilities for cross-domain redirect scenarios.
     * </p>
     */
    @Nullable
    private final UserAuthenticationInterceptor userAuthenticationInterceptor;

    /**
     * Creates a new IDP Login controller.
     *
     * @param userRegistry the user registry for authentication
     * @param sessionMappingBizService the session mapping business service
     * @param userAuthenticationInterceptor the user authentication interceptor (optional)
     */
    public UserLoginController(
            UserRegistry userRegistry,
            SessionMappingBizService sessionMappingBizService,
            @Nullable UserAuthenticationInterceptor userAuthenticationInterceptor) {
        this.userRegistry = userRegistry;
        this.sessionMappingBizService = sessionMappingBizService;
        this.userAuthenticationInterceptor = userAuthenticationInterceptor;
    }

    /**
     * Login page.
     * <p>
     * Displays the login form. The redirect_uri parameter is retrieved from the session
     * (set by {@link OAuth2AuthorizationController}) and passed to the template as a hidden field.
     * This ensures that after successful login, the user is redirected back to the authorization endpoint.
     * </p>
     *
     * @param redirectUri the original authorization endpoint URI with OAuth 2.0 parameters (fallback)
     * @param model the Spring MVC model
     * @param session the HTTP session
     * @return the login page view name
     */
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            Model model,
            HttpSession session
    ) {
        // Try to get redirect URI from session first (preferred approach)
        String sessionRedirectUri = null;
        if (session != null) {
            sessionRedirectUri = SessionManager.getAttribute(session, SessionAttributes.REDIRECT_URI);
            if (sessionRedirectUri != null) {
                model.addAttribute("redirect_uri", sessionRedirectUri);
                logger.info("Login page accessed with redirect_uri from session: {}", sessionRedirectUri);
            }
        }
        
        // Fallback to parameter-based approach for backward compatibility
        if (sessionRedirectUri == null && redirectUri != null && !redirectUri.isBlank()) {
            model.addAttribute("redirect_uri", redirectUri);
            logger.info("Login page accessed with redirect_uri from parameter: {}", redirectUri);
        } else if (sessionRedirectUri == null) {
            logger.info("Login page accessed without redirect_uri (direct login)");
        }

        // Generate and store CSRF token for form protection
        String csrfToken = generateCsrfToken();
        SessionManager.setAttribute(session, SessionAttributes.CSRF_TOKEN, csrfToken);
        model.addAttribute("_csrf", csrfToken);
        
        return "login";
    }

    /**
     * Handle login form submission.
     * <p>
     * Authenticates the user using {@link UserRegistry} and stores the user information in the session.
     * After successful authentication, redirects to the authorization endpoint (if redirect_uri is present)
     * or to the home page.
     * </p>
     *
     * @param username the username
     * @param password the password
     * @param session the HTTP session
     * @param redirectAttributes redirect attributes for error messages
     * @param redirectUri the original authorization endpoint URI with OAuth 2.0 parameters (fallback)
     * @return redirect to authorization endpoint, home page, or login page with error
     */
    @PostMapping("/login")
    public RedirectView login(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam(value = "_csrf", required = false) String csrfToken,
            HttpSession session,
            RedirectAttributes redirectAttributes,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            HttpServletRequest request) {
        
        logger.info("Login attempt for user: {}", username);

        // Validate CSRF token
        if (!validateCsrfToken(session, csrfToken)) {
            logger.warn("CSRF token validation failed for login attempt by user: {}", username);
            redirectAttributes.addFlashAttribute("error", "Invalid request. Please try again.");
            return new RedirectView("/login");
        }

        try {
            // Authenticate user using core module's UserRegistry
            String subject = userRegistry.authenticate(username, password);
            
            // Build user object from registry data for potential future use
            DefaultSessionUser.builder()
                    .subject(subject)
                    .username(username)
                    .password("")
                    .name(userRegistry.getName(username))
                    .email(userRegistry.getEmail(username))
                    .preferredUsername(username)
                    .build();

            // Store user ID in current session
            SessionManager.setAttribute(session, SessionAttributes.AUTHENTICATED_USER, subject);
            logger.info("Login successful for user: {}", username);

            // Retrieve the redirect URI from the current session.
            // It was stored by AuthorizationOrchestrator.handleUnauthenticated() before the redirect.
            String sessionRedirectUri = getRedirectUriFromSession(session);
            
            if (sessionRedirectUri != null) {
                logger.info("Redirecting to authorization endpoint: {}", sessionRedirectUri);
                return new RedirectView(sessionRedirectUri);
            }
            
            // Fallback to parameter-based approach for backward compatibility
            if (redirectUri != null && !redirectUri.isBlank()) {
                logger.info("Redirecting to authorization endpoint from form parameter: {}", redirectUri);
                return new RedirectView(redirectUri);
            }
            
            logger.info("No redirect_uri provided, redirecting to home page");
            return new RedirectView("/");
            
        } catch (Exception e) {
            logger.warn("Login failed for user: {}, error: {}", username, e.getMessage());
            redirectAttributes.addFlashAttribute("error", "Invalid username or password");
            return new RedirectView("/login");
        }
    }

    /**
     * Retrieves the redirect URI from the current session.
     * <p>
     * The redirect URI was stored in the session by {@code AuthorizationOrchestrator.handleUnauthenticated()}
     * before the OAuth redirect. Since the login page and the authorization endpoint are on the same
     * domain (same IDP), the session cookie is preserved and the redirect URI is available directly
     * in the current session.
     * </p>
     *
     * @param currentSession the current HTTP session
     * @return the redirect URI if found, null otherwise
     */
    private String getRedirectUriFromSession(HttpSession currentSession) {
        String redirectUri = SessionManager.getAttribute(currentSession, SessionAttributes.REDIRECT_URI);
        if (redirectUri != null) {
            SessionManager.removeAttribute(currentSession, SessionAttributes.REDIRECT_URI);
            logger.info("Found redirect URI in current session");
            return redirectUri;
        }

        return null;
    }

    /**
     * Generates a cryptographically secure CSRF token.
     * <p>
     * Uses {@link SecureRandom} to generate 32 bytes of random data,
     * then Base64 URL-encodes it to produce a URL-safe token string.
     * </p>
     *
     * @return a Base64 URL-encoded CSRF token
     */
    private static String generateCsrfToken() {
        byte[] tokenBytes = new byte[CSRF_TOKEN_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Validates the CSRF token from the form submission against the session-stored token.
     * <p>
     * The token is consumed after validation (single-use) to prevent replay attacks.
     * Uses constant-time comparison to prevent timing attacks.
     * </p>
     *
     * @param session the HTTP session containing the expected token
     * @param submittedToken the token submitted with the form
     * @return true if the token is valid, false otherwise
     */
    private static boolean validateCsrfToken(HttpSession session, String submittedToken) {
        String expectedToken = SessionManager.getAttribute(session, SessionAttributes.CSRF_TOKEN);
        
        // Consume the token (single-use)
        SessionManager.removeAttribute(session, SessionAttributes.CSRF_TOKEN);
        
        if (expectedToken == null || submittedToken == null) {
            return false;
        }
        
        // Constant-time comparison to prevent timing attacks
        return MessageDigest.isEqual(
                expectedToken.getBytes(StandardCharsets.UTF_8),
                submittedToken.getBytes(StandardCharsets.UTF_8)
        );
    }

    /**
     * Logout endpoint.
     * <p>
     * Logs out the user by invalidating the session and redirects to the login page.
     * </p>
     *
     * @param session the HTTP session
     * @return redirect to login page
     */
    @GetMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.logout:/oauth2/logout}")
    public RedirectView logout(HttpSession session) {
        String userId = SessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER);
        if (userId != null) {
            logger.info("Logout for user: {}", userId);
        }

        session.invalidate();
        return new RedirectView("/login");
    }

    /**
     * Home page.
     * <p>
     * Displays the home page with user information if authenticated.
     * Redirects to login page if user is not authenticated.
     * </p>
     *
     * @param session the HTTP session
     * @return redirect to login page if not authenticated, otherwise "home" view
     */
    @GetMapping("/")
    public String home(HttpSession session) {
        if (SessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER) == null) {
            return "redirect:/login";
        }
        return "home";
    }
}