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
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

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
@ConditionalOnExpression("'${open-agent-auth.roles.agent-user-idp.enabled:false}' == 'true' or '${open-agent-auth.roles.as-user-idp.enabled:false}' == 'true'")
public class UserLoginController {

    /**
     * The logger for the IDP Login controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(UserLoginController.class);

    /**
     * The user registry for authentication.
     */
    private final UserRegistry userRegistry;

    /**
     * The session mapping business service for managing session mappings.
     */
    private final SessionMappingBizService sessionMappingBizService;

    /**
     * Creates a new IDP Login controller.
     *
     * @param userRegistry the user registry for authentication
     * @param sessionMappingBizService the session mapping business service
     */
    public UserLoginController(UserRegistry userRegistry, SessionMappingBizService sessionMappingBizService) {
        this.userRegistry = userRegistry;
        this.sessionMappingBizService = sessionMappingBizService;
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
            HttpSession session,
            RedirectAttributes redirectAttributes,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            HttpServletRequest request) {
        
        logger.info("Login attempt for user: {}", username);

        try {
            // Authenticate user using core module's UserRegistry
            String subject = userRegistry.authenticate(username, password);
            
            // Build user object from registry data
            // Note: password is set to empty string as it's already validated
            // and should not be stored in session for security reasons
            DefaultSessionUser user = DefaultSessionUser.builder()
                    .subject(subject)
                    .username(username)
                    .password("") // Password already validated, not stored in session
                    .name(userRegistry.getName(username))
                    .email(userRegistry.getEmail(username))
                    .preferredUsername(username)
                    .build();

            // Store user ID in current session using SessionManager
            SessionManager.setAttribute(session, SessionAttributes.AUTHENTICATED_USER, subject);
            logger.info("Login successful for user: {}", username);

            // Try to restore the original session from SessionMappingBizService
            // This is needed when SameSite cookie policies cause session loss during redirects
            String sessionId = session.getId();
            HttpSession originalSession = sessionMappingBizService.restoreSession(sessionId, false, request);
            
            String sessionRedirectUri = null;
            if (originalSession != null) {
                // Get redirect URI from the original session
                sessionRedirectUri = SessionManager.getAttribute(originalSession, SessionAttributes.REDIRECT_URI);
                
                // Sync the user ID to the original session
                SessionManager.setAttribute(originalSession, SessionAttributes.AUTHENTICATED_USER, subject);
                
                // Clear the redirect URI from original session after use
                if (sessionRedirectUri != null) {
                    SessionManager.removeAttribute(originalSession, SessionAttributes.REDIRECT_URI);
                    logger.info("Found redirect URI in original session: {}", sessionRedirectUri);
                }
                
                // Clean up the session mapping
                sessionMappingBizService.removeSession(sessionId);
            } else {
                // Fallback: check current session
                sessionRedirectUri = SessionManager.getAttribute(session, SessionAttributes.REDIRECT_URI);
                if (sessionRedirectUri != null) {
                    // Clear the redirect URI from session after use
                    SessionManager.removeAttribute(session, SessionAttributes.REDIRECT_URI);
                    logger.info("Found redirect URI in current session: {}", sessionRedirectUri);
                }
            }
            
            if (sessionRedirectUri != null) {
                logger.info("Redirecting to authorization endpoint: {}", sessionRedirectUri);
                return new RedirectView(sessionRedirectUri);
            }
            
            // Fallback to parameter-based approach for backward compatibility
            if (redirectUri != null && !redirectUri.isBlank()) {
                logger.info("Redirecting to authorization endpoint with parameters from form: {}", redirectUri);
                return new RedirectView(redirectUri);
            }
            
            // Fallback: redirect to home page if no redirect_uri provided
            logger.info("No redirect_uri provided, redirecting to home page");
            return new RedirectView("/");
            
        } catch (Exception e) {
            logger.warn("Login failed for user: {}, error: {}", username, e.getMessage());
            redirectAttributes.addFlashAttribute("error", "Invalid username or password");
            return new RedirectView("/login");
        }
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