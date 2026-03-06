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
package com.alibaba.openagentauth.framework.web.callback;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * OAuth2 callback processing service.
 * <p>
 * Encapsulates complete OAuth2 callback processing business logic, including:
 * </p>
 * <ul>
 *   <li>Request validation</li>
 *   <li>Token exchange</li>
 *   <li>Session management</li>
 *   <li>Flow routing</li>
 * </ul>
 * <p>
 * <b>Design Pattern:</b> Service Pattern</p>
 *
 * @since 1.0
 */
public class OAuth2CallbackService {
    
    private static final Logger logger = LoggerFactory.getLogger(OAuth2CallbackService.class);
    
    private final FrameworkOAuth2TokenClient oauth2TokenClient;
    private final Agent agent;
    private final SessionMappingBizService sessionMappingBizService;
    private final OAuth2AuthorizationRequestStorage authorizationRequestStorage;
    private final String callbackEndpoint;

    /**
     * Creates a new OAuth2CallbackService without Agent support.
     * <p>
     * This constructor is used when the service is deployed in a non-Agent role
     * (e.g., Authorization Server), where Agent operation authorization callbacks
     * are not expected. Uses a default in-memory authorization request storage.
     * </p>
     *
     * @param oauth2TokenClient the framework-level token client for user authentication
     * @param sessionMappingBizService the session mapping business service
     * @param callbackEndpoint the callback endpoint path
     */
    public OAuth2CallbackService(
            FrameworkOAuth2TokenClient oauth2TokenClient,
            SessionMappingBizService sessionMappingBizService,
            String callbackEndpoint) {
        this(oauth2TokenClient, null, sessionMappingBizService,
                new InMemoryOAuth2AuthorizationRequestStorage(), callbackEndpoint);
    }

    /**
     * Creates a new OAuth2CallbackService with Agent support.
     * <p>
     * This constructor is used when the service is deployed in the Agent role,
     * where Agent operation authorization callbacks need to be handled via
     * {@link Agent#handleAuthorizationCallback(AuthorizationResponse)}.
     * Uses a default in-memory authorization request storage.
     * </p>
     *
     * @param oauth2TokenClient the framework-level token client for user authentication
     * @param agent the Agent actor for handling Agent operation authorization callbacks (nullable)
     * @param sessionMappingBizService the session mapping business service
     * @param callbackEndpoint the callback endpoint path
     */
    public OAuth2CallbackService(
            FrameworkOAuth2TokenClient oauth2TokenClient,
            Agent agent,
            SessionMappingBizService sessionMappingBizService,
            String callbackEndpoint) {
        this(oauth2TokenClient, agent, sessionMappingBizService,
                new InMemoryOAuth2AuthorizationRequestStorage(), callbackEndpoint);
    }

    /**
     * Creates a new OAuth2CallbackService with full configuration.
     * <p>
     * This constructor allows specifying a custom {@link OAuth2AuthorizationRequestStorage}
     * for distributed deployments (e.g., Redis-backed storage).
     * </p>
     *
     * @param oauth2TokenClient the framework-level token client for user authentication
     * @param agent the Agent actor for handling Agent operation authorization callbacks (nullable)
     * @param sessionMappingBizService the session mapping business service
     * @param authorizationRequestStorage the storage for resolving authorization requests
     * @param callbackEndpoint the callback endpoint path
     */
    public OAuth2CallbackService(
            FrameworkOAuth2TokenClient oauth2TokenClient,
            Agent agent,
            SessionMappingBizService sessionMappingBizService,
            OAuth2AuthorizationRequestStorage authorizationRequestStorage,
            String callbackEndpoint) {
        this.oauth2TokenClient = oauth2TokenClient;
        this.agent = agent;
        this.sessionMappingBizService = sessionMappingBizService;
        this.authorizationRequestStorage = authorizationRequestStorage != null
                ? authorizationRequestStorage
                : new InMemoryOAuth2AuthorizationRequestStorage();
        this.callbackEndpoint = callbackEndpoint;
    }
    
    /**
     * Returns the authorization request storage used by this service.
     * <p>
     * This method allows other components (e.g., interceptors, executors) to share
     * the same storage instance for storing and resolving authorization requests.
     * </p>
     *
     * @return the authorization request storage
     */
    public OAuth2AuthorizationRequestStorage getAuthorizationRequestStorage() {
        return authorizationRequestStorage;
    }

    /**
     * Handle OAuth2 callback.
     *
     * @param request callback request
     * @param clientId client ID
     * @return processing result
     */
    public OAuth2CallbackResult handleCallback(OAuth2CallbackRequest request, String clientId) {
        try {
            // Validate request
            OAuth2CallbackRequestValidator validator = new OAuth2CallbackRequestValidator();
            OAuth2CallbackRequestValidator.ValidationResult validationResult = validator.validate(request, clientId);
            
            if (!validationResult.isSuccess()) {
                return OAuth2CallbackResult.error(
                    validationResult.getStatusCode(),
                    validationResult.toErrorResponseMap()
                );
            }
            
            // Resolve flow type from authorization request storage
            OAuth2StateHandler stateHandler = new OAuth2StateHandler(authorizationRequestStorage);
            OAuth2StateHandler.StateInfo stateInfo = stateHandler.resolve(request.getState());
            
            // Build redirect URI
            String redirectUri = buildRedirectUri(request.getHttpRequest());
            
            // Route to flow-specific processing based on flow type
            // User Authentication flow: exchanges code for ID Token via FrameworkOAuth2TokenClient
            // Agent Operation Authorization flow: exchanges code for AOAT via Agent.handleAuthorizationCallback()
            return switch (stateInfo.getFlowType()) {
                case AGENT_OPERATION_AUTH -> {
                    TokenResponse tokenResponse = performAgentAuthTokenExchange(
                            request.getCode(), redirectUri, request.getState());
                    yield handleFlow(stateInfo, tokenResponse, request.getHttpRequest());
                }
                default -> {
                    TokenResponse tokenResponse = performUserAuthTokenExchange(
                            request.getCode(), redirectUri, clientId, request.getState());
                    yield handleFlow(stateInfo, tokenResponse, request.getHttpRequest());
                }
            };
            
        } catch (OAuth2TokenException e) {
            logger.error("Token exchange failed: {}", e.getMessage(), e);
            return OAuth2CallbackResult.error(400, Map.of(
                "error", e.getErrorCode(),
                "error_description", e.getMessage()
            ));
        } catch (Exception e) {
            logger.error("Unexpected error during callback: {}", e.getMessage(), e);
            return OAuth2CallbackResult.error(500, Map.of(
                "error", "server_error",
                "error_description", "Internal server error"
            ));
        }
    }
    
    /**
     * Handle based on flow type.
     */
    private OAuth2CallbackResult handleFlow(OAuth2StateHandler.StateInfo stateInfo, 
                                     TokenResponse tokenResponse,
                                     HttpServletRequest request) {

        HttpSession session = request.getSession(false);
        return switch (stateInfo.getFlowType()) {
            case USER_AUTHENTICATION -> handleUserAuthenticationFlow(stateInfo, tokenResponse, session, request);
            case AGENT_OPERATION_AUTH -> handleAgentOperationAuthorizationFlow(stateInfo, tokenResponse, session, request);
            default -> handleDefaultFlow(tokenResponse, session, request);
        };
    }
    
    /**
     * Handle user authentication flow.
     * <p>
     * Sets authentication state on the current request session using the ID Token
     * received from the User IDP. Session management is handled through standard
     * HTTP session cookies — no session restoration from the state parameter is needed.
     * </p>
     * <p>
     * This follows the approach used by mainstream OAuth2/OIDC implementations
     * (Spring Authorization Server, Keycloak) where the state parameter is used
     * solely for CSRF protection and flow routing.
     * </p>
     */
    private OAuth2CallbackResult handleUserAuthenticationFlow(OAuth2StateHandler.StateInfo stateInfo,
                                                        TokenResponse tokenResponse,
                                                        HttpSession session,
                                                        HttpServletRequest request) {
        logger.info("User authentication flow: setting session authentication state");

        // Use the current request session for authentication state.
        // If session cookie names are correctly configured (unique per service),
        // this session should be the same one that stored REDIRECT_URI before the IDP redirect.
        HttpSession requestSession = request.getSession(true);
        logger.debug("User auth callback using session: {}, isNew: {}", requestSession.getId(), requestSession.isNew());

        // Set authentication state from the ID Token
        setAuthenticationStateFromToken(requestSession, tokenResponse.getAccessToken());

        // Clean up OAuth state from session
        SessionManager.removeAttribute(requestSession, SessionAttributes.OAUTH_STATE);

        // Check for pending authorization request (stored in session before redirect)
        return handlePendingAuthorizationRequest(requestSession, requestSession);
    }
    
    /**
     * Handle Agent operation authorization flow.
     */
    private OAuth2CallbackResult handleAgentOperationAuthorizationFlow(OAuth2StateHandler.StateInfo stateInfo,
                                                                TokenResponse tokenResponse,
                                                                HttpSession session,
                                                                HttpServletRequest request) {
        logger.info("Agent Operation Authorization flow: storing token in session");
        
        // Restore or create session
        HttpSession restoredSession = restoreOrCreateSession(
            session, 
            stateInfo.getSessionId(), 
            true, 
            request
        );
        
        // Store Agent OA Token
        SessionManager.setAttribute(restoredSession, SessionAttributes.AGENT_OA_TOKEN, tokenResponse.getAccessToken());
        
        // Extract user ID
        String userId = extractUserIdFromIdToken(
            SessionManager.getAttribute(restoredSession, SessionAttributes.ID_TOKEN)
        );
        
        // Set authentication state
        SessionManager.setAttribute(restoredSession, SessionAttributes.AUTHENTICATED_USER, Objects.requireNonNullElse(userId, "authenticated"));
        
        // Sync to request session
        HttpSession requestSession = request.getSession(true);
        SessionManager.setAttribute(requestSession, SessionAttributes.AGENT_OA_TOKEN, tokenResponse.getAccessToken());
        setAuthenticationStateFromUserId(requestSession, userId);
        
        // Sync conversation history
        Object conversationHistory = SessionManager.getAttribute(restoredSession, SessionAttributes.CONVERSATION_HISTORY);
        if (conversationHistory != null) {
            @SuppressWarnings("unchecked")
            List<Object> conversationList = (List<Object>) conversationHistory;
            SessionManager.setAttribute(requestSession, SessionAttributes.CONVERSATION_HISTORY, conversationList);
        }
        
        // Sync all session attributes
        syncSessionAttributes(restoredSession, requestSession);
        
        // Remove session mapping
        if (stateInfo.getSessionId() != null) {
            sessionMappingBizService.removeSession(stateInfo.getSessionId());
        }
        
        return OAuth2CallbackResult.redirect("/");
    }
    
    /**
     * Handle default flow — treated as user authentication using the current request session.
     * <p>
     * This flow is triggered when the state parameter cannot be resolved to a known
     * authorization request (e.g., due to repository instance mismatch). It still sets
     * authentication state and attempts to redirect to the originally requested URL
     * stored in the session, falling back to {@code /admin} if no redirect URI is found.
     * </p>
     */
    private OAuth2CallbackResult handleDefaultFlow(TokenResponse tokenResponse,
                                             HttpSession session,
                                             HttpServletRequest request) {
        logger.info("Default flow: treating as user authentication");

        HttpSession requestSession = request.getSession(true);
        setAuthenticationStateFromToken(requestSession, tokenResponse.getAccessToken());

        return handlePendingAuthorizationRequest(requestSession, requestSession);
    }
    
    /**
     * Handle pending authorization request.
     * <p>
     * Checks both the restored session and the current request session for a stored
     * {@code REDIRECT_URI}. If found, redirects to that URL. If not found, logs a warning
     * and redirects to the admin dashboard ({@code /admin}) as a safe fallback, since
     * the root path ({@code /}) may not have a handler on all service roles (e.g.,
     * Authorization Server has no root page).
     * </p>
     */
    private OAuth2CallbackResult handlePendingAuthorizationRequest(HttpSession restoredSession, 
                                                             HttpSession requestSession) {
        String pendingUrl = SessionManager.getAttribute(restoredSession, SessionAttributes.REDIRECT_URI);
        
        if (pendingUrl != null && !pendingUrl.isBlank()) {
            logger.info("Found pending authorization request in restored session, redirecting to: {}", pendingUrl);
            SessionManager.removeAttribute(restoredSession, SessionAttributes.REDIRECT_URI);
            return OAuth2CallbackResult.redirect(pendingUrl);
        }
        
        pendingUrl = SessionManager.getAttribute(requestSession, SessionAttributes.REDIRECT_URI);
        if (pendingUrl != null && !pendingUrl.isBlank()) {
            logger.info("Found pending authorization request in request session, redirecting to: {}", pendingUrl);
            SessionManager.removeAttribute(requestSession, SessionAttributes.REDIRECT_URI);
            return OAuth2CallbackResult.redirect(pendingUrl);
        }
        
        logger.warn("No pending authorization request found in session after user authentication. "
                + "This may indicate a session cookie collision between services on the same domain. "
                + "Ensure each service has a unique session cookie name configured via "
                + "'open-agent-auth.security.session-cookie.name'.");
        return OAuth2CallbackResult.redirect("/");
    }

    /**
     * Perform token exchange for user authentication flow.
     * <p>
     * Exchanges the authorization code for an ID Token via the framework OAuth2 token client.
     * This method is specifically designed for the User Authentication flow where the
     * expected response is an OIDC ID Token per OIDC Core 1.0 Section 3.1.3.3.
     * </p>
     *
     * @param code the authorization code
     * @param redirectUri the redirect URI
     * @param clientId the client ID
     * @param state the state parameter
     * @return the token response containing the ID Token
     * @throws OAuth2TokenException if token exchange fails
     */
    private TokenResponse performUserAuthTokenExchange(String code, String redirectUri, String clientId, String state) throws OAuth2TokenException {

        ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                .code(code)
                .redirectUri(redirectUri)
                .clientId(clientId)
                .state(state)
                .build();

        AuthenticationResponse authResponse = oauth2TokenClient.exchangeCodeForToken(request);

        String idToken = authResponse.getIdToken();
        return TokenResponse.builder()
                .accessToken(idToken)
                .tokenType(authResponse.getTokenType())
                .expiresIn(authResponse.getExpiresIn())
                .idToken(idToken)
                .build();
    }

    /**
     * Perform token exchange for Agent operation authorization flow.
     * <p>
     * Delegates to {@link Agent#handleAuthorizationCallback(AuthorizationResponse)} to exchange
     * the authorization code for an Agent Operation Authorization Token (AOAT). This ensures
     * proper semantic separation: user authentication uses {@code exchangeCodeForToken()},
     * while Agent operation authorization uses {@code handleAuthorizationCallback()}.
     * </p>
     *
     * @param code the authorization code
     * @param redirectUri the redirect URI
     * @param state the state parameter
     * @return the token response containing the AOAT as access_token
     * @throws OAuth2TokenException if token exchange fails or Agent is not configured
     */
    private TokenResponse performAgentAuthTokenExchange(String code, String redirectUri, String state) throws OAuth2TokenException {

        if (agent == null) {
            throw OAuth2TokenException.serverError(
                    "Agent operation authorization callback received but Agent is not configured. "
                    + "Ensure the application is deployed with the Agent role enabled.");
        }

        try {
            // Build AuthorizationResponse per RFC 6749 Section 4.1.2
            AuthorizationResponse authorizationResponse = AuthorizationResponse.builder()
                    .authorizationCode(code)
                    .redirectUri(redirectUri)
                    .state(state)
                    .build();

            // Delegate to Agent.handleAuthorizationCallback() which returns AOAT
            AgentOperationAuthToken aoat = agent.handleAuthorizationCallback(authorizationResponse);

            return TokenResponse.builder()
                    .accessToken(aoat.getJwtString())
                    .tokenType("Bearer")
                    .expiresIn(aoat.getExpirationTime() != null
                            ? (aoat.getExpirationTime().getEpochSecond() - System.currentTimeMillis() / 1000)
                            : 3600)
                    .build();

        } catch (OAuth2TokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to exchange authorization code for AOAT via Agent", e);
            throw OAuth2TokenException.serverError("Failed to exchange code for AOAT: " + e.getMessage());
        }
    }

    /**
     * Build redirect URI.
     */
    private String buildRedirectUri(HttpServletRequest request) {
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();

        StringBuilder redirectUri = new StringBuilder();
        redirectUri.append(scheme).append("://").append(serverName);

        if ((scheme.equals("http") && serverPort != 80) ||
                (scheme.equals("https") && serverPort != 443)) {
            redirectUri.append(":").append(serverPort);
        }

        redirectUri.append(contextPath).append(callbackEndpoint);

        return redirectUri.toString();
    }
    
    /**
     * Restore or create session.
     * <p>
     * This method attempts to restore the original session from SessionMappingBizService
     * to preserve session history. If unable to restore, creates a new session or returns null.
     * </p>
     *
     * @param currentSession current session
     * @param sessionId session ID to restore
     * @param createIfNotFound whether to create new session if not found
     * @param request HTTP request
     * @return restored or created session
     */
    private HttpSession restoreOrCreateSession(HttpSession currentSession, String sessionId, 
                                                      boolean createIfNotFound, HttpServletRequest request) {
        // If no session ID provided
        if (sessionId == null) {
            if (createIfNotFound && currentSession == null) {
                logger.warn("Session ID not provided and current session is null, creating new session");
                return request.getSession(true);
            }
            return currentSession;
        }
        
        // If current session ID matches, return directly
        if (currentSession != null && currentSession.getId().equals(sessionId)) {
            logger.debug("Current session matches expected session ID: {}", sessionId);
            return currentSession;
        }
        
        // Attempt to restore session from SessionMappingBizService
        logger.warn("Session not found in cookies, attempting to restore from SessionMappingBizService: {}", sessionId);
        HttpSession restoredSession = sessionMappingBizService.restoreSession(sessionId, createIfNotFound, request);
        
        if (restoredSession == null && !createIfNotFound) {
            logger.error("Session not found in SessionMappingBizService: {}", sessionId);
            return null;
        }
        
        if (restoredSession != null) {
            logger.info("Session restored from SessionMappingBizService: {}", sessionId);
        }
        
        return restoredSession;
    }
    
    /**
     * Sync session attributes.
     */
    private void syncSessionAttributes(HttpSession source, HttpSession target) {
        java.util.Enumeration<String> names = source.getAttributeNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            Object value = source.getAttribute(name);
            if (value != null) {
                target.setAttribute(name, value);
            }
        }
    }
    
    /**
     * Set authentication state from token.
     */
    private void setAuthenticationStateFromToken(HttpSession session, String idToken) {
        SessionManager.setAttribute(session, SessionAttributes.ID_TOKEN, idToken);
        String userId = extractUserIdFromIdToken(idToken);
        SessionManager.setAttribute(session, SessionAttributes.AUTHENTICATED_USER, Objects.requireNonNullElse(userId, "authenticated"));
    }

    /**
     * Set authentication state from user ID.
     */
    private void setAuthenticationStateFromUserId(HttpSession session, String userId) {
        SessionManager.setAttribute(session, SessionAttributes.AUTHENTICATED_USER, Objects.requireNonNullElse(userId, "authenticated"));
    }

    /**
     * Extract user ID from ID Token.
     */
    private String extractUserIdFromIdToken(String idToken) {
        if (ValidationUtils.isNullOrEmpty(idToken)) {
            return null;
        }
        
        try {
            SignedJWT signedJwt = SignedJWT.parse(idToken);
            JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();
            String subject = claimsSet.getSubject();
            
            if (!ValidationUtils.isNullOrEmpty(subject)) {
                return subject;
            }
            
            return null;
        } catch (ParseException e) {
            logger.error("Failed to parse ID Token: {}", e.getMessage(), e);
            return null;
        }
    }
}
