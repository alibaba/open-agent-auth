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
import com.alibaba.openagentauth.core.util.ValidationUtils;
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
    private final SessionMappingBizService sessionMappingBizService;
    private final String callbackEndpoint;
    
    public OAuth2CallbackService(
            FrameworkOAuth2TokenClient oauth2TokenClient,
            SessionMappingBizService sessionMappingBizService,
            String callbackEndpoint) {
        this.oauth2TokenClient = oauth2TokenClient;
        this.sessionMappingBizService = sessionMappingBizService;
        this.callbackEndpoint = callbackEndpoint;
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
            
            // Parse state
            OAuth2StateHandler stateHandler = new OAuth2StateHandler();
            OAuth2StateHandler.StateInfo stateInfo = stateHandler.parse(request.getState());
            
            // Build redirect URI
            String redirectUri = buildRedirectUri(request.getHttpRequest());
            
            // Perform token exchange
            TokenResponse tokenResponse = performTokenExchange(
                    request.getCode(),
                    redirectUri,
                    clientId,
                    request.getState()
            );
            
            // Handle based on flow type
            return handleFlow(stateInfo, tokenResponse, request.getHttpRequest());
            
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
            case AGENT_OPERATION_AUTH ->
                    handleAgentOperationAuthorizationFlow(stateInfo, tokenResponse, session, request);
            default -> handleDefaultFlow(tokenResponse, session, request);
        };
    }
    
    /**
     * Handle user authentication flow.
     */
    private OAuth2CallbackResult handleUserAuthenticationFlow(OAuth2StateHandler.StateInfo stateInfo,
                                                        TokenResponse tokenResponse,
                                                        HttpSession session,
                                                        HttpServletRequest request) {
        logger.info("User authentication flow: setting session authentication state");

        // Get or create request session
        HttpSession requestSession = request.getSession(true);

        // Restore or create session
        HttpSession restoredSession = restoreOrCreateSession(
            session, 
            stateInfo.getSessionId(), 
            false, 
            request
        );
        
        // If original session not found, use request session for authentication flow
        if (restoredSession == null) {
            logger.warn("Original session not found, using request session for authentication flow");
            restoredSession = requestSession;
        } else {
            // Set authentication state
            setAuthenticationStateFromToken(restoredSession, tokenResponse.getAccessToken());
            
            // Sync session attributes
            syncSessionAttributes(restoredSession, requestSession);
            
            // Clean up state
            SessionManager.removeAttribute(restoredSession, SessionAttributes.OAUTH_STATE);
            
            // Remove session mapping
            sessionMappingBizService.removeSession(stateInfo.getSessionId());
        }
        
        // Check for pending authorization request
        return handlePendingAuthorizationRequest(restoredSession, requestSession);
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
     * Handle default flow.
     */
    private OAuth2CallbackResult handleDefaultFlow(TokenResponse tokenResponse,
                                             HttpSession session,
                                             HttpServletRequest request) {
        logger.info("Default flow: treating as user authentication");
        
        // Create new session
        HttpSession restoredSession = restoreOrCreateSession(session, null, true, request);
        
        if (restoredSession != null) {
            SessionManager.setAttribute(restoredSession, SessionAttributes.ID_TOKEN, tokenResponse.getAccessToken());
            
            // Extract user ID
            String userId = extractUserIdFromIdToken(tokenResponse.getAccessToken());
            if (userId != null) {
                SessionManager.setAttribute(restoredSession, SessionAttributes.AUTHENTICATED_USER, userId);
            } else {
                SessionManager.setAttribute(restoredSession, SessionAttributes.AUTHENTICATED_USER, "authenticated");
            }
        }
        
        return OAuth2CallbackResult.redirect("/");
    }
    
    /**
     * Handle pending authorization request.
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
        
        return OAuth2CallbackResult.redirect("/");
    }

    /**
     * Perform token exchange.
     */
    private TokenResponse performTokenExchange(String code, String redirectUri, String clientId,String state) throws OAuth2TokenException {
        // Build request for framework OAuth2TokenClient
        ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                .code(code)
                .state(clientId)  // Use clientId as state for framework interface
                .redirectUri(redirectUri)
                .clientId(clientId)
                .state(state)
                .build();

        // Use OAuth2TokenClient to exchange code for token
        AuthenticationResponse authResponse = oauth2TokenClient.exchangeCodeForToken(request);

        // return token response
        return TokenResponse.builder()
                .accessToken(authResponse.getIdToken())
                .tokenType(authResponse.getTokenType())
                .expiresIn(authResponse.getExpiresIn())
                .build();
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
