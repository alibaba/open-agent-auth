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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.audit.builder.AuditEventBuilder;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtParser;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.util.UriQueryBuilder;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Orchestrator for OAuth 2.0 authorization flow processing.
 * <p>
 * This class coordinates the complete authorization workflow, delegating specific
 * flow logic to strategy implementations. It follows the Orchestrator Pattern,
 * providing a single entry point for authorization processing while allowing
 * different flows (PAR, Traditional, etc.) to be plugged in.
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Single Responsibility:</b> Only orchestrates the flow, delegates flow-specific logic</li>
 *   <li><b>Open/Closed:</b> New flows can be added without modifying this class</li>
 *   <li><b>Dependency Inversion:</b> Depends on abstractions (Strategy interface)</li>
 * </ul>
 *
 * @since 1.0
 */
public class AuthorizationOrchestrator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationOrchestrator.class);

    /**
     * List of available authorization flow strategies.
     * <p>
     * This list contains all registered strategies that can handle different
     * authorization flows (e.g., PAR flow, traditional authorization code flow).
     * The appropriate strategy is selected at runtime based on the request parameters.
     * </p>
     * <p>
     * <b>Note:</b> This list is immutable to prevent concurrent modification issues.
     * </p>
     */
    private final List<AuthorizationFlowStrategy> strategies;

    /**
     * Interceptor for user authentication operations.
     * <p>
     * This interceptor is responsible for:
     * </p>
     * <ul>
     *   <li>Authenticating users based on the HTTP request</li>
     *   <li>Providing the login URL for redirecting unauthenticated users</li>
     *   <li>Retrieving the authenticated user's subject identifier</li>
     * </ul>
     */
    private final UserAuthenticationInterceptor userAuthenticationInterceptor;

    /**
     * Provider for consent page rendering and handling.
     * <p>
     * This provider is responsible for:
     * </p>
     * <ul>
     *   <li>Determining if user consent is required</li>
     *   <li>Rendering the consent page with operation details</li>
     *   <li>Processing user consent responses (approve/deny)</li>
     * </ul>
     */
    private final ConsentPageProvider consentPageProvider;

    /**
     * Service for session mapping and management.
     * <p>
     * This service provides cross-service session synchronization, allowing
     * the authorization server to track and manage user sessions across
     * different components of the system.
     * </p>
     */
    private final SessionMappingBizService sessionMappingBizService;

    /**
     * OAuth 2.0 Pushed Authorization Request (PAR) server.
     * <p>
     * This component implements RFC 9126 (OAuth 2.0 Pushed Authorization Requests).
     * It is responsible for:
     * </p>
     * <ul>
     *   <li>Storing PAR requests with a unique request URI</li>
     *   <li>Retrieving PAR requests by request URI</li>
     *   <li>Managing PAR request lifecycle and expiration</li>
     * </ul>
     * <p>
     * <b>Note:</b> This field is optional and can be null if PAR flow is not supported.
     * </p>
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
     */
    private final OAuth2ParServer parServer;

    /**
     * Parser for Agent Operation Authorization Protocol (AOAP) PAR JWTs.
     * <p>
     * This parser is responsible for:
     * </p>
     * <ul>
     *   <li>Parsing JWT-formatted PAR requests</li>
     *   <li>Extracting Agent Operation Authorization claims</li>
     *   <li>Validating JWT structure and signatures</li>
     * </ul>
     * <p>
     * The parsed claims are used to display detailed information about the proposed
     * operation in the consent page, allowing users to make informed authorization decisions.
     * </p>
     * <p>
     * <b>Note:</b> This field is optional and can be null if PAR flow is not supported.
     * </p>
     */
    private final AapParJwtParser parJwtParser;

    /**
     * Audit service for logging authorization events.
     * <p>
     * This service is responsible for:
     * </p>
     * <ul>
     *   <li>Logging authorization requests and decisions</li>
     *   <li>Tracking user consent and denials</li>
     *   <li>Maintaining a comprehensive audit trail</li>
     * </ul>
     * <p>
     * <b>Note:</b> This field is optional. If null, audit logging will be disabled.
     * </p>
     */
    private final AuditService auditService;

    /**
     * Creates a new authorization orchestrator.
     *
     * @param strategies the list of available authorization flow strategies (must not be null)
     * @param userAuthenticationInterceptor the user authentication interceptor (can be null if user authentication is not required)
     * @param consentPageProvider the consent page provider (must not be null)
     * @param sessionMappingBizService the session mapping service (must not be null)
     * @param parServer the PAR server (can be null if PAR is not used)
     * @param parJwtParser the PAR JWT parser (can be null if PAR is not used)
     * @param auditService the audit service (can be null if audit logging is not used)
     * @throws IllegalArgumentException if required parameters are null
     */
    public AuthorizationOrchestrator(
            List<AuthorizationFlowStrategy> strategies,
            UserAuthenticationInterceptor userAuthenticationInterceptor,
            ConsentPageProvider consentPageProvider,
            SessionMappingBizService sessionMappingBizService,
            OAuth2ParServer parServer,
            AapParJwtParser parJwtParser,
            AuditService auditService
    ) {
        this.strategies = List.copyOf(ValidationUtils.validateNotNull(strategies, "strategies"));
        this.userAuthenticationInterceptor = userAuthenticationInterceptor;
        this.consentPageProvider = ValidationUtils.validateNotNull(consentPageProvider, "consentPageProvider");
        this.sessionMappingBizService = ValidationUtils.validateNotNull(sessionMappingBizService, "sessionMappingBizService");
        this.parServer = parServer;
        this.parJwtParser = parJwtParser;
        this.auditService = auditService;
    }

    /**
     * Processes an authorization request.
     * <p>
     * This method orchestrates the complete authorization flow:
     * </p>
     <ol>
     *   <li>Checks if this is a consent form submission (action parameter)</li>
     *   <li>Selects the appropriate strategy based on request parameters</li>
     *   <li>Parses and validates the authorization request</li>
     *   <li>Authenticates the user</li>
     *   <li>Checks if consent is required</li>
     *   <li>Issues authorization code or renders consent page</li>
     * </ol>
     *
     * @param request the HTTP request
     * @return authorization result (redirect, error, or consent page)
     * @throws OAuth2AuthorizationException if authorization fails
     */
    public AuthorizationResult processAuthorization(HttpServletRequest request) {
        logger.info("Processing authorization request: {}", request.getRequestURI());

        // Step 1: Check if this is a consent form submission (action can be "consent", "approve", or "deny")
        String action = request.getParameter("action");
        if (action != null && !action.isBlank()) {
            logger.info("Detected consent form submission with action: {}", action);
            return processConsentSubmission(request);
        }

        // Step 2: Select strategy
        AuthorizationFlowStrategy strategy = selectStrategy(request);
        if (strategy == null) {
            logger.warn("No strategy found for authorization request");
            return AuthorizationResult.error("invalid_request", "Missing required parameters");
        }

        // Step 3: Parse request
        AuthorizationRequestContext context = strategy.parseRequest(request);

        // Step 3.5: Extract PAR JWT claims if applicable
        if ("PAR".equals(context.getFlowType()) && parServer != null && parJwtParser != null) {
            context = extractParJwtClaims(context);
        }

        // Step 4: Validate request
        strategy.validateRequest(context);

        // Step 5: Authenticate user
        String subject = authenticateUser(request);
        if (subject == null) {
            return handleUnauthenticated(request, context);
        }

        // Step 6: Check consent
        if (needsConsent(request, subject, context)) {
            return renderConsentPage(request, subject, context);
        }

        // Step 7: Issue authorization code
        AuthorizationCodeResult result = strategy.issueCode(context, subject);

        // Step 8: Build redirect URI
        String redirectUri = strategy.buildRedirectUri(result);

        logger.info("Redirecting to client callback: {}", redirectUri);
        
        // Audit: Log authorization granted
        logAuthorizationGranted(request, context, subject, result);

        return AuthorizationResult.redirect(redirectUri);
    }

    /**
     * Processes consent form submission.
     *
     * @param request the HTTP request
     * @return authorization result (redirect or error)
     * @throws OAuth2AuthorizationException if consent processing fails
     */
    public AuthorizationResult processConsentSubmission(HttpServletRequest request) {
        logger.info("Processing consent submission");

        // Select strategy
        AuthorizationFlowStrategy strategy = selectStrategy(request);
        if (strategy == null) {
            logger.warn("No strategy found for consent submission");
            return AuthorizationResult.error("invalid_request", "Missing required parameters");
        }

        // Parse request
        AuthorizationRequestContext context = strategy.parseRequest(request);

        // Validate request
        strategy.validateRequest(context);

        // Authenticate user
        String subject = authenticateUser(request);
        if (subject == null) {
            return AuthorizationResult.unauthorized("login_required", "User authentication required");
        }

        // Handle consent response
        boolean approved = consentPageProvider.handleConsentResponse(request);
        if (!approved) {
            logger.info("User denied consent");
            
            // Audit: Log authorization denied
            logAuthorizationDenied(request, context, subject);
            
            // Get redirect URI from authorization context
            String redirectUri = getRedirectUri(context);
            String state = context.getState();
            
            // Build error redirect URI according to OAuth 2.0 RFC 6749 Section 4.1.2.1
            String errorRedirectUri = AuthorizationUriBuilder.buildErrorRedirectUri(
                    redirectUri, 
                    "access_denied", 
                    "User denied the authorization request", 
                    state
            );
            
            // Clean up session to prevent using stale authorization parameters
            // when user navigates back and tries to login again
            HttpSession session = request.getSession(false);
            if (session != null) {
                SessionManager.removeAttribute(session, SessionAttributes.REDIRECT_URI);
                logger.debug("Cleared REDIRECT_URI from session after deny");
            }
            
            return AuthorizationResult.redirect(errorRedirectUri);
        }

        // Issue authorization code
        AuthorizationCodeResult result = strategy.issueCode(context, subject);

        // Build redirect URI
        String redirectUri = strategy.buildRedirectUri(result);

        logger.info("Redirecting to client callback: {}", redirectUri);
        
        // Audit: Log authorization granted after consent
        logAuthorizationGranted(request, context, subject, result);

        return AuthorizationResult.redirect(redirectUri);
    }

    /**
     * Selects the appropriate strategy for the given request.
     *
     * @param request the HTTP request
     * @return the selected strategy, or null if no strategy matches
     */
    private AuthorizationFlowStrategy selectStrategy(HttpServletRequest request) {
        return strategies.stream()
                .filter(strategy -> strategy.supports(request))
                .findFirst()
                .orElse(null);
    }

    /**
     * Authenticates the user.
     *
     * @param request the HTTP request
ç     * @return the authenticated user subject, or null if not authenticated or interceptor not available
     */
    private String authenticateUser(HttpServletRequest request) {
        if (userAuthenticationInterceptor == null) {
            logger.debug("User authentication interceptor not available, skipping authentication");
            return null;
        }
        String subject = userAuthenticationInterceptor.authenticate(request);
        logger.debug("User authentication result: {}", subject);
        return subject;
    }

    /**
     * Handles unauthenticated users by redirecting to login.
     *
     * @param request the HTTP request
     * @param context the authorization request context
     * @return authorization result (redirect to login or error)
     */
    private AuthorizationResult handleUnauthenticated(HttpServletRequest request, AuthorizationRequestContext context) {
        // If no authentication interceptor is available, return unauthorized
        if (userAuthenticationInterceptor == null) {
            logger.debug("User authentication interceptor not available, returning unauthorized");
            return AuthorizationResult.unauthorized("login_required", "User authentication required");
        }

        // Get login URL
        String loginUrl = userAuthenticationInterceptor.getLoginUrl(request);
        if (loginUrl == null) {
            return AuthorizationResult.unauthorized("login_required", "User authentication required");
        }

        logger.info("User not authenticated, redirecting to login: {}", loginUrl);

        // Build authorization URL for redirect after login
        String authorizationUrl = buildAuthorizationUrl(request, context);

        // Store in session using SessionManager
        HttpSession session = request.getSession(true);
        SessionManager.setAttribute(session, SessionAttributes.REDIRECT_URI, authorizationUrl);

        // Store session mapping
        sessionMappingBizService.storeSession(session.getId(), session);
        logger.debug("Session stored in SessionMappingBizService: {}", session.getId());

        // Redirect to login
        return AuthorizationResult.redirect(loginUrl);
    }

    /**
     * Builds the authorization URL for redirect after login.
     * <p>
     * For PAR flow, redirects to the consent endpoint (/oauth2/consent) to avoid
     * re-processing the authorization flow. This ensures that the correct ConsentPageProvider
     * is used (OAuth2ConsentController uses the provider from AuthorizationServerAutoConfiguration).
     * For traditional flow, redirects back to the authorization endpoint (/oauth2/authorize).
     * </p>
     *
     * @param request the HTTP request
     * @param context the authorization request context
     * @return the authorization URL
     */
    private String buildAuthorizationUrl(HttpServletRequest request, AuthorizationRequestContext context) {

        // Build base URL - use consent endpoint for PAR flow, authorization endpoint for traditional flow
        String baseUrl;
        if ("PAR".equals(context.getFlowType())) {
            baseUrl = "/oauth2/consent";
        } else {
            baseUrl = request.getRequestURI();
        }

        // Build query parameters using UriQueryBuilder
        UriQueryBuilder queryBuilder = new UriQueryBuilder();

        if ("PAR".equals(context.getFlowType())) {
            // For PAR flow, use requestUri parameter (matches OAuth2ConsentController)
            queryBuilder.addEncoded("requestUri", context.getRequestUri());
        } else {
            // For traditional flow, use standard OAuth 2.0 parameters
            queryBuilder.addEncoded("response_type", context.getResponseType())
                        .addEncoded("client_id", context.getClientId())
                        .addEncoded("redirect_uri", context.getRedirectUri());
            // Add scope if present
            if (!ValidationUtils.isNullOrEmpty(context.getScope())) {
                queryBuilder.addEncoded("scope", context.getScope());
            }
        }

        // Add state if present
        if (!ValidationUtils.isNullOrEmpty(context.getState())) {
            queryBuilder.addEncoded("state", context.getState());
        }

        // Build authorization URL
        String authorizationUrl = baseUrl + "?" + queryBuilder.build();
        logger.debug("Built authorization URL for redirect after login (flow: {}): {}", context.getFlowType(), authorizationUrl);
        return authorizationUrl;
    }

    /**
     * Checks if user consent is required.
     *
     * @param request the HTTP request
     * @param subject the authenticated user subject
     * @param context the authorization request context
     * @return true if consent is required, false otherwise
     */
    private boolean needsConsent(HttpServletRequest request, String subject, AuthorizationRequestContext context) {

        // Get client ID and scope
        String clientId = context.getClientId();
        String scope = context.getScope();

        // Check if consent is required
        boolean consentRequired = consentPageProvider.isConsentRequired(request, subject, clientId, scope);
        logger.debug("Consent required: {}", consentRequired);
        return consentRequired;
    }

    /**
     * Renders the consent page.
     *
     * @param request the HTTP request
     * @param subject the authenticated user subject
     * @param context the authorization request context
     * @return authorization result (consent page)
     */
    private AuthorizationResult renderConsentPage(HttpServletRequest request, String subject, AuthorizationRequestContext context) {

        // Get client ID and scope
        String clientId = context.getClientId();
        String scope = context.getScope();

        logger.info("Rendering consent page for user: {}, client: {}, with PAR claims: {}", 
                subject, clientId, context.getParJwtClaims() != null);

        Object consentPage;
        if ("PAR".equals(context.getFlowType()) && context.getParJwtClaims() != null) {
            // Render consent page with PAR JWT claims for Agent Operation Authorization
            consentPage = consentPageProvider.renderConsentPage(
                    request, context.getRequestUri(), subject, clientId, scope, context.getParJwtClaims()
            );
        } else if ("PAR".equals(context.getFlowType())) {
            // Render consent page for PAR flow without claims
            consentPage = consentPageProvider.renderConsentPage(
                    request, context.getRequestUri(), subject, clientId, scope
            );
        } else {
            // Render consent page for traditional flow
            consentPage = consentPageProvider.renderConsentPageTraditional(
                    request, subject, clientId, context.getRedirectUri(), context.getState(), scope
            );
        }

        // Return consent page
        return AuthorizationResult.consentPage(consentPage);
    }

    /**
     * Extracts PAR JWT claims from the authorization request.
     * <p>
     * This method extracts PAR JWT claims for display purposes (no validation needed
     * as it was already validated during PAR submission). The claims are used to
     * display detailed information about the proposed operation in the consent page.
     * </p>
     *
     * @param context the authorization request context
     * @return a new context with PAR JWT claims, or the original context if extraction fails
     */
    private AuthorizationRequestContext extractParJwtClaims(AuthorizationRequestContext context) {
        try {
            // Retrieve PAR request
            ParRequest parRequest = parServer.retrieveRequest(context.getRequestUri());

            // Fail-fast: return early if no JWT in PAR request
            if (parRequest.getRequestJwt() == null || parRequest.getRequestJwt().isBlank()) {
                return context;
            }

            // Parse PAR JWT
            ParJwtClaims parJwtClaims = parJwtParser.parse(parRequest.getRequestJwt());

            // Fail-fast: return early if JWT parsing fails
            if (parJwtClaims == null) {
                return context;
            }

            // Build new context with PAR JWT claims
            logger.info("Successfully extracted PAR JWT claims for display with JTI: {}", parJwtClaims.getJwtId());
            return AuthorizationRequestContext.builder()
                    .flowType(context.getFlowType())
                    .clientId(context.getClientId())
                    .scope(context.getScope())
                    .requestUri(context.getRequestUri())
                    .state(context.getState())
                    .parJwtClaims(parJwtClaims)
                    .build();

        } catch (Exception e) {
            logger.error("Error extracting PAR JWT claims for display", e);
            return context;
        }
    }

    /**
     * Gets the redirect URI from the authorization request context.
     * <p>
     * For PAR flow, retrieves the redirect URI from the PAR request.
     * For traditional flow, returns the redirect URI from the request context.
     * </p>
     *
     * @param context the authorization request context
     * @return the redirect URI
     * @throws OAuth2AuthorizationException if redirect URI cannot be retrieved
     */
    private String getRedirectUri(AuthorizationRequestContext context) {
        if ("PAR".equals(context.getFlowType())) {
            if (parServer == null) {
                throw new OAuth2AuthorizationException(
                        OAuth2RfcErrorCode.SERVER_ERROR,
                        "PAR server is not configured"
                );
            }
            ParRequest parRequest = parServer.retrieveRequest(context.getRequestUri());
            return parRequest.getRedirectUri();
        } else {
            return context.getRedirectUri();
        }
    }

    /**
     * Logs an authorization granted event.
     *
     * @param request the HTTP request
     * @param context the authorization request context
     * @param subject the authenticated user subject
     * @param result the authorization code result
     */
    private void logAuthorizationGranted(HttpServletRequest request, 
                                          AuthorizationRequestContext context, 
                                          String subject,
                                          AuthorizationCodeResult result) {
        if (auditService == null) {
            logger.debug("Audit service is not available, skipping audit logging for AUTHORIZATION_GRANTED");
            return;
        }

        try {
            String sessionId = request.getSession(false) != null ? request.getSession(false).getId() : null;
            String clientIp = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");

            logger.debug("Logging AUTHORIZATION_GRANTED event for user {}, client: {}", subject, context.getClientId());
            
            auditService.logEventAsync(AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Authorization code granted successfully")
                    .userId(subject)
                    .sessionId(sessionId)
                    .requestId(result.getCode())
                    .clientIpAddress(clientIp)
                    .userAgent(userAgent)
                    .addData("client_id", context.getClientId())
                    .addData("redirect_uri", result.getRedirectUri())
                    .addData("state", result.getState())
                    .addData("flow_type", context.getFlowType())
                    .addData("request_uri", context.getRequestUri())
                    .build());
            
            logger.info("Audit event logged: AUTHORIZATION_GRANTED for user {}, client: {}", subject, context.getClientId());
        } catch (Exception e) {
            logger.error("Failed to log audit event for authorization granted", e);
        }
    }

    /**
     * Logs an authorization denied event.
     *
     * @param request the HTTP request
     * @param context the authorization request context
     * @param subject the authenticated user subject
     */
    private void logAuthorizationDenied(HttpServletRequest request, AuthorizationRequestContext context, String subject) {

        if (auditService == null) {
            logger.debug("Audit service is not available, skipping audit logging for AUTHORIZATION_DENIED");
            return;
        }

        try {
            String sessionId = request.getSession(false) != null ? request.getSession(false).getId() : null;
            String clientIp = request.getRemoteAddr();
            String userAgent = request.getHeader("User-Agent");

            logger.debug("Logging AUTHORIZATION_DENIED event for user {}, client: {}", subject, context.getClientId());
            
            auditService.logEventAsync(AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_DENIED)
                    .severity(AuditSeverity.LOW)
                    .message("User denied authorization request")
                    .userId(subject)
                    .sessionId(sessionId)
                    .clientIpAddress(clientIp)
                    .userAgent(userAgent)
                    .addData("client_id", context.getClientId())
                    .addData("flow_type", context.getFlowType())
                    .addData("request_uri", context.getRequestUri())
                    .build());
            
            logger.info("Audit event logged: AUTHORIZATION_DENIED for user {}, client: {}", subject, context.getClientId());
        } catch (Exception e) {
            logger.error("Failed to log audit event for authorization denied", e);
        }
    }
}