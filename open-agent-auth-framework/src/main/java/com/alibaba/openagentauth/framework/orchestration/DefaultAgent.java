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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.oauth2.par.AapParParameters;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.model.AuthorizationResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.OAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.par.client.OAuth2ParClient;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.token.aoat.AoatParser;
import com.alibaba.openagentauth.core.util.UriQueryBuilder;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.workload.client.WorkloadClient;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthenticationException;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkAuthorizationContextException;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.request.InitiateAuthorizationRequest;
import com.alibaba.openagentauth.framework.model.request.ParSubmissionRequest;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Default orchestration implementation for AI Agent.
 * <p>
 * This orchestrator coordinates the complete authorization workflow for AI agents,
 * including user authentication, workload creation, authorization requests, and tool execution.
 * It implements the AOA Bridge pattern for seamless authorization coordination.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>User Authentication:</b> Authenticates users via User IDP</li>
 *   <li><b>Workload Management:</b> Creates virtual workloads for each request</li>
 *   <li><b>Authorization Coordination:</b> Manages OAuth 2.0 authorization flow</li>
 *   <li><b>Token Management:</b> Caches and manages WIT and AOAT tokens</li>
 *   <li><b>Authorization Context Preparation:</b> Prepares authorization context for tool execution</li>
 * </ul>
 *
 * @see Agent
 * @since 1.0
 */
public class DefaultAgent implements Agent {

    // Logger
    private static final Logger logger = LoggerFactory.getLogger(DefaultAgent.class);

    // OAuth 2.0 and OIDC constants
    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String SCOPE_OPENID_PROFILE = "openid profile";
    private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    private static final String AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt";
    
    // Token expiration constants
    private static final long WPT_EXPIRATION_SECONDS = 300; // 5 minutes for WPT
    private static final long DEFAULT_TOKEN_EXPIRATION_SECONDS = 3600; // 1 hour default expiration

    // URL path constants
    private static final String OAUTH2_AUTHORIZE_PATH = "/oauth2/authorize";

    // Custom parameter names
    private static final String PARAM_REQUEST_URI = "request_uri";

    // HTTP header names
    private static final String HEADER_WORKLOAD_IDENTITY = "X-Workload-Identity";
    private static final String HEADER_WORKLOAD_PROOF = "X-Workload-Proof";

    // Client name prefix
    private static final String CLIENT_NAME_PREFIX = "Agent Workload: ";

    private final WorkloadClient workloadClient;
    private final TokenService tokenService;
    private final WitValidator witValidator;
    private final IdTokenValidator idTokenValidator;
    private final OAuth2ParClient parClient;
    private final OAuth2DcrClient dcrClient;
    private final OAuth2TokenClient userAuthenticationTokenClient;
    private final OAuth2TokenClient agentOperationAuthorizationTokenClient;
    private final AapParJwtGenerator aapParJwtGenerator;
    private final String authorizationServerUrl;
    private final String agentUserIdpUrl;
    private final String clientId;
    private final String oAuthCallbacksRedirectUri;

    /**
     * Creates a new AgentOrchestrator.
     *
     * @param workloadClient the Agent IDP HTTP client
     * @param tokenService the token service
     * @param witValidator the WIT validator (optional, if not provided WIT validation will be skipped)
     * @param parClient the PAR client
     * @param dcrClient the DCR client
     * @param userAuthenticationTokenClient the token client for user authentication OIDC flow
     * @param aapParJwtGenerator the AAP PAR-JWT generator
     * @param authorizationServerUrl the authorization server URL
     * @param agentUserIdpUrl the agent user IDP URL
     * @param clientId the OAuth client ID
     * @param oAuthCallbacksRedirectUri the OAuth callbacks redirect URI
     */
    public DefaultAgent(WorkloadClient workloadClient,
                        TokenService tokenService,
                        WitValidator witValidator,
                        IdTokenValidator idTokenValidator,
                        OAuth2ParClient parClient,
                        OAuth2DcrClient dcrClient,
                        OAuth2TokenClient userAuthenticationTokenClient,
                        OAuth2TokenClient agentOperationAuthorizationTokenClient,
                        AapParJwtGenerator aapParJwtGenerator,
                        String authorizationServerUrl,
                        String agentUserIdpUrl,
                        String clientId,
                        String oAuthCallbacksRedirectUri) {

        // Validate parameters using concise null checks
        this.workloadClient = ValidationUtils.validateNotNull(workloadClient, "Agent IDP HTTP client");
        this.idTokenValidator = ValidationUtils.validateNotNull(idTokenValidator, "Id token validator");
        this.tokenService = ValidationUtils.validateNotNull(tokenService, "Token service");
        this.parClient = ValidationUtils.validateNotNull(parClient, "PAR client");
        this.dcrClient = ValidationUtils.validateNotNull(dcrClient, "DCR client");
        this.userAuthenticationTokenClient = ValidationUtils.validateNotNull(userAuthenticationTokenClient, "User authentication token client");
        this.agentOperationAuthorizationTokenClient = ValidationUtils.validateNotNull(agentOperationAuthorizationTokenClient, "Agent operation authorization token client");
        this.aapParJwtGenerator = ValidationUtils.validateNotNull(aapParJwtGenerator, "AAP PAR-JWT generator");
        
        // Validate String parameters
        this.authorizationServerUrl = ValidationUtils.validateNotEmpty(authorizationServerUrl, "Authorization server URL");
        this.agentUserIdpUrl = ValidationUtils.validateNotEmpty(agentUserIdpUrl, "Agent User IDP URL");
        this.clientId = ValidationUtils.validateNotEmpty(clientId, "Client ID");
        this.oAuthCallbacksRedirectUri = ValidationUtils.validateNotEmpty(oAuthCallbacksRedirectUri, "OAuth callbacks redirect URI");

        // Set optional witValidator
        this.witValidator = witValidator;
        if (witValidator == null) {
            logger.warn("WIT validator not provided, WIT validation will be skipped");
        }

        logger.info("AgentOrchestrator initialized with authorization server: {} and agent user IDP: {}", 
                authorizationServerUrl, agentUserIdpUrl);
    }

    /**
     * Initiates the authorization workflow for AI agents.
     *
     * @param request the initiate authorization request
     * @return the authorization URL
     */
    @Override
    public String initiateAuthorization(InitiateAuthorizationRequest request) {
        
        // Validate parameters
        ValidationUtils.validateNotNull(request, "Initiate authorization request");
        ValidationUtils.validateNotEmpty(request.getState(), "State parameter");

        logger.debug("Initiating authorization with redirect URI: {}", request.getRedirectUri());

        // Build authorization URL with OIDC parameters using UriQueryBuilder
        // This ensures proper URL encoding and prevents injection attacks
        try {
            String queryString = new UriQueryBuilder()
                    .addEncoded("response_type", RESPONSE_TYPE_CODE)
                    .addEncoded("client_id", clientId)
                    .addEncoded("redirect_uri", request.getRedirectUri())
                    .addEncoded("scope", SCOPE_OPENID_PROFILE)
                    .addEncoded("state", request.getState())
                    .build();

            String authorizationUrl = agentUserIdpUrl + OAUTH2_AUTHORIZE_PATH + "?" + queryString;
            logger.info("Authorization initiated with state: {}", request.getState());
            return authorizationUrl;
            
        } catch (Exception e) {
            logger.error("Failed to build authorization URL", e);
            throw new IllegalArgumentException("Failed to build authorization URL: " + e.getMessage(), e);
        }
    }

    /**
     * Exchanges the authorization code for an ID Token via the Agent User IDP.
     * <p>
     * This method handles <b>only</b> the User Authentication flow (OIDC Authorization Code Flow).
     * It exchanges the authorization code with the Agent User IDP for an ID Token per
     * OIDC Core 1.0 Section 3.1.3.3.
     * </p>
     * <p>
     * Agent Operation Authorization flow is handled separately by
     * {@link #handleAuthorizationCallback(AuthorizationResponse)}, which exchanges the
     * authorization code with the Authorization Server for an AOAT.
     * </p>
     *
     * @param request the exchange code request
     * @return the authentication response containing the ID Token
     * @throws FrameworkAuthenticationException if authentication fails
     */
    @Override
    public AuthenticationResponse exchangeCodeForToken(ExchangeCodeForTokenRequest request) throws FrameworkAuthenticationException {
        
        // Validate parameters
        ValidationUtils.validateNotNull(request, "Exchange code request");

        logger.debug("Exchanging authorization code for ID Token via Agent User IDP");

        try {
            // Build token request for User Authentication flow
            TokenRequest tokenRequest = TokenRequest.builder()
                    .grantType(GRANT_TYPE_AUTHORIZATION_CODE)
                    .code(request.getCode())
                    .redirectUri(request.getRedirectUri())
                    .clientId(request.getClientId())
                    .build();

            // Exchange code for token using the user authentication token client
            TokenResponse tokenResponse = userAuthenticationTokenClient.exchangeCodeForToken(tokenRequest);

            // Extract ID Token per OIDC Core 1.0 Section 3.1.3.3
            String idToken = tokenResponse.getIdToken();
            if (idToken == null) {
                throw new FrameworkAuthenticationException(
                        "Token response does not contain id_token. "
                        + "Ensure the authorization request scope includes 'openid' "
                        + "and the IDP is OIDC-compliant (OIDC Core 1.0 Section 3.1.3.3).");
            }

            logger.info("Token exchange completed successfully, id_token received");

            // Build and return authentication response with ID Token
            long expiresIn = tokenResponse.getExpiresIn() != null ? tokenResponse.getExpiresIn().intValue() : DEFAULT_TOKEN_EXPIRATION_SECONDS;
            return AuthenticationResponse.builder()
                    .success(true)
                    .idToken(idToken)
                    .tokenType(tokenResponse.getTokenType())
                    .expiresIn(expiresIn)
                    .build();
            
        } catch (FrameworkAuthenticationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to exchange authorization code for ID Token", e);
            throw new FrameworkAuthenticationException("Failed to exchange authorization code for ID Token", e);
        }
    }

    /**
     * Issues a Workload Identity Token (WIT) based on the provided request.
     * <p>
     * This method implements the WIMSE protocol for issuing Workload Identity Tokens.
     * It validates the agent-user binding proposal and operation context to ensure
     * proper authorization before issuing the WIT.
     * </p>
     *
     * @param request the issue WIT request containing operation context and agent-user binding proposal
     * @return the workload context containing the issued WIT and associated credentials
     * @throws WorkloadCreationException if WIT issuance fails
     */
    @Override
    public WorkloadContext issueWorkloadIdentityToken(IssueWitRequest request) throws WorkloadCreationException {

        // Validate parameters
        ValidationUtils.validateNotNull(request, "Issue WIT request");
        ValidationUtils.validateNotNull(request.getContext(), "Operation request context");
        ValidationUtils.validateNotNull(request.getProposal(), "Agent user binding proposal");

        logger.debug("Issuing WIT for request with context: {}", request.getContext());

        try {
            // Step 1: Generate key pair on Agent side
            ECKey keyPair = new ECKeyGenerator(Curve.P_256)
                .keyID(generateKeyId())
                .generate();

            String publicKey = keyPair.toPublicJWK().toJSONString();
            String privateKey = keyPair.toJSONString();

            // Step 2: Build IssueWitRequest with the public key
            // Merge the public key into the request
            IssueWitRequest issueWitRequestWithPublicKey = IssueWitRequest.builder()
                .context(request.getContext())
                .proposal(request.getProposal())
                .publicKey(publicKey)
                .oauthClientId(request.getOauthClientId())
                .build();

            // Step 3: Call workloadClient.issueWit(IssueWitRequest) to get WIT
            // This method automatically handles workload creation and WIT issuance
            IssueWitResponse witResponse = workloadClient.issueWit(issueWitRequestWithPublicKey);

            // Step 4: Build workload context from WIT response
            WorkloadContext workloadContext = buildWorkloadContext(
                witResponse.getWit(),
                publicKey,
                privateKey,
                request.getProposal().getUserIdentityToken(),
                request.getOauthClientId()
            );

            logger.info("WIT issued successfully: {} for user: {}", workloadContext.getWorkloadId(), workloadContext.getUserId());
            return workloadContext;

        } catch (JOSEException e) {
            logger.error("Failed to generate key pair for workload", e);
            throw new WorkloadCreationException("Failed to generate key pair", e);
        } catch (WorkloadCreationException |
                 WorkloadNotFoundException e) {
            logger.error("Failed to issue WIT via HTTP", e);
            throw new WorkloadCreationException("Failed to issue WIT", e);
        } catch (Exception e) {
            logger.error("Failed to issue WIT", e);
            throw new WorkloadCreationException("Failed to issue WIT", e);
        }
    }

    /**
     * Registers an OAuth client for the given workload via Dynamic Client Registration (RFC 7591).
     * <p>
     * After successful registration, the returned {@code client_id} is stored in the
     * {@link WorkloadContext#getOauthClientId()} field for use in subsequent PAR and
     * Token requests. Since {@code WorkloadContext} is immutable, a new instance is
     * created with the {@code oauthClientId} populated.
     * </p>
     *
     * @param workloadContext the workload context
     * @return a new WorkloadContext with the DCR-assigned oauthClientId populated
     * @throws FrameworkAuthorizationException if authorization fails
     */
    @Override
    public WorkloadContext registerOAuthClient(WorkloadContext workloadContext) throws FrameworkAuthorizationException {
        
        // Validate parameters
        ValidationUtils.validateNotNull(workloadContext, "Workload context");

        logger.debug("Registering OAuth client for workload: {}", workloadContext.getWorkloadId());

        try {
            // Build DCR request with WIT as authentication (RFC 7591)
            DcrRequest dcrRequest = DcrRequest.builder()
                    .redirectUris(List.of(oAuthCallbacksRedirectUri))
                    .clientName(CLIENT_NAME_PREFIX + workloadContext.getWorkloadId())
                    .grantTypes(List.of(GRANT_TYPE_AUTHORIZATION_CODE))
                    .tokenEndpointAuthMethod(AUTH_METHOD_PRIVATE_KEY_JWT)
                    .build();

            // Submit DCR request
            DcrResponse dcrResponse = dcrClient.registerClient(dcrRequest);
            String registeredClientId = dcrResponse.getClientId();
            logger.info("OAuth client registered: {} for workload: {}", registeredClientId, 
                    workloadContext.getWorkloadId());
            
            // Return a new WorkloadContext with the DCR-assigned client_id
            return WorkloadContext.builder()
                    .workloadId(workloadContext.getWorkloadId())
                    .userId(workloadContext.getUserId())
                    .wit(workloadContext.getWit())
                    .publicKey(workloadContext.getPublicKey())
                    .privateKey(workloadContext.getPrivateKey())
                    .expiresAt(workloadContext.getExpiresAt())
                    .oauthClientId(registeredClientId)
                    .build();
            
        } catch (Exception e) {
            logger.error("Failed to register OAuth client", e);
            throw new FrameworkAuthorizationException("Failed to register OAuth client", e);
        }
    }

    /**
     * Submits a PAR request for the given workload.
     *
     * @param request the PAR submission request
     * @return the PAR response
     * @throws FrameworkAuthorizationException if authorization fails
     */
    @Override
    public ParResponse submitParRequest(ParSubmissionRequest request) throws FrameworkAuthorizationException {
        
        // Validate parameters
        ValidationUtils.validateNotNull(request, "PAR submission request");

        logger.debug("Submitting PAR request for workload: {}", request.getWorkloadContext().getWorkloadId());

        try {
            // Build PAR request
            ParRequest parRequest = buildParRequest(request);

            // Submit PAR request
            ParResponse parResponse = parClient.submitParRequest(parRequest);

            logger.info("PAR request submitted for workload, response: {}", parResponse);
            return parResponse;

        } catch (Exception e) {
            logger.error("Failed to submit PAR request", e);
            throw new FrameworkAuthorizationException("Failed to submit PAR request", e);
        }
    }

    /**
     * Generates an authorization URL with the given request URI.
     *
     * @param requestUri the request URI
     * @return the authorization URL
     */
    @Override
    public String generateAuthorizationUrl(String requestUri) {
        return generateAuthorizationUrl(requestUri, null);
    }
    
    /**
     * Generates an authorization URL with the given request URI and state parameter.
     *
     * @param requestUri the request URI
     * @param state the state parameter (optional)
     * @return the authorization URL
     */
    @Override
    public String generateAuthorizationUrl(String requestUri, String state) {

        // Validate parameters
        if (ValidationUtils.isNullOrEmpty(requestUri)) {
            throw new IllegalArgumentException("Request URI cannot be null or empty");
        }

        logger.debug("Generating authorization URL with request_uri: {}, state: {}", requestUri, state);

        // Build authorization URL with request_uri parameter using UriQueryBuilder
        UriQueryBuilder queryBuilder = new UriQueryBuilder().addEncoded(PARAM_REQUEST_URI, requestUri);
        
        // Add state parameter if provided
        if (!ValidationUtils.isNullOrEmpty(state)) {
            queryBuilder.addEncoded("state", state);
        }
        
        String queryString = queryBuilder.build();
        String authUrl = authorizationServerUrl + OAUTH2_AUTHORIZE_PATH + "?" + queryString;

        logger.info("Authorization URL generated: {}", authUrl);
        return authUrl;
    }

    /**
     * Handles the authorization callback and issues an AOAT.
     *
     * @param response the authorization response
     * @return the AOAT
     * @throws FrameworkAuthorizationException if authorization fails
     */
    @Override
    public AgentOperationAuthToken handleAuthorizationCallback(AuthorizationResponse response) throws FrameworkAuthorizationException {

        // Validate parameters
        ValidationUtils.validateNotNull(response, "Authorization response");

        logger.debug("Handling authorization callback");

        try {
            // Check if response is successful
            if (!response.isSuccess()) {
                throw new FrameworkAuthorizationException("Authorization response indicates failure: " + response.getError());
            }

            // Extract authorization code from AuthorizationResponse
            String code = response.getAuthorizationCode();
            if (ValidationUtils.isNullOrEmpty(code)) {
                throw new FrameworkAuthorizationException("Authorization code is missing");
            }

            // Use the DCR-registered client_id from the AuthorizationResponse if available,
            // falling back to the static clientId for backward compatibility.
            // This ensures the token exchange uses the same client_id that was bound
            // to the authorization code during the PAR/authorization flow.
            String effectiveClientId = !ValidationUtils.isNullOrEmpty(response.getClientId())
                    ? response.getClientId()
                    : clientId;
            logger.debug("Token exchange using client_id: {} (DCR: {})", effectiveClientId,
                    !ValidationUtils.isNullOrEmpty(response.getClientId()));

            TokenRequest tokenRequest = TokenRequest.builder()
                    .grantType(GRANT_TYPE_AUTHORIZATION_CODE)
                    .code(code)
                    .redirectUri(response.getRedirectUri())
                    .clientId(effectiveClientId)
                    .build();

            // Exchange code for AOAT using agent operation authorization token client
            TokenResponse tokenResponse = agentOperationAuthorizationTokenClient.exchangeCodeForToken(tokenRequest);

            // Parse AOAT from token response
            AgentOperationAuthToken aoat = parseAoatFromTokenResponse(tokenResponse);

            logger.info("Authorization callback handled successfully, AOAT issued");
            return aoat;

        } catch (Exception e) {
            logger.error("Failed to handle authorization callback", e);
            throw new FrameworkAuthorizationException("Failed to handle authorization callback", e);
        }
    }

    /**
     * Prepares the authorization context for the given workload.
     *
     * @param request the prepare authorization context request
     * @return the authorization context
     * @throws FrameworkAuthorizationContextException if authorization context preparation fails
     */
    @Override
    public AgentAuthorizationContext prepareAuthorizationContext(PrepareAuthorizationContextRequest request) throws FrameworkAuthorizationContextException {

        // Validate parameters
        ValidationUtils.validateNotNull(request, "Prepare authorization context request");

        logger.debug("Preparing authorization context for workload: {}", request.getWorkloadContext().getWorkloadId());

        try {
            // Generate WPT for tool execution with AOAT binding
            String wpt = generateWptForContext(request.getWorkloadContext(), request.getAoat());

            // Build additional headers
            HashMap<String, String> additionalHeaders = new HashMap<>();
            additionalHeaders.put(HEADER_WORKLOAD_IDENTITY, request.getWorkloadContext().getWit());
            additionalHeaders.put(HEADER_WORKLOAD_PROOF, wpt);

            //  Build authorization context
            logger.info("AWIT: {}", request.getAoat().getJwtString());
            AgentAuthorizationContext context = AgentAuthorizationContext.builder()
                    .wit(request.getWorkloadContext().getWit())
                    .wpt(wpt)
                    .aoat(request.getAoat().getJwtString())
                    .additionalHeaders(additionalHeaders)
                    .build();

            logger.info("Authorization context prepared for workload: {}", request.getWorkloadContext().getWorkloadId());
            return context;

        } catch (Exception e) {
            logger.error("Failed to prepare authorization context", e);
            throw new FrameworkAuthorizationContextException("Failed to prepare authorization context", e);
        }
    }

    /**
     * Clears the authorization context for the given workload.
     *
     * @param workloadContext the workload context
     */
    @Override
    public void clearAuthorizationContext(WorkloadContext workloadContext) {

        // Validate parameters
        ValidationUtils.validateNotNull(workloadContext, "Workload context");

        logger.debug("Clearing authorization context for workload: {}", workloadContext.getWorkloadId());

        try {
            // Revoke workload via HTTP
            workloadClient.revokeWorkload(workloadContext.getWorkloadId());
            logger.info("Authorization context cleared for workload: {}", workloadContext.getWorkloadId());

        } catch (Exception e) {
            logger.error("Failed to clear authorization context", e);
        }
    }

    /**
     * Builds a PAR request according to RFC 9126 and draft-liu-agent-operation-authorization-01 specification.
     * <p>
     * This method constructs a Pushed Authorization Request containing the PAR-JWT
     * with agent operation authorization details. Client authentication (e.g.,
     * {@code client_assertion} per RFC 7523) is handled by the
     * {@code OAuth2ClientAuthentication} strategy configured on the PAR client,
     * not by this method.
     * </p>
     * <p>
     * <b>Separation of Concerns:</b></p>
     * <ul>
     *   <li><b>This method:</b> Builds the authorization request content (PAR-JWT, scope, state, etc.)</li>
     *   <li><b>PAR Client:</b> Handles client authentication via pluggable {@code OAuth2ClientAuthentication}</li>
     * </ul>
     *
     * @param request the PAR submission request containing all required parameters
     * @return a constructed ParRequest object
     * @throws IllegalArgumentException if any required parameter is null or empty
     * @throws RuntimeException if the PAR request building fails
     */
    private ParRequest buildParRequest(ParSubmissionRequest request) {
        
        WorkloadContext workloadContext = request.getWorkloadContext();
        
        // Validate required parameters
        if (ValidationUtils.isNullOrEmpty(request.getUserIdentityToken())) {
            throw new IllegalArgumentException("User identity token cannot be null or empty");
        }
        ValidationUtils.validateNotNull(request.getOperationProposal(), "Operation proposal");
        ValidationUtils.validateNotNull(request.getContext(), "Operation request context");
        
        try {
            // Build AgentUserBindingProposal
            AgentUserBindingProposal agentUserBindingProposal = AgentUserBindingProposal.builder()
                    .userIdentityToken(request.getUserIdentityToken())
                    .agentWorkloadToken(workloadContext.getWit())
                    .deviceFingerprint(request.getContext().getDeviceFingerprint())
                    .build();

            // Use the context directly without defaults
            OperationRequestContext context = request.getContext();

            // Build AapParParameters
            long expirationSeconds = request.getExpirationSeconds() != null 
                    ? request.getExpirationSeconds() 
                    : DEFAULT_TOKEN_EXPIRATION_SECONDS;
            
            // Build the redirect URI for callback (must match the one registered in DCR)
            logger.debug("Using redirect URI: {}", oAuthCallbacksRedirectUri);

            // Use the DCR-registered client_id from WorkloadContext if available,
            // otherwise fall back to the static clientId (for backward compatibility)
            String effectiveClientId = !ValidationUtils.isNullOrEmpty(workloadContext.getOauthClientId())
                    ? workloadContext.getOauthClientId()
                    : clientId;

            AapParParameters parameters = AapParParameters.builder()
                    .agentUserBindingProposal(agentUserBindingProposal)
                    .evidence(request.getEvidence())
                    .operationProposal(request.getOperationProposal())
                    .context(context)
                    .expirationSeconds(expirationSeconds)
                    .userId(workloadContext.getUserId())
                    .clientId(effectiveClientId)
                    .redirectUri(oAuthCallbacksRedirectUri)
                    .state(request.getState())
                    .build();

            // Generate PAR-JWT using AapParJwtGenerator
            String parJwt = aapParJwtGenerator.generateParJwt(parameters);
            logger.debug("Generated PAR-JWT for workload: {}", workloadContext.getWorkloadId());

            // Build the PAR request with the DCR-registered client_id
            // Client authentication (client_assertion per RFC 7523) is handled by the
            // OAuth2ClientAuthentication strategy configured on the PAR client, following the
            // separation of concerns principle.
            ParRequest.Builder parRequestBuilder = ParRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .requestJwt(parJwt)
                    .clientId(effectiveClientId)
                    .redirectUri(oAuthCallbacksRedirectUri)
                    .scope(SCOPE_OPENID_PROFILE);

            // Add state parameter if provided
            if (!ValidationUtils.isNullOrEmpty(request.getState())) {
                parRequestBuilder.state(request.getState());
                logger.debug("State parameter added to PAR request: {}", request.getState());
            }

            ParRequest parRequest = parRequestBuilder.build();

            logger.debug("PAR request built for workload: {}", workloadContext.getWorkloadId());
            return parRequest;

        } catch (Exception e) {
            logger.error("Failed to build PAR request for workload: {}", workloadContext.getWorkloadId(), e);
            throw new RuntimeException("Failed to build PAR request", e);
        }
    }

    /**
     * Generates WPT for authorization context.
     */
    private String generateWptForContext(WorkloadContext workloadContext, AgentOperationAuthToken aoatToken) throws FrameworkTokenGenerationException {
        try {
            // Parse WIT from string
            TokenValidationResult<WorkloadIdentityToken> witResult = parseWit(workloadContext.getWit());
            if (!witResult.isValid()) {
                throw new FrameworkTokenGenerationException("Failed to parse WIT: " + witResult.getErrorMessage());
            }
            
            // Parse private key from WorkloadContext
            String privateKeyJson = workloadContext.getPrivateKey();
            if (ValidationUtils.isNullOrEmpty(privateKeyJson)) {
                throw new FrameworkTokenGenerationException("Private key not found in workload context");
            }
            
            // Convert private key JSON to JWK object
            JWK wptPrivateKey = JWK.parse(privateKeyJson);
            
            // Generate WPT with 5 minutes expiration using the private key from WIT's cnf.jwk
            // Optionally bind the WPT to the AOAT token if provided
            return tokenService.generateWptAsString(witResult.getToken(), wptPrivateKey, WPT_EXPIRATION_SECONDS, aoatToken);
            
        } catch (FrameworkTokenGenerationException e) {
            throw e;
        } catch (Exception e) {
            throw new FrameworkTokenGenerationException("Failed to generate WPT", e);
        }
    }

    /**
     * Helper method to parse WIT.
     * <p>
     * This method parses and validates a Workload Identity Token (WIT) string.
     * It uses the WitValidator to perform comprehensive validation according to the WIMSE protocol,
     * including signature verification, expiration check, trust domain validation, and required claims validation.
     * </p>
     * <p>
     * If WitValidator is not provided, this method will return a failure result.
     * In production environments, WitValidator should always be configured for proper security.
     * </p>
     *
     * @param wit the WIT JWT string to parse
     * @return a TokenValidationResult containing the parsed WIT or validation error
     */
    private TokenValidationResult<WorkloadIdentityToken> parseWit(String wit) {

        // Check if WIT is provided
        if (ValidationUtils.isNullOrEmpty(wit)) {
            return TokenValidationResult.failure("WIT cannot be null or empty");
        }

        // Check if WitValidator is configured
        if (witValidator == null) {
            logger.error("WIT validator not configured - cannot validate WIT");
            return TokenValidationResult.failure("WIT validator not configured");
        }

        try {
            // Use WitValidator to perform comprehensive validation
            TokenValidationResult<WorkloadIdentityToken> validationResult = witValidator.validate(wit);
            
            if (validationResult.isValid()) {
                logger.debug("WIT validation successful for subject: {}", validationResult.getToken().getSubject());
            } else {
                logger.warn("WIT validation failed: {}", validationResult.getErrorMessage());
            }
            return validationResult;

        } catch (ParseException e) {
            logger.error("Failed to parse WIT JWT format", e);
            return TokenValidationResult.failure("Invalid WIT format");
        } catch (Exception e) {
            logger.error("Failed to parse WIT", e);
            return TokenValidationResult.failure("Failed to parse WIT: " + e.getMessage());
        }
    }

    /**
     * Generates a unique key ID for the JWK key pair.
     * <p>
     * This key ID is used as the 'kid' (Key ID) field in the JWK header
     * and will be included in the WIT's 'cnf.jwk.kid' claim.
     * </p>
     * <p>
     * According to draft-liu-agent-operation-authorization-01, the agent_identity.id
     * MUST be a UUID-based URI (e.g., "urn:uuid:550e8400-e29b-41d4-a716-446655440000").
     * </p>
     *
     * @return the generated key ID as a UUID-based URI
     */
    private String generateKeyId() {
        return "urn:uuid:" + UUID.randomUUID();
    }

    /**
     * Parses an AOAT from a token response.
     *
     * @param tokenResponse the token response
     * @return the parsed AOAT
     */
    private AgentOperationAuthToken parseAoatFromTokenResponse(TokenResponse tokenResponse) {
        try {
            String aoatJwt = tokenResponse.getAccessToken();
            SignedJWT signedJwt = SignedJWT.parse(aoatJwt);
            return new AoatParser().parse(signedJwt);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse AOAT from token response", e);
        }
    }

    /**
     * Builds a workload context from an WIT response.
     * <p>
     * This method extracts and validates information from the WIT response and
     * constructs a WorkloadContext object containing the workload identity,
     * user identity, and cryptographic credentials.
     * </p>
     * <p>
     * The process includes:
     * </p>
     * <ol>
     *   <li>Parsing and validating the WIT from the WIT response</li>
     *   <li>Extracting the workload ID from the WIT's subject claim</li>
     *   <li>Validating the user identity token and extracting the user ID</li>
     *   <li>Building the workload context with all required information</li>
     * </ol>
     *
     * @param wit the WIT
     * @param publicKey the public key associated with the workload
     * @param privateKey the private key associated with the workload
     * @param userIdentityToken the user identity token for authentication
     * @param oauthClientId the OAuth client ID (optional, will use default if null)
     * @return the constructed workload context
     * @throws WorkloadCreationException if WIT validation or user ID extraction fails
     */
    private WorkloadContext buildWorkloadContext(String wit,
                                                  String publicKey,
                                                  String privateKey,
                                                  String userIdentityToken,
                                                  String oauthClientId) throws WorkloadCreationException {
        
        // Parse WIT to extract workload information according to WIMSE standard
        // WIT is a self-contained token with all identity and lifecycle information
        TokenValidationResult<WorkloadIdentityToken> witResult = parseWit(wit);
        if (!witResult.isValid()) {
            throw new WorkloadCreationException("Failed to validate WIT: " + witResult.getErrorMessage());
        }

        // Extract workloadId from WIT's subject claim (sub)
        // According to WIMSE draft-ietf-wimse-workload-creds, sub is the Workload Identifier
        String workloadId = witResult.getToken().getSubject();
        
        // Extract userId from the user identity token
        // According to OpenID Connect, the subject (sub) claim contains the user identifier
        String userId;
        try {
            // Validate the ID token and extract the user ID
            // Use the client ID from the request or default to the configured client ID
            String expectedAudience = oauthClientId != null ? oauthClientId : clientId;
            IdToken idToken = idTokenValidator.validate(
                userIdentityToken,
                agentUserIdpUrl,
                expectedAudience
            );
            userId = idToken.getClaims().getSub();
            if (ValidationUtils.isNullOrEmpty(userId)) {
                throw new WorkloadCreationException("User ID not found in identity token");
            }
        } catch (Exception e) {
            logger.error("Failed to validate user identity token", e);
            throw new WorkloadCreationException("Failed to validate user identity token", e);
        }

        // Build workload context with information from WIT and user ID token
        // expiresAt is extracted from WIT's exp claim to ensure consistency with the token
        return WorkloadContext.builder()
            .workloadId(workloadId)
            .userId(userId)
            .wit(wit)
            .publicKey(publicKey)
            .privateKey(privateKey)
            .expiresAt(witResult.getToken().getExpirationTime().toInstant())
            .build();
    }
}
