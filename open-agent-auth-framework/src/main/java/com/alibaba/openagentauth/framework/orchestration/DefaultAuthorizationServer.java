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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.DefaultOAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.InMemoryOAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.token.aoat.AoatParser;
import com.alibaba.openagentauth.core.token.common.TokenValidationResult;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkParProcessingException;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.model.request.AoatIssuanceRequest;
import com.alibaba.openagentauth.framework.actor.AuthorizationServer;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;



/**
 * Default orchestration implementation for Authorization Server.
 * <p>
 * This orchestrator coordinates the complete authorization workflow, including PAR processing,
 * user authentication, policy registration, and AOAT issuance. It implements the zero-trust
 * authorization model with identity consistency verification.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>PAR Processing:</b> Handles Pushed Authorization Requests</li>
 *   <li><b>Authorization Flow:</b> Manages OAuth 2.0 authorization code flow</li>
 *   <li><b>Identity Verification:</b> Validates WIT and user identity tokens</li>
 *   <li><b>Policy Management:</b> Registers and evaluates OPA policies</li>
 *   <li><b>Token Issuance:</b> Issues Agent Operation Authorization Tokens</li>
 * </ul>
 *
 * @see AuthorizationServer
 * @since 1.0
 */
public class DefaultAuthorizationServer implements AuthorizationServer, FrameworkOAuth2TokenClient {

    // Logger
    private static final Logger logger = LoggerFactory.getLogger(DefaultAuthorizationServer.class);
    
    // OAuth 2.0 constants
    private static final String AUTH_METHOD_PRIVATE_KEY_JWT = "private_key_jwt";
    
    // Parameter names
    private static final String PARAM_WIT = "wit";

    private final OAuth2ParServer parServer;
    private final OAuth2DcrServer dcrServer;
    private final WitValidator witValidator;
    private final OAuth2TokenClient oAuth2TokenClient;
    private final OAuth2TokenServer oAuth2TokenServer;
    private final AoatParser aoatParser;

    /**
     * Creates a new AuthorizationServerOrchestrator with full configuration.
     *
     * @param parServer the PAR server for processing authorization requests
     * @param dcrClientStore the DCR client store (optional, will use in-memory if null)
     * @param oAuth2TokenClient the OAuth 2.0 token client for code exchange
     * @param oAuth2TokenServer the OAuth 2.0 token server for AOAT generation
     * @param keyManager the key manager for WIT verification (optional, required if WIT validation is enabled)
     * @param witVerificationKeyId the key ID for WIT verification (optional)
     * @param expectedTrustDomain the expected trust domain for WIT validation (optional)
     */
    public DefaultAuthorizationServer(OAuth2ParServer parServer,
                                      OAuth2DcrClientStore dcrClientStore,
                                      OAuth2TokenClient oAuth2TokenClient,
                                      OAuth2TokenServer oAuth2TokenServer,
                                      KeyManager keyManager,
                                      String witVerificationKeyId,
                                      String expectedTrustDomain) {
        // Validate arguments using concise null checks
        this.parServer = ValidationUtils.validateNotNull(parServer, "PAR server");
        this.oAuth2TokenClient = ValidationUtils.validateNotNull(oAuth2TokenClient, "OAuth2TokenClient");
        this.oAuth2TokenServer = ValidationUtils.validateNotNull(oAuth2TokenServer, "OAuth2TokenServer");
        this.aoatParser = new AoatParser();
        
        // Initialize DCR server with in-memory store if not provided
        OAuth2DcrClientStore clientStore = dcrClientStore != null ? dcrClientStore : new InMemoryOAuth2DcrClientStore();
        this.dcrServer = new DefaultOAuth2DcrServer(clientStore);
        
        // Initialize WIT validator if key manager and verification key ID are provided
        if (keyManager != null && !ValidationUtils.isNullOrEmpty(witVerificationKeyId)
                && !ValidationUtils.isNullOrEmpty(expectedTrustDomain)) {
            this.witValidator = new WitValidator(keyManager, witVerificationKeyId, new TrustDomain(expectedTrustDomain));
        } else {
            this.witValidator = null;
            logger.warn("KeyManager, WIT verification key ID, or trust domain not provided, WIT validation will be disabled");
        }
        
        logger.info("AuthorizationServerOrchestrator initialized");
    }

    /**
     * Processes a Pushed Authorization Request (PAR).
     * <p>
     * This method coordinates the PAR processing workflow, including validating the PAR request,
     * generating a PAR response, and storing the PAR request for later use.
     * </p>
     *
     * @param parRequest the PAR request to process
     * @return the PAR response
     * @throws FrameworkParProcessingException if PAR processing fails
     */
    @Override
    public ParResponse processParRequest(ParRequest parRequest) throws FrameworkParProcessingException {
        
        // Validate PAR request
        ValidationUtils.validateNotNull(parRequest, "PAR request");

        logger.debug("Processing PAR request");

        try {
            // PAR server requires clientId parameter
            String clientId = parRequest.getClientId();
            return parServer.processParRequest(parRequest, clientId);
            
        } catch (Exception e) {
            logger.error("Failed to process PAR request", e);
            throw new FrameworkParProcessingException("Failed to process PAR request", e);
        }
    }

    /**
     * Issues an Agent Operation Authorization Token.
     * <p>
     * This method generates an AOAT containing user identity, workload identity,
     * operation authorization, evidence, and audit trail information.
     * </p>
     * <p>
     * Note: This method uses OAuth2TokenServer for token generation, which follows
     * the standard OAuth 2.0 token endpoint protocol. The token server internally
     * uses AoatTokenGeneratorAdapter to generate AOAT tokens.
     * </p>
     * <p>
     * The method expects the AoatIssuanceRequest to contain an authorization code
     * and redirect URI that were previously issued by the Authorization Server.
     * The OAuth2TokenServer will handle all authorization code validation,
     * including verification, binding checks, and consumption.
     * </p>
     *
     * @param request the AOAT issuance request
     * @return the AOAT
     * @throws FrameworkTokenGenerationException if AOAT generation fails
     */
    @Override
    public AgentOperationAuthToken issueAoat(AoatIssuanceRequest request) throws FrameworkTokenGenerationException {
        
        // Validate AOAT issuance request
        ValidationUtils.validateNotNull(request, "AOAT issuance request");

        logger.debug("Issuing AOAT using OAuth2TokenServer");

        try {
            String authorizationCode = request.getAuthorizationCode();
            
            if (ValidationUtils.isNullOrEmpty(authorizationCode)) {
                throw new FrameworkTokenGenerationException("Authorization code is required for AOAT issuance");
            }
            
            if (ValidationUtils.isNullOrEmpty(request.getRedirectUri())) {
                throw new FrameworkTokenGenerationException("Redirect URI is required for AOAT issuance");
            }
            
            // Build TokenRequest for OAuth2TokenServer 
            // and it will handle all authorization code validation internally
            TokenRequest tokenRequest = TokenRequest.builder()
                    .grantType("authorization_code")
                    .code(authorizationCode)
                    .redirectUri(request.getRedirectUri())
                    .clientId(request.getWorkloadId())
                    .build();
            
            // OAuth2TokenServer will:
            // 1. Validate the authorization code (retrieve from storage, check binding, check status)
            // 2. Generate the AOAT token using TokenGenerator
            // 3. Consume the authorization code
            TokenResponse tokenResponse = oAuth2TokenServer.issueToken(tokenRequest, request.getWorkloadId());
            
            // Parse the access token string to AgentOperationAuthToken using AoatParser
            SignedJWT signedJwt = SignedJWT.parse(tokenResponse.getAccessToken());
            AgentOperationAuthToken aoat = aoatParser.parse(signedJwt);
            
            logger.info("AOAT issued successfully using OAuth2TokenServer for client: {}", request.getWorkloadId());
            return aoat;
            
        } catch (ParseException e) {
            logger.error("Failed to parse AOAT token", e);
            throw new FrameworkTokenGenerationException("Failed to parse AOAT token: " + e.getMessage(), e);
        } catch (FrameworkTokenGenerationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to issue AOAT using OAuth2TokenServer", e);
            throw new FrameworkTokenGenerationException("Failed to issue AOAT: " + e.getMessage(), e);
        }
    }
    
    /**
     * Registers an OAuth 2.0 client using Dynamic Client Registration (DCR).
     * <p>
     * This method coordinates the DCR workflow, including validating the WIT,
     * registering the client, and returning a DCR response.
     * </p>
     *
     * @param clientAssertion the client assertion (WIT)
     * @param redirectUris the redirect URIs for the client
     * @return the DCR response
     * @throws FrameworkAuthorizationException if DCR fails
     */
    @Override
    public DcrResponse registerOAuthClient(String clientAssertion, List<String> redirectUris) throws FrameworkAuthorizationException {
        
        // Validate parameters
        if (ValidationUtils.isNullOrEmpty(clientAssertion)) {
            throw new IllegalArgumentException("Client assertion cannot be null or empty");
        }
        if (redirectUris == null || redirectUris.isEmpty()) {
            throw new IllegalArgumentException("Redirect URIs cannot be null or empty");
        }

        logger.debug("Registering OAuth client using DCR with WIT");

        try {
            // Validate WIT if validator is available
            WorkloadIdentityToken wit;
            if (witValidator != null) {
                TokenValidationResult<WorkloadIdentityToken> result = witValidator.validate(clientAssertion);
                if (!result.isValid()) {
                    throw new FrameworkAuthorizationException("WIT validation failed: " + result.getErrorMessage());
                }
                wit = result.getToken();
                logger.debug("WIT validated successfully, subject: {}", wit.getSubject());
            } else {
                logger.warn("WIT validator not configured, skipping WIT validation");
            }

            // Build DCR request with WIT in additional parameters
            Map<String, Object> additionalParameters = new HashMap<>();
            additionalParameters.put(PARAM_WIT, clientAssertion);

            DcrRequest dcrRequest = DcrRequest.builder()
                    .redirectUris(redirectUris)
                    .tokenEndpointAuthMethod(AUTH_METHOD_PRIVATE_KEY_JWT)
                    .additionalParameters(additionalParameters)
                    .build();

            // Register client using DCR server
            DcrResponse response = dcrServer.registerClient(dcrRequest);

            logger.info("OAuth client registered successfully: client_id={}", response.getClientId());
            return response;

        } catch (Exception e) {
            logger.error("Failed to register OAuth client", e);
            throw new FrameworkAuthorizationException("Failed to register OAuth client: " + e.getMessage(), e);
        }
    }

    /**
     * Exchanges an authorization code for an access token.
     * <p>
     * This method implements the OAuth2TokenClient interface, delegating to the
     * core OAuth2TokenClient for actual token exchange.
     * </p>
     *
     * @param request the token request
     * @return the authentication response containing the ID Token
     */
    @Override
    public AuthenticationResponse exchangeCodeForToken(ExchangeCodeForTokenRequest request) {

        // Validate request parameter
        ValidationUtils.validateNotNull(request, "Exchange code for token request");
        logger.debug("Exchanging code for token using OAuth2TokenClient");
        
        // Convert ExchangeCodeForTokenRequest to TokenRequest
        TokenRequest tokenRequest = TokenRequest.builder()
                .grantType("authorization_code")
                .code(request.getCode())
                .redirectUri(request.getRedirectUri())
                .clientId(request.getClientId())
                .build();
        
        // Call core OAuth2TokenClient
        TokenResponse tokenResponse = oAuth2TokenClient.exchangeCodeForToken(tokenRequest);
        
        // Convert TokenResponse to AuthenticationResponse
        return AuthenticationResponse.builder()
                .success(true)
                .idToken(tokenResponse.getAccessToken())
                .tokenType(tokenResponse.getTokenType())
                .expiresIn(tokenResponse.getExpiresIn() != null ? tokenResponse.getExpiresIn().intValue() : 3600)
                .build();
    }

    /**
     * Processes a token request and issues an access token.
     * <p>
     * This method implements the FrameworkOAuth2TokenServer interface, delegating to the
     * core OAuth2TokenServer for actual token issuance. The core token server handles
     * all authorization code validation, token generation, and response building.
     * </p>
     *
     * @param request the token request
     * @param clientId the authenticated client identifier
     * @return the token response
     * @throws FrameworkOAuth2TokenException if token issuance fails
     */
    @Override
    public TokenResponse issueToken(TokenRequest request, String clientId) throws FrameworkOAuth2TokenException {
        logger.debug("Issuing token using core OAuth2TokenServer for client: {}", clientId);
        
        try {
            // Delegate to core OAuth2TokenServer
            return oAuth2TokenServer.issueToken(request, clientId);
        } catch (Exception e) {
            logger.error("Failed to issue token for client: {}", clientId, e);
            throw new FrameworkOAuth2TokenException("server_error", "Failed to issue token: " + e.getMessage(), e);
        }
    }
}