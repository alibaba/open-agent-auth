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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.server;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

/**
 * Default implementation of {@link OAuth2AuthorizationServer}.
 * <p>
 * This implementation provides a complete authorization server following RFC 6749
 * specification with PAR integration for the Agent Operation Authorization framework.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>PAR request retrieval and validation</li>
 *   <li>Secure authorization code generation</li>
 *   <li>Configurable code expiration (default: 10 minutes)</li>
 *   <li>Configurable storage backend</li>
 *   <li>Comprehensive error handling</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Grant</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class DefaultOAuth2AuthorizationServer implements OAuth2AuthorizationServer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2AuthorizationServer.class);

    /**
     * Default code expiration time in seconds, 10 minutes.
     */
    private static final int DEFAULT_CODE_EXPIRATION_SECONDS = 600;

    /**
     * Secure random generator for generating authorization codes.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Storage backend for storing and retrieving authorization codes.
     */
    private final OAuth2AuthorizationCodeStorage codeStorage;

    /**
     * PAR server for retrieving authorization requests.
     */
    private final OAuth2ParServer OAuth2ParServer;

    /**
     * DCR client store for validating OAuth 2.0 clients.
     */
    private final OAuth2DcrClientStore clientStore;

    /**
     * Default expiration time for authorization codes in seconds.
     */
    private final long defaultCodeExpirationSeconds;

    /**
     * Creates a new DefaultAuthorizationServer with default expiration.
     *
     * @param codeStorage the storage backend for authorization codes
     * @param OAuth2ParServer the PAR server for retrieving authorization requests
     * @param clientStore the DCR client store for validating OAuth 2.0 clients
     */
    public DefaultOAuth2AuthorizationServer(OAuth2AuthorizationCodeStorage codeStorage, OAuth2ParServer OAuth2ParServer, OAuth2DcrClientStore clientStore) {
        this(codeStorage, OAuth2ParServer, clientStore, DEFAULT_CODE_EXPIRATION_SECONDS);
    }

    /**
     * Creates a new DefaultAuthorizationServer with custom expiration.
     *
     * @param codeStorage the storage backend for authorization codes
     * @param OAuth2ParServer the PAR server for retrieving authorization requests
     * @param clientStore the DCR client store for validating OAuth 2.0 clients
     * @param defaultCodeExpirationSeconds the default expiration time in seconds
     */
    public DefaultOAuth2AuthorizationServer(
            OAuth2AuthorizationCodeStorage codeStorage,
            OAuth2ParServer OAuth2ParServer,
            OAuth2DcrClientStore clientStore,
            long defaultCodeExpirationSeconds
    ) {
        this.codeStorage = ValidationUtils.validateNotNull(codeStorage, "Code storage");
        this.OAuth2ParServer = ValidationUtils.validateNotNull(OAuth2ParServer, "PAR server");
        this.clientStore = ValidationUtils.validateNotNull(clientStore, "Client store");
        this.defaultCodeExpirationSeconds = defaultCodeExpirationSeconds;
        
        logger.info("DefaultAuthorizationServer initialized with code expiration: {} seconds", 
                defaultCodeExpirationSeconds);
    }

    /**
     * Authorizes a subject for traditional OAuth 2.0 authorization code flow.
     *
     * @param subject the authenticated user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param redirectUri the redirect URI
     * @param scopes the requested scopes
     * @return the authorization code
     */
    @Override
    public AuthorizationCode authorize(String subject, String clientId, String redirectUri, String scopes) {

        // Validate parameters
        ValidationUtils.validateNotNull(subject, "Subject cannot be null or empty");
        ValidationUtils.validateNotNull(clientId, "Client ID cannot be null or empty");
        ValidationUtils.validateNotNull(redirectUri, "Redirect URI cannot be null or empty");
        logger.info("Processing traditional authorization for subject: {}, client_id: {}", subject, clientId);

        try {
            // Step 1: Validate client and redirect URI, and get the actual client with resolved client_id
            DcrResponse client = validateClientAndRedirectUri(clientId, redirectUri);
            
            // Step 2: Generate authorization code with the actual client_id from DcrResponse
            return createAuthorizationCode(
                    subject,
                    client.getClientId(),
                    redirectUri,
                    scopes != null ? scopes : "",
                    null, // requestUri
                    null  // state
            );

        } catch (OAuth2AuthorizationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during traditional authorization", e);
            throw OAuth2AuthorizationException.serverError("Internal server error during authorization", e);
        }
    }

    /**
     * Authorizes a subject for a given request URI.
     *
     * @param requestUri the request URI from PAR
     * @param subject the subject to authorize
     * @return the authorization code
     */
    @Override
    public AuthorizationCode authorize(String requestUri, String subject) {

        // Validate parameters
        ValidationUtils.validateNotNull(requestUri, "Request URI cannot be null or empty");
        ValidationUtils.validateNotNull(subject, "Subject cannot be null or empty");
        logger.info("Processing authorization for subject: {}, request_uri: {}", subject, requestUri);

        try {
            // Step 1: Retrieve the PAR request
            ParRequest parRequest = OAuth2ParServer.retrieveRequest(requestUri);
            logger.debug("PAR request retrieved: client_id={}", parRequest.getClientId());

            // Step 2: Validate client and redirect URI, and get the actual client with resolved client_id
            // This is necessary because parRequest.getClientId() might be client_name instead of actual client_id
            DcrResponse client = validateClientAndRedirectUri(parRequest.getClientId(), parRequest.getRedirectUri());
            
            logger.debug("Using actual client_id: {} (original from PAR: {})", client.getClientId(), parRequest.getClientId());

            // Step 3: Generate authorization code with the actual client_id
            return createAuthorizationCode(
                    subject,
                    client.getClientId(),
                    parRequest.getRedirectUri(),
                    parRequest.getScope(),
                    requestUri,
                    parRequest.getState()
            );

        } catch (OAuth2AuthorizationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during authorization", e);
            throw OAuth2AuthorizationException.serverError("Internal server error during authorization", e);
        }
    }

    /**
     * Validates an authorization request for a given request URI.
     *
     * @param requestUri the request URI from PAR
     * @return true if the request is valid, false otherwise
     */
    @Override
    public boolean validateRequest(String requestUri) {

        ValidationUtils.validateNotNull(requestUri, "Request URI cannot be null or empty");
        logger.debug("Validating authorization request for request_uri: {}", requestUri);

        try {
            // Retrieve the PAR request
            ParRequest parRequest = OAuth2ParServer.retrieveRequest(requestUri);
            if (parRequest == null) {
                logger.error("PAR request not found for request_uri: {}", requestUri);
                return false;
            }

            // Validate required parameters
            if (ValidationUtils.isNullOrEmpty(parRequest.getClientId())) {
                logger.error("Invalid PAR request: missing client_id");
                return false;
            }
            if (ValidationUtils.isNullOrEmpty(parRequest.getRedirectUri())) {
                logger.error("Invalid PAR request: missing redirect_uri");
                return false;
            }

            // Validate response_type (should be "code" for authorization code flow)
            String responseType = parRequest.getResponseType();
            if (!"code".equals(responseType)) {
                logger.error("Invalid response_type: {}, expected 'code'", responseType);
                return false;
            }

            logger.debug("Authorization request validated successfully");
            return true;

        } catch (Exception e) {
            logger.error("Error validating authorization request", e);
            return false;
        }
    }

    /**
     * Validates the client and redirect URI for traditional OAuth 2.0 authorization flow.
     * <p>
     * This method performs the following validations and returns the validated client:
     * </p>
     * <ul>
     *   <li>Client exists (by client_id or client_name as fallback)</li>
     *   <li>Redirect URI is registered for the client</li>
     * </ul>
     * 
     * @param clientId    the OAuth 2.0 client identifier (may be client_id or client_name)
     * @param redirectUri the redirect URI to validate
     * @return the validated DcrResponse with the actual client_id
     * @throws OAuth2AuthorizationException if validation fails
     */
    private DcrResponse validateClientAndRedirectUri(String clientId, String redirectUri) {

        // Step 1: Validate client exists. First, try to find client by client_id
        DcrResponse client = clientStore.retrieve(clientId);

        // If not found, try to find client by client_name (fallback for development/testing)
        if (client == null) {
            logger.warn("Client not found by client_id: {}, trying to find by client_name", clientId);
            client = clientStore.retrieveByClientName(clientId);

            if (client != null) {
                logger.info("Client found by client_name: {} -> actual client_id: {}", clientId, client.getClientId());
            } else {
                logger.error("Client not found: client_id={}", clientId);
                throw OAuth2AuthorizationException.unauthorizedClient("Client not found: " + clientId);
            }
        }

        // Step 2: Validate redirect_uri is registered for this client
        List<String> registeredRedirectUris = client.getRedirectUris();
        if (registeredRedirectUris == null || registeredRedirectUris.isEmpty()) {
            logger.error("No redirect URIs registered for client: client_id={}", client.getClientId());
            throw OAuth2AuthorizationException.invalidRequest("No redirect URIs registered for client");
        }
        if (!registeredRedirectUris.contains(redirectUri)) {
            logger.error("Redirect URI not registered for client: client_id={}, redirect_uri={}, registered_uris={}",
                    client.getClientId(), redirectUri, registeredRedirectUris);
            throw OAuth2AuthorizationException.invalidRequest(
                    "Redirect URI not registered for client. Provided: " + redirectUri +
                            ", Registered: " + String.join(", ", registeredRedirectUris));
        }

        logger.debug("Client validation successful: client_id={}, redirect_uri={}", client.getClientId(), redirectUri);
        
        return client;
    }

    /**
     * Creates and stores an authorization code.
     * <p>
     * This method performs the following steps:
     * </p>
     * <ol>
     *   <li>Generates a secure authorization code</li>
     *   <li>Calculates expiration time</li>
     *   <li>Builds the authorization code object</li>
     *   <li>Stores the authorization code</li>
     * </ol>
     *
     * @param subject the user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param redirectUri the redirect URI
     * @param scope the granted scope
     * @param requestUri the request URI from PAR (optional)
     * @param state the state parameter (optional)
     * @return the created authorization code
     */
    private AuthorizationCode createAuthorizationCode(
            String subject,
            String clientId,
            String redirectUri,
            String scope,
            String requestUri,
            String state
    ) {
        // Step 1: Generate secure authorization code
        String code = generateAuthorizationCode();
        logger.debug("Generated authorization code");

        // Step 2: Calculate expiration time
        Instant now = Instant.now();
        Instant expirationTime = now.plusSeconds(defaultCodeExpirationSeconds);

        // Step 3: Build authorization code
        AuthorizationCode authorizationCode = AuthorizationCode.builder()
                .code(code)
                .clientId(clientId)
                .redirectUri(redirectUri)
                .requestUri(requestUri)
                .state(state)
                .subject(subject)
                .scope(scope)
                .issuedAt(now)
                .expiresAt(expirationTime)
                .used(false)
                .build();

        // Step 4: Store the authorization code
        codeStorage.store(authorizationCode);
        logger.info("Authorization code stored successfully for client: {}", clientId);

        return authorizationCode;
    }

    /**
     * Generates a secure authorization code with sufficient entropy.
     * <p>
     * Per RFC 6749 Section 4.1.2, authorization codes MUST be short-lived,
     * single-use, and have sufficient entropy to prevent guessing attacks.
     * This implementation uses a cryptographically secure random generator
     * to create a 256-bit value.
     * </p>
     *
     * @return the generated authorization code
     */
    private String generateAuthorizationCode() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Gets the code storage backend.
     *
     * @return the code storage
     */
    public OAuth2AuthorizationCodeStorage getCodeStorage() {
        return codeStorage;
    }

    /**
     * Gets the PAR server.
     *
     * @return the PAR server
     */
    public OAuth2ParServer getParServer() {
        return OAuth2ParServer;
    }

    /**
     * Gets the DCR client store.
     *
     * @return the DCR client store
     */
    public OAuth2DcrClientStore getClientStore() {
        return clientStore;
    }

    /**
     * Gets the default code expiration time.
     *
     * @return the expiration time in seconds
     */
    public long getDefaultCodeExpirationSeconds() {
        return defaultCodeExpirationSeconds;
    }

}