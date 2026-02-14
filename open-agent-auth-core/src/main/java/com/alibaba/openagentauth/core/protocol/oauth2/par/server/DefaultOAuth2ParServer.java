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
package com.alibaba.openagentauth.core.protocol.oauth2.par.server;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.OAuth2ParRequestStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default implementation of {@link OAuth2ParServer}.
 * <p>
 * This implementation provides a complete PAR server following RFC 9126
 * specification with configurable storage backend.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Client authentication validation</li>
 *   <li>Request JWT validation (via injected validator)</li>
 *   <li>OAuth 2.0 parameter validation</li>
 *   <li>Secure request_uri generation with sufficient entropy</li>
 *   <li>Configurable request storage</li>
 *   <li>Comprehensive error handling</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class DefaultOAuth2ParServer implements OAuth2ParServer {

    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2ParServer.class);

    private static final int DEFAULT_EXPIRES_IN = 90;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Storage backend for storing and retrieving PAR requests by their request_uri.
     * Provides persistence across the PAR flow (submission to authorization) with built-in expiration handling.
     */
    private final OAuth2ParRequestStore requestStore;

    /**
     * Validator for OAuth 2.0 PAR requests and JWT parameters.
     * Performs standard parameter validation (response_type, client_id, redirect_uri) and basic JWT format checks.
     */
    private final OAuth2ParRequestValidator requestValidator;

    /**
     * Default expiration time in seconds for stored PAR requests.
     * Used when storing requests to limit their validity period, following RFC 9126 recommendations.
     * Default is 90 seconds as per OAuth 2.0 PAR best practices.
     */
    private final long defaultExpiresInSeconds;

    /**
     * Creates a new DefaultParServer with default expiration.
     *
     * @param requestStore the storage backend for PAR requests
     * @param requestValidator the validator for PAR requests
     */
    public DefaultOAuth2ParServer(OAuth2ParRequestStore requestStore, OAuth2ParRequestValidator requestValidator) {
        this(requestStore, requestValidator, DEFAULT_EXPIRES_IN);
    }

    /**
     * Creates a new DefaultParServer with custom expiration.
     *
     * @param requestStore the storage backend for PAR requests
     * @param requestValidator the validator for PAR requests
     * @param defaultExpiresInSeconds the default expiration time in seconds
     */
    public DefaultOAuth2ParServer(
            OAuth2ParRequestStore requestStore,
            OAuth2ParRequestValidator requestValidator,
            long defaultExpiresInSeconds
    ) {
        this.requestStore = ValidationUtils.validateNotNull(requestStore, "Request store");
        this.requestValidator = ValidationUtils.validateNotNull(requestValidator, "Request validator");
        this.defaultExpiresInSeconds = defaultExpiresInSeconds;
        
        logger.info("DefaultParServer initialized with default expiration: {} seconds", 
                defaultExpiresInSeconds);
    }

    @Override
    public ParResponse processParRequest(ParRequest request, String clientId) {
        ValidationUtils.validateNotNull(request, "PAR request");
        ValidationUtils.validateNotNull(clientId, "Client ID");
        
        logger.info("Processing PAR request for client: {}", clientId);

        try {
            // Step 1: Validate client_id matches authenticated client
            validateClientId(request, clientId);
            
            // Step 2: Validate request JWT and OAuth 2.0 parameters
            requestValidator.validate(request);
            
            // Step 3: Generate unique request_uri with sufficient entropy
            String requestUri = generateRequestUri();
            
            // Step 4: Store the request with expiration
            requestStore.store(requestUri, request, defaultExpiresInSeconds);
            
            logger.info("PAR request processed successfully, request_uri: {}", requestUri);
            
            // Step 5: Return response
            return ParResponse.success(requestUri, (int) defaultExpiresInSeconds);
            
        } catch (ParException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error processing PAR request", e);
            throw ParException.internalError("Failed to process PAR request: " + e.getMessage(), e);
        }
    }

    /**
     * Validates that the client_id in the request matches the authenticated client.
     *
     * @param request the PAR request
     * @param authenticatedClientId the authenticated client ID
     * @throws ParException if validation fails
     */
    private void validateClientId(ParRequest request, String authenticatedClientId) {

        String requestClientId = request.getClientId();
        
        if (!authenticatedClientId.equals(requestClientId)) {
            logger.error("Client ID mismatch: authenticated={}, request={}", 
                    authenticatedClientId, requestClientId);
            throw ParException.authenticationFailed("Authenticated client ID does not match request client_id");
        }
        
        logger.debug("Client ID validated: {}", authenticatedClientId);
    }

    /**
     * Generates a unique request_uri with sufficient entropy.
     * <p>
     * Per RFC 9126 Section 7.1, the request_uri must have sufficient entropy
     * to prevent guessing attacks. This implementation uses a cryptographically
     * secure random generator to create a 256-bit value.
     * </p>
     *
     * @return the generated request_uri
     */
    private String generateRequestUri() {

        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        
        String randomValue = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
        
        return "urn:ietf:params:oauth:request_uri:" + randomValue;
    }

    @Override
    public ParRequest retrieveRequest(String requestUri) {
        ValidationUtils.validateNotNull(requestUri, "Request URI");

        logger.debug("Retrieving PAR request for request_uri: {}", requestUri);

        // Retrieve from storage
        ParRequest request = requestStore.retrieve(requestUri);

        if (request == null) {
            logger.error("PAR request not found or expired for request_uri: {}", requestUri);
            throw ParException.invalidParameter("request_uri",
                    "Request URI not found or expired");
        }

        logger.debug("PAR request retrieved successfully for request_uri: {}", requestUri);
        return request;
    }
}