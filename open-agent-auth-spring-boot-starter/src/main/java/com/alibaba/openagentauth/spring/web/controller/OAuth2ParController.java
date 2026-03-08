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

import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.spring.util.OAuth2ClientAuthenticator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller for OAuth 2.0 Pushed Authorization Request (PAR) endpoint.
 * <p>
 * This controller handles PAR requests according to RFC 9126 specification.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(OAuth2ParServer.class)
public class OAuth2ParController {

    /**
     * The logger for the OAuth 2.0 PAR controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(OAuth2ParController.class);

    /**
     * The PAR server.
     */
    private final OAuth2ParServer parServer;

    /**
     * The client store for validating client credentials.
     */
    private final OAuth2ClientStore clientStore;

    /**
     * The client authenticator for verifying client credentials.
     */
    private final OAuth2ClientAuthenticator clientAuthenticator;

    /**
     * Creates a new PAR controller.
     *
     * @param parServer the PAR server
     * @param clientStore the client store for client authentication
     * @param clientAuthenticator the client authenticator
     */
    public OAuth2ParController(
            OAuth2ParServer parServer,
            OAuth2ClientStore clientStore,
            OAuth2ClientAuthenticator clientAuthenticator) {
        this.parServer = ValidationUtils.validateNotNull(parServer, "PAR server");
        this.clientStore = ValidationUtils.validateNotNull(clientStore, "Client store");
        this.clientAuthenticator = ValidationUtils.validateNotNull(clientAuthenticator, "Client authenticator");
        logger.info("OAuth2ParController initialized with client store");
    }

    /**
     * PAR endpoint.
     * <p>
     * Accepts pushed authorization requests and returns a request URI.
     * </p>
     * <p>
     * <b>Client Authentication (RFC 9126 Section 2.1):</b></p>
     * <ul>
     *   <li>Client authentication is REQUIRED for PAR requests</li>
     *   <li>Confidential clients MUST authenticate using a supported method</li>
     *   <li>Supported methods: client_secret_basic (HTTP Basic), private_key_jwt (RFC 7523)</li>
     *   <li>Client credentials are validated against the client store</li>
     * </ul>
     *
     * @param requestBody the PAR request body as form data
     * @param authorizationHeader the Authorization header for client authentication
     * @return the PAR response containing request_uri and expires_in
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126#section-2.1">RFC 9126 - Client Authentication</a>
     */
    @PostMapping(
            value = "${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.par:/par}",
            consumes = "application/x-www-form-urlencoded"
    )
    public ResponseEntity<Map<String, Object>> par(
            @RequestBody MultiValueMap<String, String> requestBody,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        logger.info("Received PAR request");
        logger.debug("PAR request Authorization header present: {}", authorizationHeader != null);

        // Step 1: Convert MultiValueMap to Map for processing
        Map<String, String> requestMap = new HashMap<>();
        if (requestBody != null) {
            requestBody.forEach((key, values) -> {
                if (values != null && !values.isEmpty()) {
                    requestMap.put(key, values.get(0));
                }
            });
        }
        logger.debug("PAR request parameters: {}", requestMap.keySet());

        // Step 2: Authenticate client (supports client_secret_basic and private_key_jwt)
        logger.debug("Authenticating client for PAR request...");
        String authenticatedClientId = clientAuthenticator.authenticateClient(authorizationHeader, requestMap, clientStore);
        logger.info("PAR client authenticated successfully: {}", authenticatedClientId);

        // Step 3: Parse the PAR request with authenticated client ID
        logger.debug("Parsing PAR request for client: {}", authenticatedClientId);
        ParRequest request = parseParRequest(requestMap, authenticatedClientId);
        logger.debug("PAR request parsed - response_type: {}, redirect_uri: {}, state: {}",
                request.getResponseType(), request.getRedirectUri(), request.getState());

        // Step 4: Submit to PAR server with authenticated client ID
        logger.debug("Submitting PAR request to server for client: {}", authenticatedClientId);
        ParResponse response = parServer.processParRequest(request, authenticatedClientId);

        logger.info("PAR request processed successfully - client: {}, request_uri: {}, expires_in: {}",
                authenticatedClientId, response.getRequestUri(), response.getExpiresIn());

        // Step 5: Return response (RFC 9126 Section 2.2 requires 201 Created)
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
                "request_uri", response.getRequestUri(),
                "expires_in", response.getExpiresIn()
        ));
    }

    /**
     * Parses the PAR request from the request body.
     * <p>
     * According to RFC 9126, the PAR request can be in two forms:
     * <ul>
     *   <li><b>Pure JWT form:</b> All authorization parameters are inside the JWT,
     *       and the request body only contains the "request" parameter.</li>
     *   <li><b>Hybrid form:</b> Some parameters are in the JWT, and some are in
     *       the request body (e.g., client_id, redirect_uri).</li>
     * </ul>
     * This method supports both forms. If client_id or redirect_uri are not in
     * the request body, they will be extracted from the JWT claims.
     * </p>
     *
     * @param requestBody the request body
     * @param clientId the authenticated client ID
     * @return the parsed ParRequest
     */
    private ParRequest parseParRequest(Map<String, String> requestBody, String clientId) {

        // Get request parameter
        String request = requestBody.get("request");
        if (request == null || request.isBlank()) {
            throw new IllegalArgumentException("Missing required parameter: request");
        }

        // Get parameters from request body (hybrid form)
        String redirectUri = requestBody.get("redirect_uri");
        String responseType = requestBody.get("response_type");
        String state = requestBody.get("state");

        // If parameters are not in request body, extract from JWT (pure JWT form)
        if ((redirectUri == null || redirectUri.isBlank()) ||
            (responseType == null || responseType.isBlank()) ||
            (state == null || state.isBlank())) {
            
            try {
                Map<String, Object> jwtClaims = extractJwtClaims(request);

                // Extract redirect_uri, response_type, and state from JWT
                if (redirectUri == null || redirectUri.isBlank()) {
                    redirectUri = (String) jwtClaims.get("redirect_uri");
                }
                if (responseType == null || responseType.isBlank()) {
                    responseType = (String) jwtClaims.get("response_type");
                }
                if (state == null || state.isBlank()) {
                    state = (String) jwtClaims.get("state");
                }
            } catch (Exception e) {
                logger.error("Failed to extract claims from JWT", e);
                throw new IllegalArgumentException("Invalid JWT: " + e.getMessage());
            }
        }

        // Validate required parameters
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("Missing required parameter: redirect_uri (not found in request body or JWT)");
        }
        if (responseType == null || responseType.isBlank()) {
            responseType = "code";
        }
        
        logger.debug("Parsed PAR request - client_id: {}, redirect_uri: {}, state: {}", 
                     clientId, redirectUri, state);

        // Build PAR request
        ParRequest.Builder builder = ParRequest.builder()
                .requestJwt(request)
                .responseType(responseType)
                .clientId(clientId)
                .redirectUri(redirectUri);
        
        // Add state parameter if provided (RFC 6749 Section 4.1.1)
        if (state != null && !state.isBlank()) {
            builder.state(state);
            logger.debug("State parameter added to PAR request: {}", state);
        }
        
        return builder.build();
    }

    /**
     * Extracts claims from a JWT without verifying the signature.
     * <p>
     * Note: This method only extracts the payload for parsing purposes.
     * The signature verification is done in the PAR server layer.
     * </p>
     * <p>
     * This method uses NimbusDS JWT library for parsing, which provides
     * robust JWT parsing and handles edge cases better than manual parsing.
     * </p>
     *
     * @param jwt the JWT string
     * @return the claims as a map
     * @throws IllegalArgumentException if the JWT is malformed or cannot be parsed
     */
    private Map<String, Object> extractJwtClaims(String jwt) {
        try {
            // Parse JWT using NimbusDS library (no signature verification)
            SignedJWT signedJwt = SignedJWT.parse(jwt);
            JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();
            
            // Convert claims to map
            return claimsSet.getClaims();
            
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse JWT: " + e.getMessage(), e);
        }
    }
}