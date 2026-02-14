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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.server;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.authenticator.OAuth2DcrAuthenticator;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Default implementation of {@link OAuth2DcrServer}.
 * <p>
 * This implementation provides a complete DCR server following RFC 7591
 * specification with configurable storage backend and WIMSE integration.
 * </p>
 * <p>
 * <b>Features:</b></p>
 * <ul>
 *   <li>Pluggable authentication via Strategy Pattern</li>
 *   <li>Client metadata validation</li>
 *   <li>Secure client_id and client_secret generation</li>
 *   <li>Registration access token generation</li>
 *   <li>Configurable storage backend</li>
 *   <li>Comprehensive error handling</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
public class DefaultOAuth2DcrServer implements OAuth2DcrServer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2DcrServer.class);

    /**
     * Secure random number generator for generating client_id and client_secret.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Storage backend for storing and retrieving client registrations.
     */
    private final OAuth2DcrClientStore clientStore;

    /**
     * List of authenticators for client authentication.
     * The server will try each authenticator in order until one can handle the request.
     */
    private final List<OAuth2DcrAuthenticator> authenticators;

    /**
     * Creates a new DefaultDcrServer with the specified storage backend.
     *
     * @param clientStore the storage backend for client registrations
     * @throws IllegalArgumentException if clientStore is null
     */
    public DefaultOAuth2DcrServer(OAuth2DcrClientStore clientStore) {
        this(clientStore, new ArrayList<>());
    }

    /**
     * Creates a new DefaultDcrServer with the specified storage backend and authenticators.
     *
     * @param clientStore the storage backend for client registrations
     * @param authenticators the list of authenticators for client authentication
     * @throws IllegalArgumentException if clientStore is null
     */
    public DefaultOAuth2DcrServer(OAuth2DcrClientStore clientStore, List<OAuth2DcrAuthenticator> authenticators) {
        this.clientStore = ValidationUtils.validateNotNull(clientStore, "Client store");
        this.authenticators = authenticators != null ? authenticators : new ArrayList<>();
        logger.info("DefaultDcrServer initialized with {} authenticators", this.authenticators.size());
    }

    @Override
    public DcrResponse registerClient(DcrRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(request, "DCR request");
        logger.info("Registering new OAuth client: {}", request.getClientName());

        try {
            // Step 1: Validate request parameters
            validateRegistrationRequest(request);

            // Step 2: Authenticate client using strategy pattern
            String authenticatedSubject = authenticateClient(request);
            logger.debug("Client authenticated: subject={}", authenticatedSubject);

            // Step 3: Generate client_id
            String clientId = generateClientId();
            logger.debug("Generated client_id: {}", clientId);

            // Step 4: Generate client_secret if needed
            String clientSecret = null;
            String authMethod = request.getTokenEndpointAuthMethod();
            if (needsClientSecret(authMethod)) {
                clientSecret = generateClientSecret();
                logger.debug("Generated client_secret for client_id: {}", clientId);
            }

            // Step 5: Generate registration access token
            String registrationAccessToken = generateRegistrationAccessToken();
            logger.debug("Generated registration access token for client_id: {}", clientId);

            // Step 6: Build response
            long now = Instant.now().getEpochSecond();
            DcrResponse.Builder responseBuilder = DcrResponse.builder()
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .clientIdIssuedAt(now)
                    .clientSecretExpiresAt(0L) // 0 means never expires
                    .registrationAccessToken(registrationAccessToken)
                    .registrationClientUri(buildRegistrationClientUri(clientId))
                    .redirectUris(request.getRedirectUris())
                    .clientName(request.getClientName())
                    .grantTypes(request.getGrantTypes())
                    .responseTypes(request.getResponseTypes())
                    .tokenEndpointAuthMethod(authMethod)
                    .scope(request.getScope());

            DcrResponse response = responseBuilder.build();

            // Step 7: Store the registration
            clientStore.store(clientId, registrationAccessToken, request, response);

            logger.info("Client registered successfully: client_id={}", clientId);
            return response;

        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during client registration", e);
            throw DcrException.invalidClientMetadata("Failed to register client: " + e.getMessage());
        }
    }

    @Override
    public DcrResponse readClient(String clientId, String registrationAccessToken) {

        // Validate request
        ValidationUtils.validateNotNull(clientId, "Client ID");
        ValidationUtils.validateNotNull(registrationAccessToken, "Registration access token");

        logger.debug("Reading client registration for client_id: {}", clientId);

        try {
            // Validate token and retrieve client
            DcrResponse response = validateTokenAndRetrieveClient(clientId, registrationAccessToken);

            logger.debug("Client registration retrieved successfully for client_id: {}", clientId);
            return response;

        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error reading client registration", e);
            throw DcrException.invalidClientId("Failed to read client: " + e.getMessage());
        }
    }

    @Override
    public DcrResponse updateClient(String clientId, String registrationAccessToken, DcrRequest request) {

        // Validate request
        ValidationUtils.validateNotNull(clientId, "Client ID");
        ValidationUtils.validateNotNull(registrationAccessToken, "Registration access token");
        ValidationUtils.validateNotNull(request, "DCR request");

        logger.info("Updating client registration for client_id: {}", clientId);

        try {
            // Validate token and retrieve existing client
            DcrResponse existingResponse = validateTokenAndRetrieveClient(clientId, registrationAccessToken);

            // Validate update request
            validateUpdateRequest(request);

            // Build updated response
            DcrResponse.Builder responseBuilder = DcrResponse.builder()
                    .clientId(existingResponse.getClientId())
                    .clientSecret(existingResponse.getClientSecret())
                    .clientIdIssuedAt(existingResponse.getClientIdIssuedAt())
                    .clientSecretExpiresAt(existingResponse.getClientSecretExpiresAt())
                    .registrationAccessToken(registrationAccessToken)
                    .registrationClientUri(existingResponse.getRegistrationClientUri())
                    .redirectUris(getUpdatedValue(request.getRedirectUris(), existingResponse.getRedirectUris()))
                    .clientName(getUpdatedValue(request.getClientName(), existingResponse.getClientName()))
                    .grantTypes(getUpdatedValue(request.getGrantTypes(), existingResponse.getGrantTypes()))
                    .responseTypes(getUpdatedValue(request.getResponseTypes(), existingResponse.getResponseTypes()))
                    .tokenEndpointAuthMethod(getUpdatedValue(request.getTokenEndpointAuthMethod(), existingResponse.getTokenEndpointAuthMethod()))
                    .scope(getUpdatedValue(request.getScope(), existingResponse.getScope()));

            DcrResponse updatedResponse = responseBuilder.build();

            // Update storage
            clientStore.update(clientId, request, updatedResponse);

            logger.info("Client registration updated successfully: client_id={}", clientId);
            return updatedResponse;

        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error updating client registration", e);
            throw DcrException.invalidClientMetadata("Failed to update client: " + e.getMessage());
        }
    }

    @Override
    public void deleteClient(String clientId, String registrationAccessToken) {

        // Validate request
        ValidationUtils.validateNotNull(clientId, "Client ID");
        ValidationUtils.validateNotNull(registrationAccessToken, "Registration access token");

        logger.info("Deleting client registration for client_id: {}", clientId);

        try {
            // Validate token and check if client exists
            validateTokenAndRetrieveClient(clientId, registrationAccessToken);

            // Delete client
            clientStore.delete(clientId);

            logger.info("Client registration deleted successfully: client_id={}", clientId);

        } catch (DcrException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error deleting client registration", e);
            throw DcrException.invalidClientId("Failed to delete client: " + e.getMessage());
        }
    }

    /**
     * Validates the registration access token and retrieves the client registration.
     * <p>
     * This method validates the token and retrieves the client from storage.
     * If the token is invalid or the client does not exist, an exception is thrown.
     * </p>
     *
     * @param clientId the client ID
     * @param registrationAccessToken the registration access token
     * @return the retrieved client registration
     * @throws DcrException if validation fails or client not found
     */
    private DcrResponse validateTokenAndRetrieveClient(String clientId, String registrationAccessToken) {

        // Validate token
        if (!clientStore.validateToken(clientId, registrationAccessToken)) {
            logger.error("Invalid registration access token for client_id: {}", clientId);
            throw DcrException.invalidClientId("Invalid registration access token");
        }

        // Retrieve client
        DcrResponse response = clientStore.retrieve(clientId);
        if (response == null) {
            logger.error("Client not found: client_id={}", clientId);
            throw DcrException.invalidClientId("Client not found");
        }

        return response;
    }

    /**
     * Gets the updated value for a field during client update.
     * <p>
     * If the new value is not null, it is used; otherwise, the existing value is retained.
     * This provides a clean way to handle partial updates where only some fields are modified.
     * </p>
     *
     * @param newValue the new value from the update request
     * @param existingValue the existing value from the stored client
     * @param <T> the type of the value
     * @return the new value if not null, otherwise the existing value
     */
    private <T> T getUpdatedValue(T newValue, T existingValue) {
        return newValue != null ? newValue : existingValue;
    }

    /**
     * Validates a registration request.
     *
     * @param request the DCR request
     * @throws DcrException if validation fails
     */
    private void validateRegistrationRequest(DcrRequest request) {

        // Validate redirect_uris (required by RFC 7591)
        if (request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
            throw DcrException.invalidRedirectUri("redirect_uris is REQUIRED");
        }

        // Validate each redirect URI
        for (String redirectUri : request.getRedirectUris()) {
            if (ValidationUtils.isNullOrEmpty(redirectUri)) {
                throw DcrException.invalidRedirectUri("redirect_uris contains empty value");
            }
            // Additional URI validation can be added here
        }

        // Validate token_endpoint_auth_method if specified
        String authMethod = request.getTokenEndpointAuthMethod();
        if (authMethod != null && !isValidAuthMethod(authMethod)) {
            throw DcrException.invalidClientMetadata("Invalid token_endpoint_auth_method: " + authMethod);
        }
    }

    /**
     * Validates an update request.
     *
     * @param request the DCR request
     * @throws DcrException if validation fails
     */
    private void validateUpdateRequest(DcrRequest request) {

        // If redirect_uris is provided, validate it
        if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
            for (String redirectUri : request.getRedirectUris()) {
                if (ValidationUtils.isNullOrEmpty(redirectUri)) {
                    throw DcrException.invalidRedirectUri("redirect_uris contains empty value");
                }
            }
        }

        // Validate token_endpoint_auth_method if specified
        String authMethod = request.getTokenEndpointAuthMethod();
        if (authMethod != null && !isValidAuthMethod(authMethod)) {
            throw DcrException.invalidClientMetadata("Invalid token_endpoint_auth_method: " + authMethod);
        }
    }

    /**
     * Authenticates a client using the configured authenticators.
     * <p>
     * This method uses the Strategy Pattern to try each authenticator in order
     * until one can handle the request. If no authenticator can handle the request,
     * a default authentication is performed (no authentication).
     * </p>
     *
     * @param request the DCR request
     * @return the authenticated subject identifier
     * @throws DcrException if authentication fails
     */
    private String authenticateClient(DcrRequest request) throws DcrException {

        // Try each authenticator in order
        for (OAuth2DcrAuthenticator authenticator : authenticators) {
            if (authenticator.canAuthenticate(request)) {
                logger.debug("Using authenticator: {}", authenticator.getAuthenticationMethod());
                return authenticator.authenticate(request);
            }
        }

        // No authenticator could handle the request - use default (no authentication)
        logger.debug("No authenticator matched, using default authentication");
        return "default-client";
    }

    /**
     * Checks if the authentication method requires a client secret.
     *
     * @param authMethod the authentication method
     * @return true if client secret is needed, false otherwise
     */
    private boolean needsClientSecret(String authMethod) {
        if (authMethod == null) {
            // Default to client_secret_basic
            return true;
        }
        return !authMethod.equals("none") && !authMethod.equals("private_key_jwt");
    }

    /**
     * Checks if the authentication method is valid.
     *
     * @param authMethod the authentication method
     * @return true if valid, false otherwise
     */
    private boolean isValidAuthMethod(String authMethod) {
        return "client_secret_basic".equals(authMethod) ||
               "client_secret_post".equals(authMethod) ||
               "client_secret_jwt".equals(authMethod) ||
               "private_key_jwt".equals(authMethod) ||
               "none".equals(authMethod);
    }

    /**
     * Generates a unique client identifier.
     *
     * @return the generated client ID
     */
    private String generateClientId() {
        return UUID.randomUUID().toString();
    }

    /**
     * Generates a cryptographically secure client secret.
     *
     * @return the generated client secret
     */
    private String generateClientSecret() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Generates a registration access token.
     *
     * @return the generated token
     */
    private String generateRegistrationAccessToken() {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Builds the registration client URI for a client.
     *
     * @param clientId the client ID
     * @return the registration client URI
     */
    private String buildRegistrationClientUri(String clientId) {
        return "/register/" + clientId;
    }

}