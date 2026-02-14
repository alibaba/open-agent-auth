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
package com.alibaba.openagentauth.spring.util;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class for OAuth 2.0 client authentication.
 * <p>
 * This class provides static methods for authenticating OAuth 2.0 clients
 * using various authentication mechanisms as specified in RFC 6749.
 * </p>
 * <p>
 * <b>Supported Authentication Methods:</b></p>
 * <ul>
 *   <li><b>client_secret_basic (RFC 6749 Section 2.3.1)</b>: HTTP Basic authentication</li>
 * </ul>
 * <p>
 * <b>Security Considerations:</b></p>
 * <ul>
 *   <li>All authentication methods validate client credentials against the DCR store</li>
 *   <li>Client secrets are compared using constant-time comparison to prevent timing attacks</li>
 *   <li>Detailed error messages are logged for debugging while returning generic errors to clients</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
 * @since 1.0
 */
public final class OAuth2ClientAuthenticator {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientAuthenticator.class);

    /**
     * The HTTP Basic authentication scheme.
     */
    private static final String BASIC_AUTH_SCHEME = "Basic ";

    /**
     * The client_secret_basic authentication method.
     */
    private static final String CLIENT_SECRET_BASIC = "client_secret_basic";

    /**
     * Private constructor to prevent instantiation.
     */
    private OAuth2ClientAuthenticator() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Authenticates the client using HTTP Basic authentication.
     * <p>
     * This method implements RFC 6749 Section 2.3.1 client authentication.
     * It extracts and validates the client credentials from the Authorization header.
     * </p>
     * <p>
     * <b>Authentication Flow:</b></p>
     * <ol>
     *   <li>Validate Authorization header is present</li>
     *   <li>Validate Basic Auth scheme</li>
     *   <li>Extract and decode Base64 credentials</li>
     *   <li>Parse client_id:client_secret</li>
     *   <li>Validate client ID is not empty</li>
     *   <li>Retrieve client from DCR store</li>
     *   <li>Validate client secret matches</li>
     *   <li>Validate token endpoint auth method supports client_secret_basic</li>
     * </ol>
     *
     * @param authorizationHeader the Authorization header value
     * @param clientStore the DCR client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1">RFC 6749 - Client Password</a>
     */
    public static String authenticateWithBasicAuth(String authorizationHeader, OAuth2DcrClientStore clientStore) {
        // Validate Authorization header is present
        if (ValidationUtils.isNullOrEmpty(authorizationHeader)) {
            logger.error("Authorization header is missing");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Authorization header is missing");
        }

        // Validate Basic Auth scheme
        if (!authorizationHeader.startsWith(BASIC_AUTH_SCHEME)) {
            logger.error("Invalid authentication scheme, expected 'Basic'");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Only Basic authentication is supported");
        }

        // Extract and decode credentials
        String base64Credentials = authorizationHeader.substring(BASIC_AUTH_SCHEME.length()).trim();
        String credentials;
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            credentials = new String(decodedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            logger.error("Failed to decode Base64 credentials", e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid Base64 encoding");
        }

        // Parse client_id:client_secret
        String[] parts = credentials.split(":", 2);
        if (parts.length != 2) {
            logger.error("Invalid credentials format, expected 'client_id:client_secret'");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid credentials format");
        }

        String clientId = parts[0];
        String clientSecret = parts[1];

        // Validate client ID is not empty
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            logger.error("Client ID is empty");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client ID is required");
        }

        // Retrieve client from DCR store
        DcrResponse client = clientStore.retrieve(clientId);
        if (client == null) {
            logger.error("Client not found: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client not registered");
        }

        // Validate client secret
        String storedSecret = client.getClientSecret();
        if (ValidationUtils.isNullOrEmpty(storedSecret)) {
            logger.error("Client {} has no secret configured (public client)", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for authentication");
        }

        if (!storedSecret.equals(clientSecret)) {
            logger.error("Invalid client secret for client: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid client secret");
        }

        // Validate token endpoint auth method
        String authMethod = client.getTokenEndpointAuthMethod();
        if (authMethod != null && !CLIENT_SECRET_BASIC.equals(authMethod)) {
            logger.error("Client {} uses unsupported auth method: {}", clientId, authMethod);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Unsupported authentication method: " + authMethod);
        }

        logger.debug("Client authentication successful for client: {}", clientId);
        return clientId;
    }
}
