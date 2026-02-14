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
package com.alibaba.openagentauth.core.protocol.oauth2.token.server;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link OAuth2TokenServer}.
 * <p>
 * This implementation handles standard OAuth 2.0 protocol operations as defined in RFC 6749.
 * It delegates token generation to a {@link TokenGenerator} interface, allowing for
 * different token types (e.g., standard OAuth tokens, AOAT tokens).
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0 Authorization Framework</a>
 * @since 1.0
 */
public class DefaultOAuth2TokenServer implements OAuth2TokenServer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2TokenServer.class);

    /**
     * Storage backend for authorization codes.
     */
    private final OAuth2AuthorizationCodeStorage codeStorage;

    /**
     * Token generator for creating access tokens.
     */
    private final TokenGenerator tokenGenerator;

    /**
     * Creates a new DefaultOAuth2TokenServer.
     *
     * @param codeStorage the storage backend for authorization codes
     * @param tokenGenerator the token generator
     */
    public DefaultOAuth2TokenServer(OAuth2AuthorizationCodeStorage codeStorage, TokenGenerator tokenGenerator) {
        this.codeStorage = ValidationUtils.validateNotNull(codeStorage, "Code storage");
        this.tokenGenerator = ValidationUtils.validateNotNull(tokenGenerator, "Token generator");
        logger.info("DefaultOAuth2TokenServer initialized");
    }

    @Override
    public TokenResponse issueToken(TokenRequest request, String clientId) {
        logger.info("Issuing token for client: {}", clientId);

        try {
            // Step 1: Validate token request
            validateTokenRequest(request, clientId);

            // Step 2: Validate and retrieve authorization code
            AuthorizationCode authCode = validateAndRetrieveAuthorizationCode(request, clientId);

            // Step 3: Generate access token
            String accessToken = tokenGenerator.generateToken(authCode, request);

            // Step 4: Consume authorization code
            consumeAuthorizationCode(authCode.getCode());

            // Step 5: Build token response
            TokenResponse response = buildTokenResponse(accessToken, tokenGenerator.getExpirationSeconds(), authCode.getScope());

            logger.info("Token issued successfully for client: {}", clientId);
            return response;

        } catch (OAuth2TokenException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during token issuance", e);
            throw OAuth2TokenException.serverError("Internal server error during token issuance", e);
        }
    }

    @Override
    public void validateTokenRequest(TokenRequest request, String clientId) {

        ValidationUtils.validateNotNull(request, "Token request");
        ValidationUtils.validateNotNull(clientId, "Client ID");

        // Validate grant_type (RFC 6749 Section 4.1.3)
        if (request.getGrantType() == null || request.getGrantType().isEmpty()) {
            logger.error("Grant type is missing");
            throw OAuth2TokenException.invalidRequest("grant_type is required");
        }

        if (!"authorization_code".equals(request.getGrantType())) {
            logger.error("Unsupported grant type: {}", request.getGrantType());
            throw OAuth2TokenException.unsupportedGrantType("grant_type must be 'authorization_code'");
        }

        if (request.getCode() == null || request.getCode().isEmpty()) {
            logger.error("Authorization code is missing");
            throw OAuth2TokenException.invalidRequest("Authorization code is required");
        }

        if (request.getRedirectUri() == null || request.getRedirectUri().isEmpty()) {
            logger.error("Redirect URI is missing");
            throw OAuth2TokenException.invalidRequest("Redirect URI is required");
        }

        logger.debug("Token request validated for client: {}", clientId);
    }

    @Override
    public AuthorizationCode validateAndRetrieveAuthorizationCode(TokenRequest request, String clientId) {

        // Retrieve code from request
        String code = request.getCode();

        // Step 1: Retrieve authorization code
        AuthorizationCode authCode = codeStorage.retrieve(code);
        if (authCode == null) {
            logger.error("Authorization code not found: {}", code);
            throw OAuth2TokenException.invalidGrant("Authorization code not found");
        }

        // Step 2: Validate code binding
        validateCodeBinding(authCode, clientId, request);

        // Step 3: Validate code status
        validateCodeStatus(authCode, code);

        logger.debug("Authorization code validated: {}", code);
        return authCode;
    }

    /**
     * Validates the authorization code binding to the client and redirect URI.
     *
     * @param authCode the authorization code
     * @param clientId the client ID
     * @param request the token request
     * @throws OAuth2TokenException if binding validation fails
     */
    private void validateCodeBinding(AuthorizationCode authCode, String clientId, TokenRequest request) {

        // Validate client ID
        if (!authCode.getClientId().equals(clientId)) {
            logger.error("Client ID mismatch: code={}, request={}", authCode.getClientId(), clientId);
            throw OAuth2TokenException.invalidGrant("Authorization code is bound to a different client");
        }

        // Validate redirect URI
        if (!authCode.getRedirectUri().equals(request.getRedirectUri())) {
            logger.error("Redirect URI mismatch: code={}, request={}", authCode.getRedirectUri(), request.getRedirectUri());
            throw OAuth2TokenException.invalidGrant("Redirect URI does not match");
        }

        logger.debug("Code binding validated");
    }

    /**
     * Validates the authorization code status (expiration and usage).
     *
     * @param authCode the authorization code
     * @param code the code string for logging
     * @throws OAuth2TokenException if status validation fails
     */
    private void validateCodeStatus(AuthorizationCode authCode, String code) {

        if (authCode.isExpired()) {
            logger.error("Authorization code expired: {}", code);
            throw OAuth2TokenException.invalidGrant("Authorization code has expired");
        }

        if (authCode.isUsed()) {
            logger.error("Authorization code already used: {}", code);
            throw OAuth2TokenException.invalidGrant("Authorization code has already been used");
        }

        logger.debug("Code status validated");
    }

    /**
     * Consumes the authorization code.
     *
     * @param code the authorization code
     */
    private void consumeAuthorizationCode(String code) {
        codeStorage.consume(code);
        logger.info("Authorization code consumed: {}", code);
    }

    @Override
    public TokenResponse buildTokenResponse(String accessToken, long expiresIn, String scope) {
        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .scope(scope)
                .build();
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
     * Gets the token generator.
     *
     * @return the token generator
     */
    public TokenGenerator getTokenGenerator() {
        return tokenGenerator;
    }
}