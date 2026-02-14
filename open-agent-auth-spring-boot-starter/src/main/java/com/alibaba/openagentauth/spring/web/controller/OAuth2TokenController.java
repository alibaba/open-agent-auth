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

import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenServer;
import com.alibaba.openagentauth.spring.util.OAuth2ClientAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controller for OAuth 2.0 Token endpoint.
 * <p>
 * This controller handles token requests according to OAuth 2.0 specification.
 * It is enabled for authorization-server, agent-user-idp, and as-user-idp roles.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749 - OAuth 2.0</a>
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnExpression("'${open-agent-auth.roles.agent-user-idp.enabled:false}' == 'true' or '${open-agent-auth.roles.authorization-server.enabled:false}' == 'true' or '${open-agent-auth.roles.as-user-idp.enabled:false}' == 'true'")
public class OAuth2TokenController {

    /**
     * The logger for the Token controller.
     */
    private static final Logger logger = LoggerFactory.getLogger(OAuth2TokenController.class);

    /**
     * The token server.
     */
    private final FrameworkOAuth2TokenServer tokenServer;

    /**
     * The DCR client store for validating client credentials.
     */
    private final OAuth2DcrClientStore clientStore;

    /**
     * Creates a new Token controller.
     *
     * @param tokenServer the token server
     * @param clientStore the DCR client store for client authentication
     */
    public OAuth2TokenController(FrameworkOAuth2TokenServer tokenServer, OAuth2DcrClientStore clientStore) {
        this.tokenServer = ValidationUtils.validateNotNull(tokenServer, "Token server");
        this.clientStore = ValidationUtils.validateNotNull(clientStore, "DCR client store");
        logger.info("OAuth2TokenController initialized with client store");
    }

    /**
     * Token endpoint.
     * <p>
     * Accepts token requests and issues access tokens according to OAuth 2.0 RFC 6749 specification.
     * The endpoint accepts application/x-www-form-urlencoded content type as per the standard.
     * </p>
     * <p>
     * <b>Client Authentication (RFC 6749 Section 2.3):</b></p>
     * <ul>
     *   <li>Confidential clients MUST authenticate using HTTP Basic authentication</li>
     *   <li>Authorization header format: Basic base64(client_id:client_secret)</li>
     *   <li>Client credentials are validated against the DCR client store</li>
     * </ul>
     *
     * @param grantType the grant type (e.g., authorization_code, refresh_token)
     * @param code the authorization code (required for authorization_code grant)
     * @param redirectUri the redirect URI (required for authorization_code grant)
     * @param authorizationHeader the Authorization header for client authentication
     * @return the token response
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
     */
    @PostMapping(value = "${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.token:/oauth2/token}", consumes = "application/x-www-form-urlencoded")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam(value = "grant_type") String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        try {
            logger.info("Received token request with grant_type: {}", grantType);

            // Step 1: Authenticate client using Basic Auth (RFC 6749 Section 2.3.1)
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authorizationHeader, clientStore);
            logger.debug("Client authenticated: {}", authenticatedClientId);

            // Step 2: Parse the token request
            TokenRequest request = TokenRequest.builder()
                    .grantType(grantType)
                    .code(code)
                    .redirectUri(redirectUri)
                    .clientId(authenticatedClientId)
                    .build();

            // Step 3: Submit to token server
            TokenResponse response = tokenServer.issueToken(request, authenticatedClientId);

            logger.info("Token issued successfully for grant_type: {}", request.getGrantType());

            // Step 4: Build response body dynamically
            Map<String, Object> responseBody = new java.util.HashMap<>();
            responseBody.put("access_token", response.getAccessToken());
            responseBody.put("token_type", response.getTokenType());
            responseBody.put("expires_in", response.getExpiresIn());
            
            // Add scope if present
            if (response.getScope() != null) {
                responseBody.put("scope", response.getScope());
            }
            
            return ResponseEntity.ok(responseBody);

        } catch (FrameworkOAuth2TokenException e) {
            logger.error("Token request failed: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                            "error", e.getErrorCode(),
                            "error_description", e.getErrorDescription()
                    ));
        } catch (Exception e) {
            logger.error("Unexpected error processing token request: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of(
                            "error", "server_error",
                            "error_description", "Internal server error"
                    ));
        }
    }

}