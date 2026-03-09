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
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenServer;
import com.alibaba.openagentauth.spring.util.OAuth2ClientAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for OAuth 2.0 Token endpoint.
 * <p>
 * This controller handles token requests according to OAuth 2.0 specification.
 * It is enabled for authorization-server, agent-user-idp, and as-user-idp roles.
 * </p>
 * <p>
 * <b>Client Authentication:</b> When {@link OAuth2ClientAuthenticator} is available
 * (e.g., in the authorization-server role), both {@code client_secret_basic} and
 * {@code private_key_jwt} authentication methods are supported. When it is not
 * available (e.g., in User IDP roles), only {@code client_secret_basic} is supported.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749 - OAuth 2.0</a>
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(FrameworkOAuth2TokenServer.class)
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
     * The client store for validating client credentials.
     */
    private final OAuth2ClientStore clientStore;

    /**
     * The client authenticator for verifying client credentials.
     * <p>
     * This is nullable because {@link OAuth2ClientAuthenticator} is only available
     * in the authorization-server role (where it needs a {@code JwksProvider} for
     * verifying client assertion signatures). In User IDP roles, this field is null
     * and the controller falls back to Basic Auth only.
     * </p>
     */
    private final OAuth2ClientAuthenticator clientAuthenticator;

    /**
     * Creates a new Token controller with full client authentication support.
     * <p>
     * This constructor is used when {@link OAuth2ClientAuthenticator} is available
     * (typically in the authorization-server role), enabling both {@code client_secret_basic}
     * and {@code private_key_jwt} authentication methods.
     * </p>
     *
     * @param tokenServer the token server
     * @param clientStore the client store for client authentication
     * @param clientAuthenticator the client authenticator
     */
    public OAuth2TokenController(
            FrameworkOAuth2TokenServer tokenServer,
            OAuth2ClientStore clientStore,
            @Autowired(required = false)
            OAuth2ClientAuthenticator clientAuthenticator) {
        this.tokenServer = ValidationUtils.validateNotNull(tokenServer, "Token server");
        this.clientStore = ValidationUtils.validateNotNull(clientStore, "client store");
        this.clientAuthenticator = clientAuthenticator;

        if (clientAuthenticator != null) {
            logger.info("OAuth2TokenController initialized with client store and authenticator (private_key_jwt supported)");
        } else {
            logger.info("OAuth2TokenController initialized with client store (Basic Auth only)");
        }
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
     *   <li>Confidential clients MUST authenticate using a supported method</li>
     *   <li>Supported methods: client_secret_basic (HTTP Basic), private_key_jwt (RFC 7523)</li>
     *   <li>Client credentials are validated against the client store</li>
     * </ul>
     *
     * @param requestBody the token request body as form data
     * @param authorizationHeader the Authorization header for client authentication
     * @return the token response
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
     */
    @PostMapping(
            value = "${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.token:/oauth2/token}",
            consumes = "application/x-www-form-urlencoded"
    )
    public ResponseEntity<Map<String, Object>> token(
            @RequestBody MultiValueMap<String, String> requestBody,
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader
    ) {
        // Step 1: Convert MultiValueMap to Map for processing
        Map<String, String> requestMap = new HashMap<>();
        if (requestBody != null) {
            requestBody.forEach((key, values) -> {
                if (values != null && !values.isEmpty()) {
                    requestMap.put(key, values.get(0));
                }
            });
        }

        String grantType = requestMap.get("grant_type");
        String code = requestMap.get("code");
        String redirectUri = requestMap.get("redirect_uri");
        String requestClientId = requestMap.get("client_id");

        logger.info("Received token request - grant_type: {}, Authorization header present: {}",
                grantType, authorizationHeader != null);
        logger.debug("Token request parameters: grant_type={}, code={}, redirect_uri={}, client_id={}",
                grantType,
                code != null ? code.substring(0, Math.min(code.length(), 10)) + "..." : null,
                redirectUri, requestClientId);

        // Step 2: Authenticate client
        // When OAuth2ClientAuthenticator is available (authorization-server role), supports both
        // client_secret_basic and private_key_jwt. Otherwise, falls back to Basic Auth only.
        logger.debug("Authenticating client for token request (authenticator available: {})...",
                clientAuthenticator != null);
        String authenticatedClientId;
        if (clientAuthenticator != null) {
            authenticatedClientId = clientAuthenticator.authenticateClient(authorizationHeader, requestMap, clientStore);
        } else {
            authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(authorizationHeader, clientStore);
        }
        logger.info("Token request client authenticated successfully: {}", authenticatedClientId);

        // Step 3: Determine the effective client_id for authorization code binding validation.
        // Per RFC 6749 Section 4.1.3, the token request MAY include a client_id parameter.
        // In DCR scenarios, the authorization code is bound to the dynamically registered
        // client_id (UUID), while the HTTP authentication uses the pre-registered agent
        // credentials. The request body client_id takes precedence for code binding validation
        // when it differs from the authenticated client_id.
        String effectiveClientId = (requestClientId != null && !requestClientId.isEmpty())
                ? requestClientId
                : authenticatedClientId;
        if (!effectiveClientId.equals(authenticatedClientId)) {
            logger.info("Using DCR client_id for code binding: {} (authenticated as: {})",
                    effectiveClientId, authenticatedClientId);
        }
        logger.debug("Effective client_id for token exchange: {}", effectiveClientId);

        // Step 4: Parse the token request
        TokenRequest request = TokenRequest.builder()
                .grantType(grantType)
                .code(code)
                .redirectUri(redirectUri)
                .clientId(effectiveClientId)
                .build();
        logger.debug("Token request built - grant_type: {}, client_id: {}, redirect_uri: {}",
                request.getGrantType(), request.getClientId(), request.getRedirectUri());

        // Step 5: Submit to token server
        logger.debug("Submitting token request to server for client: {}", effectiveClientId);
        TokenResponse response = tokenServer.issueToken(request, effectiveClientId);

        logger.info("Token issued successfully - grant_type: {}, client: {}, token_type: {}, expires_in: {}",
                request.getGrantType(), effectiveClientId, response.getTokenType(), response.getExpiresIn());

        // Step 6: Build response body per RFC 6749 Section 5.1 and OIDC Core 1.0 Section 3.1.3.3
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("access_token", response.getAccessToken());
        responseBody.put("token_type", response.getTokenType());
        responseBody.put("expires_in", response.getExpiresIn());

        // Add scope if present
        if (response.getScope() != null) {
            responseBody.put("scope", response.getScope());
        }

        // Add id_token if present (OIDC Core 1.0 Section 3.1.3.3)
        if (response.getIdToken() != null) {
            responseBody.put("id_token", response.getIdToken());
        }

        return ResponseEntity.ok(responseBody);
    }

}