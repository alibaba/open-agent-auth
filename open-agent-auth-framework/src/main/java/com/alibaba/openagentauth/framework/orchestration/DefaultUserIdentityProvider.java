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

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.actor.UserIdentityProvider;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation for User IDP.
 * <p>
 * This provider delegates to core module's {@link AuthenticationProvider}
 * for authentication and {@link OAuth2TokenServer} for token issuance. It serves
 * as a role-oriented orchestration layer for User IDP actors.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>Authentication Orchestration:</b> Delegates to core AuthenticationProvider</li>
 *   <li><b>Token Issuance:</b> Delegates to core OAuth2TokenServer</li>
 *   <li><b>Response Formatting:</b> Formats authentication response for framework layer</li>
 * </ul>
 *
 * @see UserIdentityProvider
 * @see AuthenticationProvider
 * @since 1.0
 */
public class DefaultUserIdentityProvider implements UserIdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(DefaultUserIdentityProvider.class);

    private final AuthenticationProvider authenticationProvider;
    private final OAuth2TokenServer oAuth2TokenServer;

    /**
     * Creates a new UserIdpProvider.
     *
     * @param authenticationProvider the core authentication provider
     * @param oAuth2TokenServer the OAuth2 token server
     * @throws IllegalArgumentException if any parameter is null
     */
    public DefaultUserIdentityProvider(AuthenticationProvider authenticationProvider, OAuth2TokenServer oAuth2TokenServer) {
        ValidationUtils.validateNotNull(authenticationProvider, "AuthenticationProvider");
        ValidationUtils.validateNotNull(oAuth2TokenServer, "OAuth2TokenServer");
        this.authenticationProvider = authenticationProvider;
        this.oAuth2TokenServer = oAuth2TokenServer;
        logger.info("UserIdpProvider initialized");
    }

    /**
     * Authenticates the user request.
     *
     * @param request the user request
     * @return the authentication response
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest request) throws AuthenticationException {

        // Validate request
        ValidationUtils.validateNotNull(request, "Authentication request");
        logger.debug("Authenticating user request");

        // Delegate to core AuthenticationProvider
        IdToken idToken = authenticationProvider.authenticate(request);

        logger.info("User authenticated successfully: {}", idToken.getClaims().getSub());

        // Format response for framework layer
        return AuthenticationResponse.builder()
                .success(true)
                .idToken(idToken.getTokenValue())
                .tokenType("Bearer")
                .expiresIn(calculateExpiresIn(idToken))
                .build();
    }

    /**
     * Calculates the expires in value from the ID token.
     *
     * @param idToken the ID token
     * @return the expires in value in seconds
     */
    private long calculateExpiresIn(IdToken idToken) {
        Long exp = idToken.getClaims().getExp();
        Long iat = idToken.getClaims().getIat();
        if (exp == null || iat == null) {
            return 0;
        }
        return exp - iat;
    }

    /**
     * Issues a token for the given request.
     * <p>
     * This method implements the OAuth2TokenServer interface, delegating to the
     * core OAuth2TokenServer for actual token issuance.
     * </p>
     *
     * @param request the token request
     * @param clientId the authenticated client identifier
     * @return the token response
     * @throws FrameworkOAuth2TokenException if token issuance fails
     */
    @Override
    public TokenResponse issueToken(TokenRequest request, String clientId) throws FrameworkOAuth2TokenException {
        logger.debug("Issuing token using OAuth2TokenServer");
        try {
            return oAuth2TokenServer.issueToken(request, clientId);
        } catch (Exception e) {
            throw new FrameworkOAuth2TokenException("invalid_request", "Failed to issue token", e);
        }
    }
}