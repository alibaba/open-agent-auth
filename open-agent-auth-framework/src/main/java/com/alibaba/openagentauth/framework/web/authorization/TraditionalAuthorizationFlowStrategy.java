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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Traditional OAuth 2.0 authorization code flow strategy.
 * <p>
 * This strategy handles standard OAuth 2.0 authorization code requests as defined in RFC 6749.
 * It encapsulates all traditional flow logic, making it easy to maintain and test independently.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 6749 Section 4.1):</b></p>
 * <pre>
 * Client                                          Authorization Server
 *  |                                                    |
 *  |-- GET /authorize?response_type=code              |
 *  |     &client_id=...&redirect_uri=... ------------>|
 *  |                                                    |
 *  |                   User authenticates              |
 *  |                   User consents                    |
 *  |                                                    |
 *  |<-- 302 Found (redirect to client) ----------------|
 *  | Location: https://client.example.com/callback?   |
 *  |           code=...&state=...                      |
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Grant</a>
 * @since 1.0
 */
public class TraditionalAuthorizationFlowStrategy implements AuthorizationFlowStrategy {

    private static final Logger logger = LoggerFactory.getLogger(TraditionalAuthorizationFlowStrategy.class);

    private final OAuth2AuthorizationServer authorizationServer;

    /**
     * Creates a new traditional authorization flow strategy.
     *
     * @param authorizationServer the authorization server (must not be null)
     * @throws IllegalArgumentException if authorizationServer is null
     */
    public TraditionalAuthorizationFlowStrategy(OAuth2AuthorizationServer authorizationServer) {
        this.authorizationServer = ValidationUtils.validateNotNull(authorizationServer, "authorizationServer");
    }

    @Override
    public boolean supports(HttpServletRequest request) {
        return request.getParameter("request_uri") == null
                && request.getParameter("response_type") != null
                && request.getParameter("client_id") != null
                && request.getParameter("redirect_uri") != null;
    }

    @Override
    public AuthorizationRequestContext parseRequest(HttpServletRequest request) {
        String responseType = request.getParameter("response_type");
        String clientId = request.getParameter("client_id");
        String redirectUri = request.getParameter("redirect_uri");
        String scope = request.getParameter("scope");
        String state = request.getParameter("state");

        logger.debug("Parsing traditional authorization request: responseType={}, clientId={}, redirectUri={}, scope={}, state={}",
                responseType, clientId, redirectUri, scope, state);

        return AuthorizationRequestContext.builder()
                .flowType("TRADITIONAL")
                .responseType(responseType)
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .state(state)
                .build();
    }

    @Override
    public void validateRequest(AuthorizationRequestContext context) {
        logger.info("Validating traditional authorization request");

        if (!"code".equals(context.getResponseType())) {
            throw new OAuth2AuthorizationException(
                    OAuth2RfcErrorCode.UNSUPPORTED_RESPONSE_TYPE,
                    "Only 'code' response_type is supported"
            );
        }

        logger.debug("Traditional authorization request validation successful");
    }

    @Override
    public AuthorizationCodeResult issueCode(AuthorizationRequestContext context, String subject) {
        logger.info("Issuing authorization code for traditional flow: clientId={}, subject={}",
                context.getClientId(), subject);

        String scopes = context.getScope() != null ? context.getScope() : "";

        AuthorizationCode authorizationCode = authorizationServer.authorize(
                subject,
                context.getClientId(),
                context.getRedirectUri(),
                scopes
        );

        logger.debug("Authorization code issued: code={}, state={}",
                authorizationCode.getCode(), context.getState());

        return new AuthorizationCodeResult(
                authorizationCode.getCode(),
                context.getRedirectUri(),
                context.getState()
        );
    }
}