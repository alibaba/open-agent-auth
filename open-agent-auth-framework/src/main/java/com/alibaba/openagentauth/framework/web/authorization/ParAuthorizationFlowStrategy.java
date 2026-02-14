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
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * PAR (Pushed Authorization Request) authorization flow strategy.
 * <p>
 * This strategy handles OAuth 2.0 authorization requests using the Pushed Authorization Request
 * mechanism as defined in RFC 9126. It encapsulates all PAR-specific logic, making it easy to
 * maintain and test independently.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 9126 Section 3):</b></p>
 * <pre>
 * Client                                          Authorization Server
 *  |                                                    |
 *  |-- POST /par (request JWT) ----------------------->|
 *  |                                                    |
 *  |<-- 200 OK {request_uri, expires_in} -------------|
 *  |                                                    |
 *  |-- GET /authorize?request_uri=urn:... ------------>|
 *  |                                                    |
 *  |                   User authenticates              |
 *  |                   User consents                    |
 *  |                                                    |
 *  |<-- 302 Found (redirect to client) ----------------|
 *  | Location: https://client.example.com/callback?   |
 *  |           code=...&state=...                      |
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class ParAuthorizationFlowStrategy implements AuthorizationFlowStrategy {

    private static final Logger logger = LoggerFactory.getLogger(ParAuthorizationFlowStrategy.class);

    private final OAuth2AuthorizationServer authorizationServer;
    private final OAuth2ParServer parServer;

    /**
     * Creates a new PAR authorization flow strategy.
     *
     * @param authorizationServer the authorization server (must not be null)
     * @param parServer the PAR server (must not be null)
     * @throws IllegalArgumentException if any parameter is null
     */
    public ParAuthorizationFlowStrategy(
            OAuth2AuthorizationServer authorizationServer,
            OAuth2ParServer parServer) {
        this.authorizationServer = ValidationUtils.validateNotNull(authorizationServer, "authorizationServer");
        this.parServer = ValidationUtils.validateNotNull(parServer, "parServer");
    }

    @Override
    public boolean supports(HttpServletRequest request) {
        String requestUri = request.getParameter("request_uri");
        return requestUri != null && !requestUri.isBlank();
    }

    @Override
    public AuthorizationRequestContext parseRequest(HttpServletRequest request) {
        String requestUri = request.getParameter("request_uri");
        String state = request.getParameter("state");

        logger.debug("Parsing PAR authorization request: requestUri={}, state={}", requestUri, state);

        return AuthorizationRequestContext.builder()
                .flowType("PAR")
                .requestUri(requestUri)
                .state(state)
                .build();
    }

    @Override
    public void validateRequest(AuthorizationRequestContext context) {
        logger.info("Validating PAR request: {}", context.getRequestUri());

        if (!authorizationServer.validateRequest(context.getRequestUri())) {
            throw new OAuth2AuthorizationException(
                    OAuth2RfcErrorCode.INVALID_REQUEST,
                    "Invalid or expired request_uri"
            );
        }

        logger.debug("PAR request validation successful");
    }

    @Override
    public AuthorizationCodeResult issueCode(AuthorizationRequestContext context, String subject) {
        logger.info("Issuing authorization code for PAR flow: requestUri={}, subject={}",
                context.getRequestUri(), subject);

        AuthorizationCode authorizationCode = authorizationServer.authorize(
                context.getRequestUri(),
                subject
        );

        ParRequest parRequest = parServer.retrieveRequest(context.getRequestUri());

        logger.debug("Authorization code issued: code={}, state={}",
                authorizationCode.getCode(), parRequest.getState());

        return new AuthorizationCodeResult(
                authorizationCode.getCode(),
                parRequest.getRedirectUri(),
                parRequest.getState()
        );
    }
}