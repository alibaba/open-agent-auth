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

import com.alibaba.openagentauth.core.protocol.oauth2.token.revocation.TokenRevocationService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for OAuth 2.0 Token Revocation endpoint.
 * <p>
 * This controller handles token revocation requests according to RFC 7009.
 * The endpoint allows clients to notify the authorization server that a previously
 * obtained access or refresh token is no longer needed.
 * </p>
 * <p>
 * <b>Endpoint:</b> {@code POST /oauth2/revoke}
 * </p>
 * <p>
 * <b>Request Parameters:</b></p>
 * <ul>
 *   <li>{@code token} (REQUIRED): The token to revoke</li>
 *   <li>{@code token_type_hint} (OPTIONAL): A hint about the type of token
 *       ({@code access_token} or {@code refresh_token})</li>
 * </ul>
 * <p>
 * <b>Response Format:</b></p>
 * <ul>
 *   <li>HTTP 200 (OK) - Token was successfully revoked or already revoked</li>
 *   <li>HTTP 400 (Bad Request) - Missing required {@code token} parameter</li>
 * </ul>
 * <p>
 * <b>Important:</b> Per RFC 7009 Section 2.1, the authorization server MUST respond
 * with HTTP 200 (OK) regardless of whether the token was valid, invalid, or already
 * revoked. This prevents information leakage about token validity.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7009">RFC 7009 - OAuth 2.0 Token Revocation</a>
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(TokenRevocationService.class)
public class TokenRevocationController {

    private static final Logger logger = LoggerFactory.getLogger(TokenRevocationController.class);

    /**
     * The required token parameter name.
     */
    private static final String PARAM_TOKEN = "token";

    /**
     * The optional token type hint parameter name.
     */
    private static final String PARAM_TOKEN_TYPE_HINT = "token_type_hint";

    /**
     * The token revocation service for managing revoked tokens.
     */
    private final TokenRevocationService tokenRevocationService;

    /**
     * Creates a new token revocation controller.
     *
     * @param tokenRevocationService the token revocation service
     */
    public TokenRevocationController(TokenRevocationService tokenRevocationService) {
        this.tokenRevocationService = tokenRevocationService;
        logger.info("TokenRevocationController initialized");
    }

    /**
     * Token revocation endpoint (RFC 7009 Section 2).
     * <p>
     * Handles POST requests to revoke access tokens or refresh tokens.
     * </p>
     * <p>
     * <b>Request Processing:</b></p>
     * <ol>
     *   <li>Validate the required {@code token} parameter</li>
     *   <li>Revoke the token using {@link TokenRevocationService}</li>
     *   <li>Return HTTP 200 (OK) per RFC 7009 Section 2.1</li>
     * </ol>
     * <p>
     * <b>Response:</b> Returns HTTP 200 with an empty body if successful,
     * or HTTP 400 with error {@code invalid_request} if the token parameter is missing.
     * </p>
     *
     * @param request the HTTP request containing the revocation parameters
     * @return the response entity
     */
    @PostMapping("${open-agent-auth.capabilities.oauth2-server.endpoints.oauth2.revocation:/oauth2/revoke}")
    public ResponseEntity<Map<String, Object>> revoke(HttpServletRequest request) {
        try {
            // Step 1: Extract required token parameter
            String token = request.getParameter(PARAM_TOKEN);
            if (token == null || token.isBlank()) {
                logger.warn("Token revocation request failed: missing or empty token parameter");
                return badRequestResponse("invalid_request", "Token parameter is required");
            }

            // Step 2: Extract optional token_type_hint parameter (for logging purposes)
            String tokenTypeHint = request.getParameter(PARAM_TOKEN_TYPE_HINT);
            logger.info("Token revocation request received, token_type_hint: {}", tokenTypeHint);

            // Step 3: Revoke the token
            tokenRevocationService.revoke(token);

            // Step 4: Return HTTP 200 (OK) per RFC 7009 Section 2.1
            // The response MUST be HTTP 200 regardless of token validity
            logger.info("Token revoked successfully");
            return ResponseEntity.ok().build();

        } catch (Exception e) {
            logger.error("Unexpected error processing token revocation request: {}", e.getMessage(), e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("server_error", "Internal server error"));
        }
    }

    /**
     * Creates a 400 Bad Request response with OAuth 2.0 error format.
     *
     * @param error the error code
     * @param errorDescription the error description
     * @return the bad request response entity
     */
    private ResponseEntity<Map<String, Object>> badRequestResponse(String error, String errorDescription) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(createErrorResponse(error, errorDescription));
    }

    /**
     * Creates an error response map per RFC 7009 Section 2.2.
     *
     * @param error the error code
     * @param errorDescription the error description
     * @return the error response map
     */
    private Map<String, Object> createErrorResponse(String error, String errorDescription) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", error);
        response.put("error_description", errorDescription);
        return response;
    }
}
