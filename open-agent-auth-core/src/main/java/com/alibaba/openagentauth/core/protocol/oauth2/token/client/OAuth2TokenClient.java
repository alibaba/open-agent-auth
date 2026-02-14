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
package com.alibaba.openagentauth.core.protocol.oauth2.token.client;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;

/**
 * Client-side interface for OAuth 2.0 Token requests.
 * <p>
 * This interface defines the contract for clients to exchange authorization codes
 * for access tokens according to RFC 6749. Implementations are responsible for
 * sending token requests to the Authorization Server and processing the responses.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 6749 Section 4.1.3):</b></p>
 * <pre>
 * Client                                        Authorization Server
 *  |                                                    |
 *  |-- POST /token (application/x-www-form-urlencoded) ->|
 *  | grant_type=authorization_code                     |
 *  | code=...                                          |
 *  | redirect_uri=...                                   |
 *  | Authorization: Basic [client_credentials]          |
 *  |                                                    |
 *  |                   Authenticate client              |
 *  |                   Validate authorization code      |
 *  |                   Generate access token            |
 *  |                                                    |
 *  |<-- 200 OK (application/json) ----------------------|
 *  | {                                                  |
 *  |   "access_token": "...",                           |
 *  |   "token_type": "Bearer",                          |
 *  |   "expires_in": 3600                               |
 *  | }                                                  |
 * </pre>
 * <p>
 * <b>Client Responsibilities:</b></p>
 * <ul>
 *   <li><b>Request Construction:</b> Build the token request with required parameters</li>
 *   <li><b>Client Authentication:</b> Authenticate using Basic Auth, JWT, or other method</li>
 *   <li><b>Request Submission:</b> Send the request to the token endpoint</li>
 *   <li><b>Response Handling:</b> Parse the token response</li>
 *   <li><b>Error Handling:</b> Handle token errors gracefully</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST use HTTPS for all token requests</li>
 *   <li>MUST authenticate using one of the supported methods</li>
 *   <li>MUST protect client credentials</li>
 *   <li>MUST handle error responses securely</li>
 *   <li>MUST store access tokens securely</li>
 * </ul>
 * <p>
 * <b>Agent Operation Authorization Extension:</b></p>
 * <p>
 * In the Agent Operation Authorization framework, the access_token returned is an
 * Agent Operation Authorization Token (AOAT), which contains additional claims for
 * agent operations beyond standard OAuth 2.0.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
public interface OAuth2TokenClient {

    /**
     * Exchanges an authorization code for an access token.
     * <p>
     * This method performs the following according to RFC 6749:
     * </p>
     * <ol>
     *   <li>Build the token request with the authorization code</li>
     *   <li>Authenticate the client using the configured method</li>
     *   <li>Send the POST request to the token endpoint</li>
     *   <li>Parse the response and extract the access token</li>
     *   <li>Return the token response</li>
     * </ol>
     * <p>
     * <b>HTTP Request Format:</b></p>
     * <pre>
     * POST /token HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * Authorization: Basic [base64(client_id:client_secret)]
     *
     * grant_type=authorization_code&code=...&redirect_uri=...
     * </pre>
     * <p>
     * <b>HTTP Response Format (Success):</b></p>
     * <pre>
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     * Cache-Control: no-store
     *
     * {
     *   "access_token": "...",
     *   "token_type": "Bearer",
     *   "expires_in": 3600,
     *   "scope": "..."
     * }
     * </pre>
     * <p>
     * <b>HTTP Response Format (Error):</b></p>
     * <pre>
     * HTTP/1.1 400 Bad Request
     * Content-Type: application/json
     *
     * {
     *   "error": "invalid_grant",
     *   "error_description": "The authorization code is invalid"
     * }
     * </pre>
     *
     * @param request the token request containing the authorization code
     * @return the token response containing the access token
     * @throws OAuth2TokenException if token exchange fails
     * @throws IllegalArgumentException if request is null or invalid
     */
    TokenResponse exchangeCodeForToken(TokenRequest request);

    /**
     * Refreshes an access token using a refresh token.
     * <p>
     * This method exchanges a refresh token for a new access token when the current
     * access token expires. This is an optional feature and may not be supported
     * by all Authorization Servers.
     * </p>
     * <p>
     * <b>HTTP Request Format:</b></p>
     * <pre>
     * POST /token HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * Authorization: Basic [base64(client_id:client_secret)]
     *
     * grant_type=refresh_token&refresh_token=...
     * </pre>
     *
     * @param refreshToken the refresh token
     * @return a new token response with a fresh access token
     * @throws OAuth2TokenException if token refresh fails
     * @throws IllegalArgumentException if refreshToken is null or empty
     */
    TokenResponse refreshToken(String refreshToken);

    /**
     * Revokes an access token or refresh token.
     * <p>
     * This method revokes the specified token, making it invalid for future use.
     * This is an optional feature based on RFC 7009.
     * </p>
     *
     * @param token the token to revoke
     * @param tokenType the type of token ("access_token" or "refresh_token")
     * @throws OAuth2TokenException if token revocation fails
     * @throws IllegalArgumentException if parameters are invalid
     */
    void revokeToken(String token, String tokenType);

}
