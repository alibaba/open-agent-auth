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

/**
 * Server-side interface for handling OAuth 2.0 Token requests.
 * <p>
 * This interface defines the contract for Authorization Servers to process
 * token requests and issue access tokens according to RFC 6749. In the Agent
 * Operation Authorization framework, the access token is an Agent Operation
 * Authorization Token (AOAT).
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 6749 Section 4.1.3):</b></p>
 * <pre>
 * Client                                        Authorization Server (OAuth2TokenServer)
 *  |                                                        |
 *  |-- POST /token (application/x-www-form-urlencoded) --->|
 *  | grant_type=authorization_code                        |
 *  | code=...                                             |
 *  | redirect_uri=...                                     |
 *  | client_id=...                                        |
 *  |                                                        |
 *  |                   1. Authenticate client             |
 *  |                   2. Validate authorization code     |
 *  |                   3. Retrieve authorization request  |
 *  |                   4. Generate access token (AOAT)    |
 *  |                   5. Consume authorization code      |
 *  |                                                        |
 *  |<-- 200 OK (application/json) -------------------------|
 *  | {                                                      |
 *  |   "access_token": "...",                               |
 *  |   "token_type": "Bearer",                              |
 *  |   "expires_in": 3600                                   |
 *  | }                                                      |
 * </pre>
 * <p>
 * <b>Server Responsibilities:</b></p>
 * <ul>
 *   <li><b>Client Authentication:</b> Verify client identity (Basic Auth, JWT, etc.)</li>
 *   <li><b>Code Validation:</b> Validate authorization code signature, expiration, and usage</li>
 *   <li><b>Request Retrieval:</b> Retrieve the original authorization request from PAR</li>
 *   <li><b>Token Generation:</b> Generate an Agent Operation Authorization Token (AOAT)</li>
 *   <li><b>Code Consumption:</b> Mark the authorization code as used</li>
 *   <li><b>Response Building:</b> Build and return the token response</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST authenticate the client</li>
 *   <li>MUST validate the authorization code (not expired, not used, valid binding)</li>
 *   <li>MUST enforce single-use of authorization codes</li>
 *   <li>MUST validate redirect_uri matches original request</li>
 *   <li>MUST generate cryptographically secure access tokens</li>
 * </ul>
 * <p>
 * <b>Agent Operation Authorization Extension:</b></p>
 * <p>
 * Unlike standard OAuth 2.0, this framework generates Agent Operation Authorization Tokens
 * (AOAT) which contain additional claims for agent operations:
 * </p>
 * <ul>
 *   <li><b>agent_identity:</b> Identity of the agent</li>
 *   <li><b>agent_operation_authorization:</b> Authorization metadata with policy_id</li>
 *   <li><b>evidence:</b> Proof of user's original intent</li>
 *   <li><b>context:</b> Authorization context</li>
 *   <li><b>auditTrail:</b> Semantic audit trail</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3">RFC 6749 - Access Token Request</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
public interface OAuth2TokenServer {

    /**
     * Processes a token request and issues an access token.
     * <p>
     * This method performs the following according to RFC 6749:
     * </p>
     * <ol>
     *   <li>Authenticate the client using the provided credentials</li>
     *   <li>Validate the authorization code (not expired, not used, valid binding)</li>
     *   <li>Validate the redirect_uri matches the original authorization request</li>
     *   <li>Retrieve the original authorization request from PAR using the code's request_uri</li>
     *   <li>Extract agent operation authorization claims from the PAR request</li>
     *   <li>Generate an Agent Operation Authorization Token (AOAT)</li>
     *   <li>Mark the authorization code as used (single-use enforcement)</li>
     *   <li>Build and return the token response</li>
     * </ol>
     * <p>
     * <b>Error Handling (RFC 6749 Section 5.2):</b></p>
     * <ul>
     *   <li><b>invalid_request:</b> Missing required parameter, invalid value, or malformed request</li>
     *   <li><b>invalid_client:</b> Client authentication failed</li>
     *   <li><b>invalid_grant:</b> Authorization code is invalid, expired, or already used</li>
     *   <li><b>invalid_scope:</b> Requested scope is invalid or exceeds granted scope</li>
     *   <li><b>unauthorized_client:</b> Client is not authorized to use this grant type</li>
     * </ul>
     *
     * @param request the token request
     * @param clientId the authenticated client identifier
     * @return the token response containing the access token
     * @throws OAuth2TokenException if token issuance fails
     * @throws IllegalArgumentException if request is null or invalid
     */
    TokenResponse issueToken(TokenRequest request, String clientId);

    /**
     * Validates the token request parameters.
     *
     * @param request the token request
     * @param clientId the authenticated client identifier
     * @throws OAuth2TokenException if the request is invalid
     */
    void validateTokenRequest(TokenRequest request, String clientId);

    /**
     * Validates and retrieves the authorization code.
     *
     * @param request the token request
     * @param clientId the authenticated client identifier
     * @return the authorization code
     * @throws OAuth2TokenException if the code is invalid
     */
    AuthorizationCode validateAndRetrieveAuthorizationCode(TokenRequest request, String clientId);

    /**
     * Builds a token response.
     *
     * @param accessToken the access token string
     * @param expiresIn the expiration time in seconds
     * @param scope the scope (maybe null)
     * @return the token response
     */
    TokenResponse buildTokenResponse(String accessToken, long expiresIn, String scope);

}
