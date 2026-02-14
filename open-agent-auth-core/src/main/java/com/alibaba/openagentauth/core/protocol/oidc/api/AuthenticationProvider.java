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
package com.alibaba.openagentauth.core.protocol.oidc.api;

import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.model.oidc.IdToken;
import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;

/**
 * Interface for handling OpenID Connect authentication.
 * <p>
 * This interface defines the contract for processing authentication requests
 * and issuing ID Tokens. Implementations are responsible for validating
 * authentication requests, authenticating users, and generating ID Tokens.
 * </p>
 * <p>
 * <b>Authentication Flow:</b></p>
 * <pre>
 * Relying Party                                Authorization Server
 *     |                                                 |
 *     |-- Authentication Request ----------------------->|
 *     | response_type=code                             |
 *     | client_id=...                                  |
 *     | redirect_uri=...                               |
 *     | scope=openid                                   |
 *     | state=...                                      |
 *     | nonce=...                                      |
 *     |                                                 |
 *     |                    Validate Request            |
 *     |                    Authenticate User           |
 *     |                    Generate Authorization Code |
 *     |                                                 |
 *     |<-- Redirect to redirect_uri?code=...&state=...-|
 *     |                                                 |
 *     |-- Token Request (POST /token) ----------------->|
 *     | grant_type=authorization_code                  |
 *     | code=...                                       |
 *     | redirect_uri=...                               |
 *     | client_id=...                                  |
 *     | client_secret=...                              |
 *     |                                                 |
 *     |                    Validate Code               |
 *     |                    Issue ID Token              |
 *     |                    Issue Access Token           |
 *     |                                                 |
 *     |<-- Token Response ------------------------------|
 *     | {                                               |
 *     |   "access_token": "...",                        |
 *     |   "id_token": "...",                            |
 *     |   "token_type": "Bearer",                       |
 *     |   "expires_in": 3600                            |
 *     | }                                               |
 * </pre>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST validate all authentication request parameters</li>
 *   <li>MUST authenticate the user</li>
 *   <li>MUST obtain user consent</li>
 *   <li>MUST generate secure authorization codes</li>
 *   <li>MUST issue properly signed ID Tokens</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">OpenID Connect Core 1.0 - Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Flow</a>
 * @since 1.0
 */
public interface AuthenticationProvider {

    /**
     * Processes an authentication request.
     * <p>
     * This method validates the authentication request, authenticates the user,
     * and returns an ID Token if authentication is successful.
     * </p>
     * <p>
     * <b>Validation Steps:</b></p>
     * <ol>
     *   <li>Validate the response_type parameter</li>
     *   <li>Validate the client_id parameter</li>
     *   <li>Validate the redirect_uri parameter</li>
     *   <li>Validate the scope parameter (must include "openid")</li>
     *   <li>Validate the state parameter (recommended)</li>
     *   <li>Validate the nonce parameter (required for implicit flow)</li>
     * </ol>
     * <p>
     * <b>Authentication Steps:</b></p>
     * <ol>
     *   <li>Authenticate the user (if not already authenticated)</li>
     *   <li>Obtain user consent (if required)</li>
     *   <li>Generate an authorization code (for code flow)</li>
     *   <li>Generate an ID Token (for implicit flow)</li>
     * </ol>
     *
     * @param request the authentication request
     * @return the ID Token if authentication is successful
     * @throws AuthenticationException if authentication fails or the request is invalid
     * @throws IllegalArgumentException if request is null
     */
    IdToken authenticate(AuthenticationRequest request);

    /**
     * Validates an authentication request without performing authentication.
     * <p>
     * This method validates the authentication request parameters but does not
     * authenticate the user. This is useful for pre-validation before showing
     * the login page.
     * </p>
     *
     * @param request the authentication request to validate
     * @return true if the request is valid, false otherwise
     * @throws IllegalArgumentException if request is null
     */
    boolean validateRequest(AuthenticationRequest request);

    /**
     * Checks if a user is authenticated.
     * <p>
     * This method checks if the user with the specified subject identifier
     * has an active authentication session.
     * </p>
     *
     * @param subject the subject identifier
     * @return true if the user is authenticated, false otherwise
     * @throws IllegalArgumentException if subject is null or empty
     */
    boolean isAuthenticated(String subject);

    /**
     * Gets the maximum authentication age.
     * <p>
     * This method returns the maximum allowed time in seconds since the last
     * authentication. If the user's last authentication is older than this value,
     * the user must re-authenticate.
     * </p>
     *
     * @return the maximum authentication age in seconds, or null if not configured
     */
    Long getMaxAge();

}
