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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.server;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;

/**
 * Server-side interface for handling OAuth 2.0 Authorization Code flow.
 * <p>
 * This interface defines the contract for Authorization Servers to process
 * authorization requests and issue authorization codes according to RFC 6749.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 6749 Section 4.1):</b></p>
 * <pre>
 * Client                                        Authorization Server (AuthorizationServer)
 *  |                                                        |
 *  |-- GET /authorize?request_uri=... -------------------->|
 *  |                                                        |
 *  |                   1. Retrieve PAR request             |
 *  |                   2. Authenticate user                |
 *  |                   3. Present consent UI               |
 *  |                   4. Generate authorization code      |
 *  |                   5. Store authorization code         |
 *  |                                                        |
 *  |<-- 302 Found (redirect to client) ---------------------|
 *  | Location: https://client.example.com/callback?       |
 *  |           code=...&state=...                          |
 * </pre>
 * <p>
 * <b>Server Responsibilities:</b></p>
 * <ul>
 *   <li><b>Request Retrieval:</b> Retrieve the original authorization request from PAR</li>
 *   <li><b>User Authentication:</b> Authenticate the user (via IDP, session, etc.)</li>
 *   <li><b>Consent Display:</b> Present the authorization request to the user for consent</li>
 *   <li><b>Code Generation:</b> Generate a secure, single-use authorization code</li>
 *   <li><b>Code Storage:</b> Store the authorization code with expiration</li>
 *   <li><b>Redirection:</b> Redirect the user back to the client with the code</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST authenticate the user before issuing authorization code</li>
 *   <li>MUST obtain explicit user consent</li>
 *   <li>MUST generate cryptographically secure authorization codes</li>
 *   <li>MUST enforce code expiration (recommended: 10 minutes)</li>
 *   <li>MUST enforce single-use of authorization codes</li>
 *   <li>MUST validate redirect_uri matches registered value</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1">RFC 6749 - Authorization Code Grant</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public interface OAuth2AuthorizationServer {

    /**
     * Processes a traditional OAuth 2.0 authorization request and issues an authorization code.
     * <p>
     * This method performs the following according to RFC 6749:
     * </p>
     * <ol>
     *   <li>Validate the client_id and redirect_uri</li>
     *   <li>Authenticate the user (via session, IDP, or other mechanism)</li>
     *   <li>Present the authorization details to the user</li>
     *   <li>Obtain user consent for the requested scope</li>
     *   <li>Generate a cryptographically secure authorization code</li>
     *   <li>Store the authorization code with associated metadata</li>
     *   <li>Return the authorization code for redirection to the client</li>
     * </ol>
     * <p>
     * <b>Authorization Code Generation:</b></p>
     * <ul>
     *   <li>MUST be cryptographically random (minimum 128 bits of entropy)</li>
     *   <li>MUST be unique per request</li>
     *   <li>MUST expire within a short time (recommended: 10 minutes)</li>
     *   <li>MUST be bound to the client_id and redirect_uri</li>
     * </ul>
     *
     * @param subject the authenticated user subject
     * @param clientId the OAuth 2.0 client identifier
     * @param redirectUri the redirect URI
     * @param scopes the requested scopes
     * @return the issued authorization code
     * @throws OAuth2AuthorizationException if authorization fails
     * @throws IllegalArgumentException if any parameter is null or empty
     */
    AuthorizationCode authorize(String subject, String clientId, String redirectUri, String scopes);

    /**
     * Processes an authorization request and issues an authorization code.
     * <p>
     * This method performs the following according to RFC 6749:
     * </p>
     * <ol>
     *   <li>Retrieve the original authorization request using the request_uri from PAR</li>
     *   <li>Authenticate the user (via session, IDP, or other mechanism)</li>
     *   <li>Present the authorization details to the user</li>
     *   <li>Obtain user consent for the requested scope</li>
     *   <li>Generate a cryptographically secure authorization code</li>
     *   <li>Store the authorization code with associated metadata</li>
     *   <li>Return the authorization code for redirection to the client</li>
     * </ol>
     * <p>
     * <b>Authorization Code Generation:</b></p>
     * <ul>
     *   <li>MUST be cryptographically random (minimum 128 bits of entropy)</li>
     *   <li>MUST be unique per request</li>
     *   <li>MUST expire within a short time (recommended: 10 minutes)</li>
     *   <li>MUST be bound to the client_id and redirect_uri</li>
     * </ul>
     *
     * @param requestUri the request URI from PAR
     * @param subject the authenticated user subject
     * @return the issued authorization code
     * @throws OAuth2AuthorizationException if authorization fails
     * @throws IllegalArgumentException if requestUri or subject is null or empty
     */
    AuthorizationCode authorize(String requestUri, String subject);

    /**
     * Validates an authorization request before presenting consent.
     * <p>
     * This method validates the authorization request parameters and ensures
     * that the request is valid and can be presented to the user for consent.
     * </p>
     * <p>
     * <b>Validation Checks:</b></p>
     * <ul>
     *   <li>request_uri is valid and exists</li>
     *   <li>client_id is registered</li>
     *   <li>redirect_uri is registered for the client</li>
     *   <li>response_type is supported</li>
     *   <li>scope is valid and allowed</li>
     * </ul>
     *
     * @param requestUri the request URI from PAR
     * @return true if the request is valid, false otherwise
     * @throws OAuth2AuthorizationException if validation fails
     * @throws IllegalArgumentException if requestUri is null or empty
     */
    boolean validateRequest(String requestUri);

}
