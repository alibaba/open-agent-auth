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
package com.alibaba.openagentauth.core.protocol.oauth2.par.server;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;

/**
 * Server-side interface for handling Pushed Authorization Requests (PAR).
 * <p>
 * This interface defines the contract for Authorization Servers to process
 * PAR requests according to RFC 9126 specification. Implementations are
 * responsible for receiving, validating, and storing authorization requests.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 9126 Section 2):</b></p>
 * <pre>
 * Client                                        Authorization Server (ParServer)
 *  |                                                        |
 *  |-- POST /par (application/x-www-form-urlencoded) ----->|
 *  | request=eyJ... (authorization request JWT)             |
 *  |                                                        |
 *  |                   1. Validate client authentication    |
 *  |                   2. Validate request JWT signature   |
 *  |                   3. Validate required parameters     |
 *  |                   4. Generate unique request_uri       |
 *  |                   5. Store request with expiration    |
 *  |                                                        |
 *  |<-- 200 OK (application/json) --------------------------|
 *  | {                                                      |
 *  |   "request_uri": "urn:ietf:params:oauth:request_uri:...", |
 *  |   "expires_in": 90                                     |
 *  | }                                                      |
 * </pre>
 * <p>
 * <b>Server Responsibilities:</b></p>
 * <ul>
 *   <li><b>Client Authentication:</b> Verify client identity (RFC 9126 Section 2.1)</li>
 *   <li><b>Request Validation:</b> Validate JWT signature, expiration, required claims</li>
 *   <li><b>Parameter Validation:</b> Check response_type, client_id, redirect_uri</li>
 *   <li><b>Request Storage:</b> Store authorization request with expiration</li>
 *   <li><b>URI Generation:</b> Generate unique URN-format request_uri</li>
 *   <li><b>Security:</b> Prevent replay attacks, enforce one-time use</li>
 * </ul>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>MUST require client authentication (per RFC 9126 Section 2.1)</li>
 *   <li>MUST validate request JWT signature and claims</li>
 *   <li>MUST generate request_uri with sufficient entropy (RFC 9126 Section 7.1)</li>
 *   <li>SHOULD treat request_uri as one-time use (RFC 9126 Section 7.3)</li>
 *   <li>MUST reject expired request_uri values</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see ParRequest
 * @see ParResponse
 * @since 1.0
 */
public interface OAuth2ParServer {

    /**
     * Processes a Pushed Authorization Request from a client.
     * <p>
     * This method performs the following according to RFC 9126:
     * </p>
     * <ol>
     *   <li>Authenticate the client (Basic Auth, MTLS, or other method)</li>
     *   <li>Validate the request JWT signature and claims</li>
     *   <li>Validate required OAuth 2.0 parameters (response_type, client_id, redirect_uri)</li>
     *   <li>Generate a unique request_uri with sufficient entropy</li>
     *   <li>Store the authorization request content with expiration time</li>
     *   <li>Return the request_uri and expires_in to the client</li>
     * </ol>
     * <p>
     * <b>Error Handling (RFC 9126 Section 2.2):</b></p>
     * <ul>
     *   <li><b>invalid_request:</b> Missing required parameter, invalid value, or malformed request</li>
     *   <li><b>invalid_client:</b> Client authentication failed</li>
     *   <li><b>invalid_redirect_uri:</b> Redirect URI is invalid or not registered</li>
     * </ul>
     *
     * @param request the PAR request containing authorization parameters
     * @param clientId the authenticated client identifier
     * @return the PAR response with request_uri and expires_in
     * @throws ParException if the PAR processing fails
     * @throws IllegalArgumentException if request is null or invalid
     */
    ParResponse processParRequest(ParRequest request, String clientId);

    /**
     * Retrieves a stored PAR request by its request_uri.
     * <p>
     * This method is called during the authorization phase to retrieve the original
     * authorization request that was previously submitted via PAR. The request_uri
     * must be valid and not expired.
     * </p>
     * <p>
     * <b>Usage:</b></p>
     * <pre>
     * // After user authorization, retrieve the original request
     * ParRequest request = parServer.retrieveRequest(requestUri);
     * // Use the request to build the authorization response
     * </pre>
     *
     * @param requestUri the request URI returned from PAR submission
     * @return the stored PAR request
     * @throws ParException if the request_uri is invalid, expired, or not found
     * @throws IllegalArgumentException if requestUri is null or blank
     */
    ParRequest retrieveRequest(String requestUri);
}
