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
package com.alibaba.openagentauth.core.protocol.oauth2.par.client;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;

/**
 * Client-side interface for Pushed Authorization Requests (PAR).
 * <p>
 * This interface defines the contract for OAuth 2.0 PAR clients according to
 * RFC 9126 specification. Implementations are responsible for submitting
 * authorization requests to the Authorization Server and receiving request URIs.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 9126 Section 2):</b></p>
 * <pre>
 * Client                                        Authorization Server
 *  |                                                    |
 *  |-- POST /par (application/x-www-form-urlencoded) ->|
 *  | request=eyJ... (authorization request JWT)        |
 *  |                                                    |
 *  |<-- 200 OK (application/json) ---------------------|
 *  | {                                                  |
 *  |   "request_uri": "urn:ietf:params:oauth:request_uri:...", |
 *  |   "expires_in": 90                                 |
 *  | }                                                  |
 * </pre>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>All requests MUST use HTTPS</li>
 *   <li>The request parameter MUST be signed (JWT)</li>
 *   <li>Client authentication is REQUIRED (per RFC 9126 Section 2.1)</li>
 *   <li>request_uri MUST only be used once (per RFC 9126 Section 4)</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see ParRequest
 * @see ParResponse
 * @since 1.0
 */
public interface OAuth2ParClient {

    /**
     * Submits a Pushed Authorization Request to the Authorization Server.
     * <p>
     * This method performs the following according to RFC 9126:
     * </p>
     * <ol>
     *   <li>Builds the HTTP POST request with Content-Type: application/x-www-form-urlencoded</li>
     *   <li>Includes the request parameter containing the authorization request (JWT)</li>
     *   <li>Performs client authentication (as required by the AS)</li>
     *   <li>Sends the request to the PAR endpoint</li>
     *   <li>Parses the response and returns the request_uri</li>
     * </ol>
     * <p>
     * <b>HTTP Request Format:</b></p>
     * <pre>
     * POST /par HTTP/1.1
     * Host: as.example.com
     * Content-Type: application/x-www-form-urlencoded
     * Authorization: Basic [client_credentials]  (or other auth method)
     *
     * request=eyJ...
     * </pre>
     * <p>
     * <b>HTTP Response Format (Success):</b></p>
     * <pre>
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     * Cache-Control: no-store
     *
     * {
     *   "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
     *   "expires_in": 90
     * }
     * </pre>
     * <p>
     * <b>HTTP Response Format (Error):</b></p>
     * <pre>
     * HTTP/1.1 400 Bad Request
     * Content-Type: application/json
     *
     * {
     *   "error": "invalid_request",
     *   "error_description": "The request is missing a required parameter"
     * }
     * </pre>
     *
     * @param request the PAR request containing authorization parameters
     * @return the PAR response with request_uri and expires_in
     * @throws ParException if the PAR submission fails
     * @throws IllegalArgumentException if request is null or invalid
     */
    ParResponse submitParRequest(ParRequest request);

}
