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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.client;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;

/**
 * Client-side interface for Dynamic Client Registration (DCR).
 * <p>
 * This interface defines the contract for OAuth 2.0 Dynamic Client Registration
 * according to RFC 7591 specification. Implementations are responsible for
 * registering clients with the Authorization Server and managing their credentials.
 * </p>
 * <p>
 * <b>Protocol Flow (RFC 7591 Section 3):</b></p>
 * <pre>
 * Client                                        Authorization Server
 *  |                                                    |
 *  |-- POST /register (application/json) -------------->|
 *  | {                                                  |
 *  |   "redirect_uris": ["https://client.example.com/callback"], |
 *  |   "client_name": "My Client",                      |
 *  |   "grant_types": ["authorization_code"],           |
 *  |   "token_endpoint_auth_method": "private_key_jwt"  |
 *  | }                                                  |
 *  |                                                    |
 *  |<-- 201 Created (application/json) ----------------|
 *  | {                                                  |
 *  |   "client_id": "s6BhdRkqt3",                       |
 *  |   "client_secret": "7Fjfp0ZBr1KtDRbnfVdmIw",       |
 *  |   "client_id_issued_at": 1234567890,               |
 *  |   "registration_access_token": "...",              |
 *  |   "registration_client_uri": "..."                 |
 *  | }                                                  |
 * </pre>
 * <p>
 * <b>WIMSE Integration:</b></p>
 * <p>
 * This interface supports WIMSE-based client registration by allowing clients
 * to present a Workload Identity Token (WIT) during registration. The WIT
 * authenticates the workload and binds the OAuth client to a specific
 * workload identity.
 * </p>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>All requests MUST use HTTPS</li>
 *   <li>Initial registration typically requires authentication (e.g., bearer token)</li>
 *   <li>Client secrets MUST be stored securely</li>
 *   <li>Registration access tokens MUST be protected</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7592">RFC 7592 - OAuth 2.0 Dynamic Client Registration Management</a>
 * @see DcrRequest
 * @see DcrResponse
 * @since 1.0
 */
public interface OAuth2DcrClient {

    /**
     * Registers a new OAuth 2.0 client with the Authorization Server.
     * <p>
     * This method performs the following according to RFC 7591:
     * </p>
     * <ol>
     *   <li>Validates the DCR request parameters</li>
     *   <li>Builds the HTTP POST request with Content-Type: application/json</li>
     *   <li>Includes authentication (if required for initial registration)</li>
     *   <li>Sends the request to the registration endpoint</li>
     *   <li>Parses the response and returns the registered client metadata</li>
     * </ol>
     * <p>
     * <b>WIMSE Integration:</b></p>
     * When the DCR request includes a WIT in the {@code wit} field, the client
     * is authenticated using the WIT. The Authorization Server validates the WIT
     * signature and claims before registering the client. The registered client
     * is bound to the workload identity specified in the WIT.
     * </p>
     *
     * @param request the DCR request containing client metadata
     * @return the DCR response with registered client information
     * @throws DcrException if the registration fails
     * @throws IllegalArgumentException if request is null or invalid
     */
    DcrResponse registerClient(DcrRequest request);

    /**
     * Reads the current registration for a registered client.
     * <p>
     * This method retrieves the current client metadata using the registration
     * access token and registration client URI returned during registration.
     * </p>
     *
     * @param registrationClientUri the registration client URI
     * @param registrationAccessToken the registration access token
     * @return the current DCR response with client metadata
     * @throws DcrException if the read operation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    DcrResponse readClient(String registrationClientUri, String registrationAccessToken);

    /**
     * Updates the registration for a registered client.
     * <p>
     * This method updates client metadata using the registration access token
     * and registration client URI. Only the fields present in the request are
     * updated; other fields remain unchanged.
     * </p>
     *
     * @param registrationClientUri the registration client URI
     * @param registrationAccessToken the registration access token
     * @param request the DCR request containing updated metadata
     * @return the updated DCR response
     * @throws DcrException if the update operation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    DcrResponse updateClient(String registrationClientUri, String registrationAccessToken, DcrRequest request);

    /**
     * Deletes the registration for a registered client.
     * <p>
     * This method permanently deletes the client registration using the
     * registration access token and registration client URI. After deletion,
     * the client_id is no longer valid.
     * </p>
     *
     * @param registrationClientUri the registration client URI
     * @param registrationAccessToken the registration access token
     * @throws DcrException if the delete operation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    void deleteClient(String registrationClientUri, String registrationAccessToken);

}
