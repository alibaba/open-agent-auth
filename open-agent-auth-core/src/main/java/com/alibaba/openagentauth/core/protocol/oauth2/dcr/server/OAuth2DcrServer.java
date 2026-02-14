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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.server;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;

/**
 * Server-side interface for Dynamic Client Registration (DCR).
 * <p>
 * This interface defines the contract for OAuth 2.0 Dynamic Client Registration
 * server implementation according to RFC 7591 specification. Implementations are
 * responsible for processing client registration requests and managing client metadata.
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
 *  |   "wit": "eyJ..."  (Workload Identity Token)       |
 *  | }                                                  |
 *  |                                                    |
 *  |<-- 201 Created (application/json) ----------------|
 *  | {                                                  |
 *  |   "client_id": "s6BhdRkqt3",                       |
 *  |   "client_secret": "7Fjfp0ZBr1KtDRbnfVdmIw",       |
 *  |   "registration_access_token": "...",              |
 *  |   "registration_client_uri": "..."                 |
 *  | }                                                  |
 * </pre>
 * <p>
 * <b>WIMSE Integration:</b></p>
 * <p>
 * This interface supports WIMSE-based client registration by validating
 * Workload Identity Tokens (WIT) presented by clients. The WIT authenticates
 * the workload and binds the OAuth client to a specific workload identity.
 * </p>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>Validate WIT signature and claims before registration</li>
 *   <li>Generate cryptographically secure client IDs and secrets</li>
 *   <li>Generate unique registration access tokens</li>
 *   <li>Store client metadata securely</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7592">RFC 7592 - OAuth 2.0 Dynamic Client Registration Management</a>
 * @see DcrRequest
 * @see DcrResponse
 * @since 1.0
 */
public interface OAuth2DcrServer {

    /**
     * Registers a new OAuth 2.0 client.
     * <p>
     * This method performs the following according to RFC 7591:
     * </p>
     * <ol>
     *   <li>Validates the WIT (if present) to authenticate the workload</li>
     *   <li>Validates the DCR request parameters (redirect_uris, etc.)</li>
     *   <li>Generates a unique client_id</li>
     *   <li>Generates client_secret (if needed based on token_endpoint_auth_method)</li>
     *   <li>Generates registration_access_token</li>
     *   <li>Stores the client metadata</li>
     *   <li>Returns the registration response</li>
     * </ol>
     * <p>
     * <b>WIMSE Integration:</b></p>
     * When the DCR request includes a WIT in the {@code wit} field, the server
     * validates the WIT signature and claims. The registered client is bound to
     * the workload identity specified in the WIT. This ensures that only
     * authenticated workloads can register clients.
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
     * access token. The token is validated before returning the client metadata.
     * </p>
     *
     * @param clientId the client identifier
     * @param registrationAccessToken the registration access token
     * @return the current DCR response with client metadata
     * @throws DcrException if the read operation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    DcrResponse readClient(String clientId, String registrationAccessToken);

    /**
     * Updates the registration for a registered client.
     * <p>
     * This method updates client metadata using the registration access token.
     * Only the fields present in the request are updated; other fields remain
     * unchanged. The token is validated before applying updates.
     * </p>
     *
     * @param clientId the client identifier
     * @param registrationAccessToken the registration access token
     * @param request the DCR request containing updated metadata
     * @return the updated DCR response
     * @throws DcrException if the update operation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    DcrResponse updateClient(String clientId, String registrationAccessToken, DcrRequest request);

    /**
     * Deletes the registration for a registered client.
     * <p>
     * This method permanently deletes the client registration using the
     * registration access token. After deletion, the client_id is no longer
     * valid. The token is validated before deletion.
     * </p>
     *
     * @param clientId the client identifier
     * @param registrationAccessToken the registration access token
     * @throws DcrException if the delete operation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    void deleteClient(String clientId, String registrationAccessToken);

}
