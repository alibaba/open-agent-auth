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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.store;

import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;

/**
 * Storage interface for Dynamic Client Registration (DCR) client metadata.
 * <p>
 * This interface defines the contract for storing and retrieving OAuth 2.0 client
 * registration information. Implementations can use various storage backends such
 * as in-memory, database, or distributed cache.
 * </p>
 * <p>
 * <b>Storage Requirements:</b></p>
 * <ul>
 *   <li>Store client metadata keyed by client_id</li>
 *   <li>Store registration access tokens for client management</li>
 *   <li>Support CRUD operations for client registration</li>
 *   <li>Handle concurrent access safely</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
public interface OAuth2DcrClientStore {

    /**
     * Stores a newly registered client.
     *
     * @param clientId the client identifier
     * @param registrationAccessToken the registration access token
     * @param request the original DCR request
     * @param response the DCR response with registered client information
     */
    void store(String clientId, String registrationAccessToken, DcrRequest request, DcrResponse response);

    /**
     * Retrieves a client by its client ID.
     *
     * @param clientId the client identifier
     * @return the DCR response with client metadata, or null if not found
     */
    DcrResponse retrieve(String clientId);

    /**
     * Retrieves a client by its registration access token.
     *
     * @param registrationAccessToken the registration access token
     * @return the DCR response with client metadata, or null if not found
     */
    DcrResponse retrieveByToken(String registrationAccessToken);

    /**
     * Updates an existing client registration.
     *
     * @param clientId the client identifier
     * @param request the updated DCR request
     * @param response the updated DCR response
     */
    void update(String clientId, DcrRequest request, DcrResponse response);

    /**
     * Deletes a client registration.
     *
     * @param clientId the client identifier
     */
    void delete(String clientId);

    /**
     * Checks if a client exists.
     *
     * @param clientId the client identifier
     * @return true if the client exists, false otherwise
     */
    boolean exists(String clientId);

    /**
     * Validates a registration access token for a client.
     *
     * @param clientId the client identifier
     * @param registrationAccessToken the registration access token
     * @return true if the token is valid for the client, false otherwise
     */
    boolean validateToken(String clientId, String registrationAccessToken);

    /**
     * Retrieves a client by its client name.
     * <p>
     * This method is useful for authorization flows where the client_id
     * may be confused with the client_name. It allows fallback lookup
     * by client_name when client_id lookup fails.
     * </p>
     *
     * @param clientName the client name
     * @return the DCR response with client metadata, or null if not found
     */
    DcrResponse retrieveByClientName(String clientName);

}
