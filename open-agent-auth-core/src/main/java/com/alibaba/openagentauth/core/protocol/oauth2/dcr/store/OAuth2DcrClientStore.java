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

import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;

/**
 * Storage interface for Dynamic Client Registration (DCR) client metadata.
 * <p>
 * This interface extends {@link OAuth2ClientStore} with DCR-specific operations
 * for managing client registrations according to RFC 7591. While {@code OAuth2ClientStore}
 * provides read-only client lookup capabilities, this interface adds the full CRUD
 * operations needed for dynamic client registration.
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
 * @see OAuth2ClientStore
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
public interface OAuth2DcrClientStore extends OAuth2ClientStore {

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
     * Retrieves the full DCR response for a client by its client ID.
     * <p>
     * Unlike {@link OAuth2ClientStore#retrieve(String)} which returns a generic
     * {@code OAuth2RegisteredClient}, this method returns the complete DCR response
     * including DCR-specific fields such as registration access token, registration
     * client URI, and client secret expiration.
     * </p>
     *
     * @param clientId the client identifier
     * @return the full DCR response, or null if not found
     */
    DcrResponse retrieveDcrResponse(String clientId);

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
     * Validates a registration access token for a client.
     *
     * @param clientId the client identifier
     * @param registrationAccessToken the registration access token
     * @return true if the token is valid for the client, false otherwise
     */
    boolean validateToken(String clientId, String registrationAccessToken);

}
