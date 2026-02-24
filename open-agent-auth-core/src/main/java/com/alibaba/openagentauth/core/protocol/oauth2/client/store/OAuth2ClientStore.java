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
package com.alibaba.openagentauth.core.protocol.oauth2.client.store;

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;

/**
 * Storage interface for OAuth 2.0 client metadata retrieval and validation.
 * <p>
 * This interface defines the contract for querying and validating OAuth 2.0 client
 * registrations. It represents the fundamental client storage capability that any
 * OAuth 2.0 Authorization Server needs, independent of how clients are registered.
 * </p>
 * <p>
 * In OAuth 2.0, clients can be registered through various mechanisms:
 * </p>
 * <ul>
 *   <li>Static configuration (e.g., YAML-based pre-registration)</li>
 *   <li>Dynamic Client Registration (RFC 7591)</li>
 *   <li>Manual administrative registration</li>
 * </ul>
 * <p>
 * This interface abstracts away the registration mechanism and focuses on the
 * read-only operations needed by the authorization server to validate clients
 * during OAuth 2.0 flows.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2">RFC 6749 - Client Registration</a>
 * @since 1.0
 */
public interface OAuth2ClientStore {

    /**
     * Registers a new OAuth 2.0 client.
     * <p>
     * This method stores a client registration in the store. If a client with the
     * same client_id already exists, the behavior is implementation-defined (typically
     * the existing registration is overwritten).
     * </p>
     *
     * @param client the client to register
     * @throws IllegalArgumentException if client is null or has no client_id
     */
    void register(OAuth2RegisteredClient client);

    /**
     * Retrieves a client by its client ID.
     *
     * @param clientId the client identifier
     * @return the client metadata as a OAuth2RegisteredClient, or null if not found
     */
    OAuth2RegisteredClient retrieve(String clientId);

    /**
     * Retrieves a client by its client name.
     * <p>
     * This method provides a fallback lookup mechanism when the provided identifier
     * might be a client name rather than a client ID. This is useful in scenarios
     * where client_id and client_name may be confused.
     * </p>
     *
     * @param clientName the client name
     * @return the client metadata as a OAuth2RegisteredClient, or null if not found
     */
    OAuth2RegisteredClient retrieveByClientName(String clientName);

    /**
     * Checks if a client with the given ID exists.
     *
     * @param clientId the client identifier
     * @return true if the client exists, false otherwise
     */
    boolean exists(String clientId);
}