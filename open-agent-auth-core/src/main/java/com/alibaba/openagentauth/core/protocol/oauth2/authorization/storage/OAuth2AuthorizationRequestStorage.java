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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage;

import com.alibaba.openagentauth.core.model.oauth2.authorization.OAuth2AuthorizationRequest;

/**
 * Storage interface for persisting {@link OAuth2AuthorizationRequest} instances between
 * the authorization request initiation and the callback response.
 * <p>
 * This interface follows the Storage pattern consistent with {@link OAuth2AuthorizationCodeStorage}
 * and decouples the storage mechanism from the authorization flow logic, allowing
 * different implementations for different deployment scenarios:
 * </p>
 * <ul>
 *   <li><b>In-memory</b> (default): Suitable for single-server deployments</li>
 *   <li><b>Redis/Database-based</b>: Suitable for distributed/clustered deployments</li>
 *   <li><b>Cookie-based</b>: Suitable for stateless deployments</li>
 * </ul>
 *
 * <h3>Contract</h3>
 * <p>
 * Implementations must ensure that:
 * </p>
 * <ul>
 *   <li>{@link #save(OAuth2AuthorizationRequest)} stores the request keyed by its state value</li>
 *   <li>{@link #load(String)} retrieves the request by state without removing it</li>
 *   <li>{@link #remove(String)} retrieves and removes the request atomically (consume-once semantics)</li>
 * </ul>
 *
 * <h3>Thread Safety</h3>
 * <p>
 * Implementations should be thread-safe, as concurrent requests may access the
 * storage simultaneously in multi-threaded web server environments.
 * </p>
 *
 * @since 1.1
 * @see OAuth2AuthorizationRequest
 * @see InMemoryOAuth2AuthorizationRequestStorage
 * @see OAuth2AuthorizationCodeStorage
 */
public interface OAuth2AuthorizationRequestStorage {

    /**
     * Saves an authorization request.
     * <p>
     * The request is stored using its {@link OAuth2AuthorizationRequest#getState()} value
     * as the lookup key. If a request with the same state already exists, it is replaced.
     * </p>
     *
     * @param authorizationRequest the authorization request to save
     * @throws IllegalArgumentException if authorizationRequest is null
     */
    void save(OAuth2AuthorizationRequest authorizationRequest);

    /**
     * Loads an authorization request by its state parameter without removing it.
     * <p>
     * This method is useful for validation scenarios where the request needs to be
     * inspected but should remain available for subsequent processing.
     * </p>
     *
     * @param state the state parameter value
     * @return the authorization request, or null if not found
     */
    OAuth2AuthorizationRequest load(String state);

    /**
     * Removes and returns an authorization request by its state parameter.
     * <p>
     * This method provides consume-once semantics: the request is atomically
     * retrieved and removed from the storage. This prevents replay attacks
     * where the same authorization code callback could be processed multiple times.
     * </p>
     *
     * @param state the state parameter value
     * @return the removed authorization request, or null if not found
     */
    OAuth2AuthorizationRequest remove(String state);
}
