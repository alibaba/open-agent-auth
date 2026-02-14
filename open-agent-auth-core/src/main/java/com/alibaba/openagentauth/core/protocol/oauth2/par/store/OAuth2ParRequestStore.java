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
package com.alibaba.openagentauth.core.protocol.oauth2.par.store;

import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;

/**
 * Storage interface for PAR requests.
 * <p>
 * This interface defines the contract for storing and retrieving
 * Pushed Authorization Requests. Implementations can use various
 * storage backends such as in-memory cache, Redis, database, etc.
 * </p>
 * <p>
 * <b>Storage Requirements (RFC 9126):</b></p>
 * <ul>
     *   <li>Requests MUST be stored with an expiration time</li>
 *   <li>Expired requests MUST NOT be retrievable</li>
 *   <li>request_uri values SHOULD be treated as one-time use</li>
 *   <li>Storage MUST be secure and prevent unauthorized access</li>
 * </ul>
 *
 * @since 1.0
 */
public interface OAuth2ParRequestStore {

    /**
     * Stores a PAR request with the given request_uri.
     *
     * @param requestUri the request URI (key)
     * @param request the PAR request to store
     * @param expiresIn the expiration time in seconds
     * @throws IllegalArgumentException if any parameter is null or invalid
     */
    void store(String requestUri, ParRequest request, long expiresIn);

    /**
     * Retrieves a PAR request by its request_uri.
     *
     * @param requestUri the request URI
     * @return the stored PAR request, or null if not found or expired
     * @throws IllegalArgumentException if requestUri is null or blank
     */
    ParRequest retrieve(String requestUri);

    /**
     * Removes a PAR request by its request_uri.
     * <p>
     * This is typically called after the request has been used
     * to enforce one-time use.
     * </p>
     *
     * @param requestUri the request URI
     * @return true if the request was removed, false if not found
     * @throws IllegalArgumentException if requestUri is null or blank
     */
    boolean remove(String requestUri);
}
