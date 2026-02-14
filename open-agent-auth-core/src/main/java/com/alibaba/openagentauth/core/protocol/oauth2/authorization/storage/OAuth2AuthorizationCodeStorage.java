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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2AuthorizationException;
import com.alibaba.openagentauth.core.model.oauth2.authorization.AuthorizationCode;

/**
 * Storage interface for OAuth 2.0 Authorization Codes.
 * <p>
 * This interface defines the contract for storing and retrieving authorization codes.
 * Implementations can use various storage mechanisms such as in-memory maps, databases,
 * or distributed caches.
 * </p>
 * <p>
 * <b>Security Requirements:</b></p>
 * <ul>
 *   <li>Authorization codes MUST be stored securely</li>
 *   <li>Authorization codes MUST have a short expiration time (recommended: 10 minutes)</li>
 *   <li>Authorization codes MUST be single-use</li>
 *   <li>Storage MUST be thread-safe for concurrent access</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">RFC 6749 - Authorization Code</a>
 * @since 1.0
 */
public interface OAuth2AuthorizationCodeStorage {

    /**
     * Stores an authorization code.
     * <p>
     * This method stores the authorization code with its associated metadata.
     * The code should be stored securely and should be retrievable using the code value.
     * </p>
     *
     * @param authorizationCode the authorization code to store
     * @throws IllegalArgumentException if authorizationCode is null
     * @throws OAuth2AuthorizationException if storage fails
     */
    void store(AuthorizationCode authorizationCode);

    /**
     * Retrieves an authorization code by its value.
     * <p>
     * This method retrieves the stored authorization code. If the code has expired
     * or has already been used, this method may return null or throw an exception
     * depending on the implementation.
     * </p>
     *
     * @param code the authorization code value
     * @return the stored authorization code, or null if not found
     * @throws IllegalArgumentException if code is null or empty
     * @throws OAuth2AuthorizationException if retrieval fails
     */
    AuthorizationCode retrieve(String code);

    /**
     * Consumes an authorization code.
     * <p>
     * This method marks the authorization code as used and prevents future use.
     * According to RFC 6749, authorization codes MUST be single-use. This method
     * should be called when the code is successfully exchanged for an access token.
     * </p>
     *
     * @param code the authorization code to consume
     * @return the consumed authorization code, or null if not found
     * @throws IllegalArgumentException if code is null or empty
     * @throws OAuth2AuthorizationException if consumption fails or code is already used
     */
    AuthorizationCode consume(String code);

    /**
     * Deletes an authorization code.
     * <p>
     * This method permanently removes the authorization code from storage.
     * This can be used for cleanup purposes or when a code is no longer needed.
     * </p>
     *
     * @param code the authorization code to delete
     * @throws IllegalArgumentException if code is null or empty
     * @throws OAuth2AuthorizationException if deletion fails
     */
    void delete(String code);

    /**
     * Checks if an authorization code exists and is valid.
     * <p>
     * A code is valid if it exists, has not expired, and has not been used.
     * </p>
     *
     * @param code the authorization code to check
     * @return true if the code exists and is valid, false otherwise
     * @throws IllegalArgumentException if code is null or empty
     */
    boolean isValid(String code);

    /**
     * Removes expired authorization codes.
     * <p>
     * This method cleans up expired authorization codes from storage.
     * Implementations may call this method periodically to free up resources.
     * </p>
     *
     * @return the number of codes removed
     * @throws OAuth2AuthorizationException if cleanup fails
     */
    int cleanupExpired();
}
