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
package com.alibaba.openagentauth.core.protocol.oidc.registry;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;

/**
 * Interface for user authentication registry.
 * <p>
 * This interface defines a pluggable mechanism for user authentication,
 * allowing different implementations to be used with the authentication provider.
 * </p>
 * <p>
 * <b>Implementations:</b></p>
 * <ul>
 *   <li>{@link InMemoryUserRegistry} - In-memory storage for development/testing</li>
 * </ul>
 *
 * @since 1.0
 */
public interface UserRegistry {

    /**
     * Authenticates a user with the given credentials.
     *
     * @param username the username
     * @param password the password
     * @return the user subject identifier
     * @throws AuthenticationException if authentication fails
     */
    String authenticate(String username, String password) throws AuthenticationException;

    /**
     * Checks if a user exists in the registry.
     *
     * @param username the username to check
     * @return true if the user exists, false otherwise
     */
    boolean userExists(String username);

    /**
     * Gets the subject identifier for a user.
     *
     * @param username the username
     * @return the subject identifier, or null if not found
     */
    String getSubject(String username);

    /**
     * Gets the email address for a user.
     *
     * @param username the username
     * @return the email address, or null if not found
     */
    String getEmail(String username);

    /**
     * Gets the display name for a user.
     *
     * @param username the username
     * @return the display name, or null if not found
     */
    String getName(String username);
}
