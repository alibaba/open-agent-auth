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
package com.alibaba.openagentauth.core.model.oidc;

/**
 * Session-based user interface for Identity Provider (IDP) scenarios.
 * <p>
 * This interface defines the contract for user objects that are stored in HTTP sessions
 * and used across the IDP authentication flow. It provides a unified abstraction for
 * session-based user management, allowing both framework implementations and custom
 * implementations to be used interchangeably.
 * </p>
 * <p>
 * <b>Key Characteristics:</b></p>
 * <ul>
 *   <li><b>Session-Oriented:</b> Designed for HTTP session-based authentication and authorization</li>
 *   <li><b>Serializable:</b> Implementations must be serializable for session storage</li>
 *   <li><b>Immutable:</b> Recommended to be immutable for thread safety</li>
 *   <li><b>Extensible:</b> Applications can provide custom implementations for specific use cases</li>
 * </ul>
 * <p>
 * <b>Usage Scenarios:</b></p>
 * <ul>
 *   <li>Framework's authentication controllers store implementations in HTTP session</li>
 *   <li>Authentication providers retrieve and validate implementations from session</li>
 *   <li>Authorization services use implementations to build user identity claims</li>
 *   <li>Applications can provide their own implementations for custom user models</li>
 * </ul>
 * <p>
 * <b>Implementations:</b></p>
 * <ul>
 *   <li>{@link DefaultSessionUser} provides a lightweight, immutable implementation for simple session-based scenarios</li>
 *   <li>Custom implementations can extend this interface for complex requirements</li>
 * </ul>
 *
 * @since 1.0
 */
public interface SessionUser {

    /**
     * Gets the unique subject identifier for the user.
     * <p>
     * This value is used as the 'sub' claim in ID tokens and is the primary
     * identifier for the user throughout the authentication and authorization flow.
     * </p>
     *
     * @return the subject identifier, never null
     */
    String getSubject();

    /**
     * Gets the username used for authentication.
     * <p>
     * This is the username that the user entered during login.
     * </p>
     *
     * @return the username, never null
     */
    String getUsername();

    /**
     * Gets the user's password.
     * <p>
     * <b>Security Note:</b> In most cases, this should return an empty string
     * or null, as passwords should not be stored in session after authentication.
     * This method exists primarily for backward compatibility with existing code.
     * </p>
     *
     * @return the password (may be empty or null)
     */
    String getPassword();

    /**
     * Gets the user's display name.
     * <p>
     * This is the user's full name or preferred display name.
     * </p>
     *
     * @return the display name, or null if not set
     */
    String getName();

    /**
     * Gets the user's email address.
     * <p>
     * This is the user's preferred email address.
     * </p>
     *
     * @return the email address, or null if not set
     */
    String getEmail();

    /**
     * Gets the user's preferred username.
     * <p>
     * This is the username that the user prefers to be referred to,
     * which may be different from the authentication username.
     * </p>
     *
     * @return the preferred username, or null if not set
     */
    String getPreferredUsername();

}
