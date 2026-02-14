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
package com.alibaba.openagentauth.core.protocol.oidc.strategy;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;
import com.alibaba.openagentauth.core.model.oidc.AuthenticationRequest;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;

/**
 * Strategy interface for user authentication methods.
 * <p>
 * This interface defines the contract for different authentication mechanisms,
 * allowing the authentication provider to support multiple authentication methods
 * through a pluggable strategy pattern.
 * </p>
 * <p>
 * <b>Implementations:</b></p>
 * <ul>
 *   <li>{@link PasswordAuthenticationMethod} - Username/password authentication</li>
 *   <li>{@link LoginHintAuthenticationMethod} - login_hint based authentication</li>
 *   <li>{@link IdTokenHintAuthenticationMethod} - id_token_hint based authentication</li>
 * </ul>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern - Encapsulates authentication algorithms
 * into separate classes that can be selected at runtime.
 * </p>
 *
 * @since 1.0
 */
public interface AuthenticationMethod {

    /**
     * Attempts to authenticate the user using this authentication method.
     * <p>
     * If this method is applicable to the request (e.g., the required parameters
     * are present), it will attempt authentication and return the result.
     * If this method is not applicable, it returns null, allowing the authentication
     * provider to try the next method in the chain.
     * </p>
     *
     * @param request the authentication request
     * @param userRegistry the user registry for credential validation
     * @return the authentication result if successful and applicable, null if not applicable
     * @throws AuthenticationException if authentication fails (credentials invalid)
     */
    AuthenticationResult authenticate(AuthenticationRequest request, UserRegistry userRegistry) throws AuthenticationException;

}
