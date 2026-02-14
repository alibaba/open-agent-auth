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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Password-based authentication method strategy.
 * <p>
 * This implementation authenticates users using username and password
 * credentials provided in the authentication request. It supports multiple
 * parameter names for username (username, userid) to accommodate different
 * client implementations.
 * </p>
 * <p>
 * <b>Authentication Method Reference:</b> pwd
 * </p>
 *
 * @since 1.0
 */
public class PasswordAuthenticationMethod implements AuthenticationMethod {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(PasswordAuthenticationMethod.class);

    /**
     * Attempts to authenticate using username and password credentials.
     *
     * @param request the authentication request
     * @param userRegistry the user registry for credential validation
     * @return the authentication result if credentials are present and valid, null otherwise
     * @throws AuthenticationException if authentication fails (invalid credentials)
     */
    @Override
    public AuthenticationResult authenticate(AuthenticationRequest request, UserRegistry userRegistry) throws AuthenticationException {
        String username = extractUsername(request);
        String password = extractPassword(request);

        // Return null if credentials are not present (this method is not applicable)
        if (username == null || password == null) {
            return null;
        }

        try {
            // Authenticate via user registry
            String subject = userRegistry.authenticate(username, password);
            logger.debug("Password authentication successful for user: {}", username);
            return new AuthenticationResult(subject, new String[]{"pwd"});
        } catch (AuthenticationException e) {
            logger.warn("Password authentication failed for user: {}", username);
            throw e;
        }
    }

    /**
     * Extracts username from the authentication request.
     * Checks multiple possible parameter names.
     *
     * @param request the authentication request
     * @return the username, or null if not found
     */
    private String extractUsername(AuthenticationRequest request) {
        if (request.getAdditionalParameters() == null) {
            return null;
        }

        // Check common parameter names for username
        String username = request.getAdditionalParameters().get("username");
        if (!ValidationUtils.isNullOrEmpty(username)) {
            return username;
        }

        username = request.getAdditionalParameters().get("userid");
        if (!ValidationUtils.isNullOrEmpty(username)) {
            return username;
        }

        return null;
    }

    /**
     * Extracts password from the authentication request.
     *
     * @param request the authentication request
     * @return the password, or null if not found
     */
    private String extractPassword(AuthenticationRequest request) {
        if (request.getAdditionalParameters() == null) {
            return null;
        }

        String password = request.getAdditionalParameters().get("password");
        if (!ValidationUtils.isNullOrEmpty(password)) {
            return password;
        }

        return null;
    }
}
