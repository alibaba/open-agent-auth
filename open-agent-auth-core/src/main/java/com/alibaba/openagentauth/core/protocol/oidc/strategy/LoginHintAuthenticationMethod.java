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
 * Login hint-based authentication method strategy.
 * <p>
 * This implementation authenticates users using the login_hint parameter,
 * which indicates that the user has already been authenticated and the
 * subject identifier is provided as a hint. This is typically used in
 * scenarios where authentication has already occurred in a previous step
 * or session.
 * </p>
 * <p>
 * <b>Authentication Method Reference:</b> none
 * </p>
 * <p>
 * <b>Security Note:</b> This method does not perform actual authentication
 * but trusts the provided login_hint. It should only be used in trusted
 * environments or when combined with other security measures like session
 * validation.
 * </p>
 *
 * @since 1.0
 */
public class LoginHintAuthenticationMethod implements AuthenticationMethod {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(LoginHintAuthenticationMethod.class);

    /**
     * Attempts to authenticate using login_hint parameter.
     *
     * @param request the authentication request
     * @param userRegistry the user registry (not used in this method)
     * @return the authentication result if login_hint is present, null otherwise
     * @throws AuthenticationException never thrown for this method
     */
    @Override
    public AuthenticationResult authenticate(AuthenticationRequest request, UserRegistry userRegistry) throws AuthenticationException {
        String loginHint = request.getLoginHint();

        // Return null if login_hint is not present (this method is not applicable)
        if (ValidationUtils.isNullOrEmpty(loginHint)) {
            return null;
        }

        logger.debug("Using login_hint as subject: {}", loginHint);
        return new AuthenticationResult(loginHint, new String[]{"none"});
    }
}