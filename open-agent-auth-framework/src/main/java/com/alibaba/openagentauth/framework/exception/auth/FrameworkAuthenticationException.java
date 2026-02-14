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
package com.alibaba.openagentauth.framework.exception.auth;

import com.alibaba.openagentauth.core.exception.oidc.AuthenticationException;

/**
 * Exception thrown when authentication fails in framework orchestration layer.
 * <p>
 * This exception is thrown when there is an error during the authentication process
 * in the framework orchestration layer, such as invalid credentials, expired tokens, or authentication
 * service failures in the framework workflow.
 * </p>
 * <p>
 * <b>Note:</b> This exception is different from {@link AuthenticationException}
 * which is used at the OpenID Connect protocol layer. This exception is specifically for
 * framework orchestration layer authentication errors.
 * </p>
 *
 * @since 1.0
 */
public class FrameworkAuthenticationException extends AuthException {

    /**
     * The error code for this exception.
     */
    private static final AuthErrorCode ERROR_CODE = AuthErrorCode.AUTHENTICATION_FAILED;

    /**
     * Constructs a new framework authentication exception with the specified detail message.
     *
     * @param message the detail message
     */
    public FrameworkAuthenticationException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new framework authentication exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public FrameworkAuthenticationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
