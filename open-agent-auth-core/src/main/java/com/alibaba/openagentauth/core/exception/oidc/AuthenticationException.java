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
package com.alibaba.openagentauth.core.exception.oidc;

/**
 * Exception thrown when an authentication operation fails.
 * <p>
 * This exception indicates that an error occurred during the OpenID Connect
 * authentication flow. It provides detailed information about the failure
 * to help diagnose and resolve issues.
 * </p>
 * <p>
 * <b>Common Causes:</b></p>
 * <ul>
 *   <li>Invalid authentication request</li>
 *   <li>User authentication failed</li>
 *   <li>Client authentication failed</li>
 *   <li>Invalid redirect URI</li>
 *   <li>Invalid scope</li>
 *   <li>Missing required parameters</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">OpenID Connect Core 1.0 - Authentication</a>
 * @since 1.0
 */
public class AuthenticationException extends OidcException {

    /**
     * The error code for this exception.
     */
    private static final OidcErrorCode ERROR_CODE = OidcErrorCode.AUTHENTICATION_FAILED;

    /**
     * Constructs a new authentication exception with the specified detail message.
     * <p>
     * This constructor is kept for backward compatibility.
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     */
    public AuthenticationException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new authentication exception with the specified type, detail message, and cause.
     * <p>
     * This constructor is kept for backward compatibility.
     * It maps the type and message to template parameters:
     * - {0}: type
     * - {1}: detail message
     * </p>
     *
     * @param message the detail message
     * @param cause the cause
     */
    public AuthenticationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }

    /**
     * Constructs a new authentication exception with the specified RFC error code and detail message.
     *
     * @param rfcErrorCode the OIDC RFC error code
     * @param message the detail message
     */
    public AuthenticationException(OidcRfcErrorCode rfcErrorCode, String message) {
        super(rfcErrorCode, ERROR_CODE, message);
    }

    /**
     * Constructs a new authentication exception with the specified RFC error code, detail message, and cause.
     *
     * @param rfcErrorCode the OIDC RFC error code
     * @param message the detail message
     * @param cause the cause
     */
    public AuthenticationException(OidcRfcErrorCode rfcErrorCode, String message, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, message);
    }
}