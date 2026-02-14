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
package com.alibaba.openagentauth.core.exception.oauth2;

/**
 * Exception thrown when client assertion generation or validation fails.
 * <p>
 * This exception represents errors that occur during OAuth 2.0 client assertion
 * processing according to RFC 7523. Client assertions are JWT-based credentials
 * used for client authentication in OAuth 2.0 flows.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 1.0
 */
public class ClientAssertionException extends OAuth2Exception {

    /**
     * The error code for this exception.
     */
    private static final OAuth2ErrorCode ERROR_CODE = OAuth2ErrorCode.CLIENT_ASSERTION_ERROR;

    /**
     * Creates a new ClientAssertionException with the specified message.
     *
     * @param message the error message
     */
    public ClientAssertionException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Creates a new ClientAssertionException with the specified message and cause.
     *
     * @param message the error message
     * @param cause the cause of the exception
     */
    public ClientAssertionException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }

    /**
     * Creates a new ClientAssertionException with the specified RFC error code and message.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     */
    public ClientAssertionException(OAuth2RfcErrorCode rfcErrorCode, String message) {
        super(rfcErrorCode, ERROR_CODE, message);
    }

    /**
     * Creates a new ClientAssertionException with the specified RFC error code, message, and cause.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     * @param cause the cause of the exception
     */
    public ClientAssertionException(OAuth2RfcErrorCode rfcErrorCode, String message, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, message);
    }
}