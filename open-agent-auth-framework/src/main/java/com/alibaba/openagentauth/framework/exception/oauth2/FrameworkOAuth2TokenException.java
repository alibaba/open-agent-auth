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
package com.alibaba.openagentauth.framework.exception.oauth2;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;

/**
 * Framework-level exception for OAuth 2.0 token operations.
 * <p>
 * This exception represents errors that occur during OAuth 2.0 token operations
 * in the framework layer, such as token exchange failures, validation errors,
 * or client authentication failures. It wraps core-level exceptions and provides
 * framework-specific error handling.
 * </p>
 * <p>
 * <b>Error Categories:</b></p>
 * <ul>
 *   <li><b>invalid_request:</b> Missing required parameter, invalid value, or malformed request</li>
 *   <li><b>invalid_client:</b> Client authentication failed</li>
 *   <li><b>invalid_grant:</b> Authorization code is invalid, expired, or already used</li>
 *   <li><b>invalid_scope:</b> Requested scope is invalid or exceeds granted scope</li>
 *   <li><b>unauthorized_client:</b> Client is not authorized to use this grant type</li>
 * </ul>
 * 
 * @see OAuth2TokenException
 * @since 1.0
 */
public class FrameworkOAuth2TokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * The OAuth 2.0 error code.
     */
    private final String errorCode;

    /**
     * The human-readable error description.
     */
    private final String errorDescription;

    /**
     * The HTTP status code for this error.
     */
    private final int httpStatus;

    /**
     * Constructs a new FrameworkOAuth2TokenException with the specified error code and message.
     *
     * @param errorCode the OAuth 2.0 error code
     * @param message the error message
     */
    public FrameworkOAuth2TokenException(String errorCode, String message) {
        this(errorCode, message, null);
    }

    /**
     * Constructs a new FrameworkOAuth2TokenException with the specified error code, message, and cause.
     *
     * @param errorCode the OAuth 2.0 error code
     * @param message the error message
     * @param cause the underlying cause
     */
    public FrameworkOAuth2TokenException(String errorCode, String message, Throwable cause) {
        this(errorCode, message, message, cause, determineHttpStatus(errorCode));
    }

    /**
     * Constructs a new FrameworkOAuth2TokenException with full details.
     *
     * @param errorCode the OAuth 2.0 error code
     * @param message the error message
     * @param errorDescription the human-readable error description
     * @param cause the underlying cause
     * @param httpStatus the HTTP status code
     */
    public FrameworkOAuth2TokenException(String errorCode, String message, String errorDescription, 
                                         Throwable cause, int httpStatus) {
        super(message, cause);
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.httpStatus = httpStatus;
    }

    /**
     * Constructs a new FrameworkOAuth2TokenException wrapping a core OAuth2TokenException.
     *
     * @param cause the core exception to wrap
     */
    public FrameworkOAuth2TokenException(OAuth2TokenException cause) {
        super(cause.getMessage(), cause);
        this.errorCode = cause.getErrorCode();
        this.errorDescription = cause.getMessage();
        this.httpStatus = determineHttpStatus(cause.getErrorCode());
    }

    /**
     * Gets the OAuth 2.0 error code.
     *
     * @return the error code
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the human-readable error description.
     *
     * @return the error description
     */
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * Gets the HTTP status code for this error.
     *
     * @return the HTTP status code
     */
    public int getHttpStatus() {
        return httpStatus;
    }

    /**
     * Determines the appropriate HTTP status code based on the error code.
     *
     * @param errorCode the OAuth 2.0 error code
     * @return the HTTP status code
     */
    private static int determineHttpStatus(String errorCode) {
        if (errorCode == null) {
            return 500;
        }
        switch (errorCode) {
            case "invalid_client":
                return 401;
            case "unauthorized_client":
                return 403;
            case "invalid_request":
            case "invalid_grant":
            case "invalid_scope":
            default:
                return 400;
        }
    }

    /**
     * Creates an invalid_request exception.
     *
     * @param message the error message
     * @return the exception
     */
    public static FrameworkOAuth2TokenException invalidRequest(String message) {
        return new FrameworkOAuth2TokenException("invalid_request", message);
    }

    /**
     * Creates an invalid_client exception.
     *
     * @param message the error message
     * @return the exception
     */
    public static FrameworkOAuth2TokenException invalidClient(String message) {
        return new FrameworkOAuth2TokenException("invalid_client", message);
    }

    /**
     * Creates an invalid_grant exception.
     *
     * @param message the error message
     * @return the exception
     */
    public static FrameworkOAuth2TokenException invalidGrant(String message) {
        return new FrameworkOAuth2TokenException("invalid_grant", message);
    }

    /**
     * Creates an invalid_scope exception.
     *
     * @param message the error message
     * @return the exception
     */
    public static FrameworkOAuth2TokenException invalidScope(String message) {
        return new FrameworkOAuth2TokenException("invalid_scope", message);
    }

    /**
     * Creates an unauthorized_client exception.
     *
     * @param message the error message
     * @return the exception
     */
    public static FrameworkOAuth2TokenException unauthorizedClient(String message) {
        return new FrameworkOAuth2TokenException("unauthorized_client", message);
    }

    @Override
    public String toString() {
        return "FrameworkOAuth2TokenException{" +
                "errorCode='" + errorCode + '\'' +
                ", errorDescription='" + errorDescription + '\'' +
                ", httpStatus=" + httpStatus +
                ", message='" + getMessage() + '\'' +
                '}';
    }
}
