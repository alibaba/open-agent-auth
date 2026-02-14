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
 * Exception thrown when PAR (Pushed Authorization Request) operations fail.
 * <p>
 * This exception encapsulates errors that occur during PAR submission
 * according to RFC 9126 specification.
 * </p>
 * <p>
 * <b>Standard Error Codes (RFC 9126 Section 2.2):</b></p>
 * <ul>
 *   <li><b>invalid_request:</b> The request is missing a required parameter,
 *       includes an invalid parameter value, includes a parameter more than once,
 *       or is otherwise malformed</li>
 *   <li><b>invalid_client:</b> Client authentication failed</li>
 *   <li><b>invalid_redirect_uri:</b> The redirect URI is invalid</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @since 1.0
 */
public class ParException extends OAuth2Exception {

    /**
     * The error code for this exception.
     */
    private static final OAuth2ErrorCode ERROR_CODE = OAuth2ErrorCode.PAR_ERROR;

    /**
     * HTTP status code.
     */
    private final int statusCode;

    /**
     * Creates a new PAR exception with a message.
     *
     * @param message the error message
     */
    public ParException(String message) {
        super(ERROR_CODE, message);
        this.statusCode = 500;
    }

    /**
     * Creates a new PAR exception with a message and cause.
     *
     * @param message the error message
     * @param cause the cause of the exception
     */
    public ParException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
        this.statusCode = 500;
    }

    /**
     * Creates a new PAR exception with error code and description.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     * @param statusCode the HTTP status code
     */
    public ParException(OAuth2RfcErrorCode rfcErrorCode, String message, int statusCode) {
        super(rfcErrorCode, ERROR_CODE, message);
        this.statusCode = statusCode;
    }

    /**
     * Creates a new PAR exception with error code and description.
     *
     * @param message the error message
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorDescription the error description
     */
    public ParException(String message, OAuth2RfcErrorCode rfcErrorCode, String errorDescription) {
        super(rfcErrorCode, ERROR_CODE, message, errorDescription);
        this.statusCode = 500;
    }

    /**
     * Creates a new PAR exception with all fields.
     *
     * @param message the error message
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorDescription the error description
     * @param cause the cause of the exception
     */
    public ParException(String message, OAuth2RfcErrorCode rfcErrorCode, String errorDescription, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, message, errorDescription);
        this.statusCode = 500;
    }

    // ============ Static Factory Methods ============

    /**
     * Creates an exception for missing required parameters.
     *
     * @param parameterName the name of the missing parameter
     * @return a new ParException with INVALID_REQUEST error code
     */
    public static ParException missingParameter(String parameterName) {
        return new ParException(
                "Missing required parameter: " + parameterName,
                OAuth2RfcErrorCode.INVALID_REQUEST,
                parameterName + " is required"
        );
    }

    /**
     * Creates an exception for invalid parameter values.
     *
     * @param parameterName the name of the invalid parameter
     * @param reason the reason why the parameter is invalid
     * @return a new ParException with INVALID_REQUEST error code
     */
    public static ParException invalidParameter(String parameterName, String reason) {
        return new ParException(
                "Invalid " + parameterName,
                OAuth2RfcErrorCode.INVALID_REQUEST,
                reason
        );
    }

    /**
     * Creates an exception for client authentication failures.
     *
     * @param reason the reason for authentication failure
     * @return a new ParException with INVALID_CLIENT error code
     */
    public static ParException authenticationFailed(String reason) {
        return new ParException(
                "Client authentication failed",
                OAuth2RfcErrorCode.INVALID_CLIENT,
                reason
        );
    }

    /**
     * Creates an exception for invalid redirect URI.
     *
     * @param reason the reason why the redirect URI is invalid
     * @return a new ParException with INVALID_REDIRECT_URI error code
     */
    public static ParException invalidRedirectUri(String reason) {
        return new ParException(
                "Invalid redirect_uri",
                OAuth2RfcErrorCode.INVALID_REDIRECT_URI,
                reason
        );
    }

    /**
     * Creates an exception for internal server errors.
     *
     * @param message the error message
     * @param cause the cause of the exception
     * @return a new ParException with INVALID_REQUEST error code
     */
    public static ParException internalError(String message, Throwable cause) {
        return new ParException(
                message,
                OAuth2RfcErrorCode.INVALID_REQUEST,
                "Internal server error",
                cause
        );
    }

    /**
     * Gets the HTTP status code.
     *
     * @return the status code
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Creates an exception for HTTP response errors from the Authorization Server.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code from the response
     * @param errorDescription the error description from the response
     * @return a new ParException
     */
    public static ParException httpResponseError(int statusCode, String rfcErrorCode, String errorDescription) {
        OAuth2RfcErrorCode errorCode = null;
        try {
            errorCode = OAuth2RfcErrorCode.fromValue(rfcErrorCode);
        } catch (IllegalArgumentException e) {
            // Use null for unknown error codes
        }
        String message = String.format("PAR request failed: status=%d, error=%s, description=%s",
                statusCode, rfcErrorCode, errorDescription);
        return new ParException(
            errorCode != null ? errorCode : OAuth2RfcErrorCode.SERVER_ERROR,
            message,
            statusCode
        );
    }
}