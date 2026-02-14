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
 * Exception thrown when Dynamic Client Registration (DCR) operations fail.
 * <p>
 * This exception represents errors that occur during OAuth 2.0 Dynamic Client
 * Registration according to RFC 7591. It includes error codes and descriptions
 * as defined in the specification.
 * </p>
 * <p>
 * <b>Standard Error Codes (RFC 7591 Section 3.2.2):</b></p>
 * <ul>
 *   <li><b>invalid_redirect_uri</b>: Redirect URI is invalid</li>
 *   <li><b>invalid_client_metadata</b>: Client metadata is invalid</li>
 *   <li><b>invalid_client_id</b>: Client ID is invalid</li>
 *   <li><b>unapproved_client</b>: Client is not approved</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
public class DcrException extends OAuth2Exception {

    /**
     * The error code for this exception.
     */
    private static final OAuth2ErrorCode ERROR_CODE = OAuth2ErrorCode.DCR_ERROR;

    /**
     * HTTP status code.
     */
    private final int statusCode;

    /**
     * Creates a new DcrException with the specified message.
     *
     * @param message the error message
     */
    public DcrException(String message) {
        super(OAuth2RfcErrorCode.SERVER_ERROR, ERROR_CODE, message);
        this.statusCode = 500;
    }

    /**
     * Creates a new DcrException with the specified message and cause.
     *
     * @param message the error message
     * @param cause the cause of the exception
     */
    public DcrException(String message, Throwable cause) {
        super(OAuth2RfcErrorCode.SERVER_ERROR, ERROR_CODE, cause, message);
        this.statusCode = 500;
    }

    /**
     * Creates a new DcrException with the specified error code and message.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     */
    private DcrException(OAuth2RfcErrorCode rfcErrorCode, String message) {
        super(rfcErrorCode, ERROR_CODE, message);
        this.statusCode = 400;
    }

    /**
     * Creates a new DcrException with the specified error code, message, and cause.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     * @param cause the cause of the exception
     */
    private DcrException(OAuth2RfcErrorCode rfcErrorCode, String message, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, message);
        this.statusCode = 400;
    }

    /**
     * Creates a new DcrException with the specified error code, message, and HTTP status.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     * @param statusCode the HTTP status code
     */
    private DcrException(OAuth2RfcErrorCode rfcErrorCode, String message, int statusCode) {
        super(rfcErrorCode, ERROR_CODE, message);
        this.statusCode = statusCode;
    }

    /**
     * Creates a new DcrException with the specified error code, message, HTTP status, and cause.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param message the error message
     * @param statusCode the HTTP status code
     * @param cause the cause of the exception
     */
    private DcrException(OAuth2RfcErrorCode rfcErrorCode, String message, int statusCode, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, message);
        this.statusCode = statusCode;
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
     * Creates a DcrException for an invalid redirect URI (400 Bad Request).
     *
     * @param message the error message
     * @return a DcrException with error code "invalid_redirect_uri"
     */
    public static DcrException invalidRedirectUri(String message) {
        return new DcrException(OAuth2RfcErrorCode.INVALID_REDIRECT_URI, message, 400);
    }

    /**
     * Creates a DcrException for invalid client metadata (400 Bad Request).
     *
     * @param message the error message
     * @return a DcrException with error code "invalid_client_metadata"
     */
    public static DcrException invalidClientMetadata(String message) {
        return new DcrException(OAuth2RfcErrorCode.INVALID_CLIENT_METADATA, message, 400);
    }

    /**
     * Creates a DcrException for an invalid client ID (401 Unauthorized).
     *
     * @param message the error message
     * @return a DcrException with error code "invalid_client_id"
     */
    public static DcrException invalidClientId(String message) {
        return new DcrException(OAuth2RfcErrorCode.INVALID_CLIENT, message, 401);
    }

    /**
     * Creates a DcrException for an unapproved client (403 Forbidden).
     *
     * @param message the error message
     * @return a DcrException with error code "unapproved_client"
     */
    public static DcrException unapprovedClient(String message) {
        return new DcrException(OAuth2RfcErrorCode.UNAUTHORIZED_CLIENT, message, 403);
    }

    /**
     * Creates a DcrException for an HTTP response error.
     *
     * @param statusCode the HTTP status code
     * @param errorCode the OAuth 2.0 error code
     * @param errorDescription the error description
     * @return a DcrException
     */
    public static DcrException httpResponseError(int statusCode, String errorCode, String errorDescription) {
        OAuth2RfcErrorCode rfcErrorCode = null;
        try {
            rfcErrorCode = OAuth2RfcErrorCode.fromValue(errorCode);
        } catch (IllegalArgumentException e) {
            // Use null for unknown error codes
        }
        String message = String.format("DCR request failed: status=%d, error=%s, description=%s",
                statusCode, errorCode, errorDescription);
        return new DcrException(
                rfcErrorCode != null ? rfcErrorCode : OAuth2RfcErrorCode.SERVER_ERROR,
                message,
                statusCode
        );
    }
}