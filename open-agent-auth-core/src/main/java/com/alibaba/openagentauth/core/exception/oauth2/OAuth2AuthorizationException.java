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
 * Exception thrown when authorization operations fail.
 * <p>
 * This exception encapsulates errors that occur during OAuth 2.0 authorization
 * code flow operations according to RFC 6749 specification. It provides static
 * factory methods for creating standard OAuth 2.0 error responses.
 * </p>
 * <p>
 * <b>Standard Error Codes (RFC 6749 Section 4.1.2.1):</b></p>
 * <ul>
 *   <li><b>invalid_request:</b> The request is missing a required parameter,
 *       includes an invalid parameter value, includes a parameter more than once,
 *       or is otherwise malformed</li>
 *   <li><b>unauthorized_client:</b> The client is not authorized to request an
 *       authorization code using this method</li>
 *   <li><b>access_denied:</b> The resource owner or authorization server denied
 *       the request</li>
 *   <li><b>unsupported_response_type:</b> The authorization server does not support
 *       obtaining an authorization code using this method</li>
 *   <li><b>invalid_scope:</b> The requested scope is invalid, unknown, or malformed</li>
 *   <li><b>server_error:</b> The authorization server encountered an unexpected
 *       condition that prevented it from fulfilling the request</li>
 *   <li><b>temporarily_unavailable:</b> The authorization server is currently unable
 *       to handle the request due to a temporary overloading or maintenance</li>
 * </ul>
 *
 * <p><b>Usage Example:</b></p>
 * <pre>{@code
 * // Using static factory methods (recommended)
 * throw AuthorizationException.invalidRequest("Missing required parameter: redirect_uri");
 * 
 * // With cause
 * throw AuthorizationException.serverError("Failed to connect to database", e);
 * 
 * // Using constructor (for custom error codes)
 * throw new AuthorizationException(OAuth2RfcErrorCode.SERVER_ERROR, "Custom error description", 500);
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">RFC 6749 - Authorization Error Response</a>
 * @since 1.0
 */
public class OAuth2AuthorizationException extends OAuth2Exception {

    /**
     * The error code for this exception.
     */
    private static final OAuth2ErrorCode ERROR_CODE = OAuth2ErrorCode.AUTHORIZATION_ERROR;

    // ============ Static Factory Methods ============

    /**
     * Creates an exception for invalid request.
     *
     * @param description the error description
     * @return a new AuthorizationException with INVALID_REQUEST error code
     */
    public static OAuth2AuthorizationException invalidRequest(String description) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.INVALID_REQUEST, description);
    }

    /**
     * Creates an exception for invalid request with a cause.
     *
     * @param description the error description
     * @param cause the underlying cause
     * @return a new AuthorizationException with INVALID_REQUEST error code
     */
    public static OAuth2AuthorizationException invalidRequest(String description, Throwable cause) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.INVALID_REQUEST, description, cause);
    }

    /**
     * Creates an exception for missing required parameter.
     *
     * @param parameterName the name of the missing parameter
     * @return a new AuthorizationException with INVALID_REQUEST error code
     */
    public static OAuth2AuthorizationException missingParameter(String parameterName) {
        return new OAuth2AuthorizationException(
                OAuth2RfcErrorCode.INVALID_REQUEST,
                "Missing required parameter: " + parameterName
        );
    }

    /**
     * Creates an exception for invalid parameter value.
     *
     * @param parameterName the name of the invalid parameter
     * @param reason the reason why the parameter is invalid
     * @return a new AuthorizationException with INVALID_REQUEST error code
     */
    public static OAuth2AuthorizationException invalidParameter(String parameterName, String reason) {
        return new OAuth2AuthorizationException(
                OAuth2RfcErrorCode.INVALID_REQUEST,
                "Invalid " + parameterName + ": " + reason
        );
    }

    /**
     * Creates an exception for unauthorized client.
     *
     * @param description the error description
     * @return a new AuthorizationException with UNAUTHORIZED_CLIENT error code
     */
    public static OAuth2AuthorizationException unauthorizedClient(String description) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.UNAUTHORIZED_CLIENT, description);
    }

    /**
     * Creates an exception for access denied.
     *
     * @param description the error description
     * @return a new AuthorizationException with ACCESS_DENIED error code
     */
    public static OAuth2AuthorizationException accessDenied(String description) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.ACCESS_DENIED, description);
    }

    /**
     * Creates an exception for unsupported response type.
     *
     * @param responseType the unsupported response type
     * @return a new AuthorizationException with UNSUPPORTED_RESPONSE_TYPE error code
     */
    public static OAuth2AuthorizationException unsupportedResponseType(String responseType) {
        return new OAuth2AuthorizationException(
                OAuth2RfcErrorCode.UNSUPPORTED_RESPONSE_TYPE,
                "Unsupported response type: " + responseType
        );
    }

    /**
     * Creates an exception for invalid scope.
     *
     * @param description the error description
     * @return a new AuthorizationException with INVALID_SCOPE error code
     */
    public static OAuth2AuthorizationException invalidScope(String description) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.INVALID_SCOPE, description);
    }

    /**
     * Creates an exception for server error.
     *
     * @param description the error description
     * @return a new AuthorizationException with SERVER_ERROR error code
     */
    public static OAuth2AuthorizationException serverError(String description) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.SERVER_ERROR, description);
    }

    /**
     * Creates an exception for server error with a cause.
     *
     * @param description the error description
     * @param cause the underlying cause
     * @return a new AuthorizationException with SERVER_ERROR error code
     */
    public static OAuth2AuthorizationException serverError(String description, Throwable cause) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.SERVER_ERROR, description, cause);
    }

    /**
     * Creates an exception for temporarily unavailable.
     *
     * @param description the error description
     * @return a new AuthorizationException with TEMPORARILY_UNAVAILABLE error code
     */
    public static OAuth2AuthorizationException temporarilyUnavailable(String description) {
        return new OAuth2AuthorizationException(OAuth2RfcErrorCode.TEMPORARILY_UNAVAILABLE, description);
    }

    /**
     * Creates an exception for OAuth 2.0 error response from authorization server.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code from the response
     * @param errorDescription the error description from the response
     * @return a new AuthorizationException
     */
    public static OAuth2AuthorizationException oauthError(String rfcErrorCode, String errorDescription) {
        OAuth2RfcErrorCode errorCode = null;
        try {
            errorCode = OAuth2RfcErrorCode.fromValue(rfcErrorCode);
        } catch (IllegalArgumentException e) {
            // Use null for unknown error codes
        }
        return new OAuth2AuthorizationException(
                errorCode,
                errorDescription != null ? errorDescription : "OAuth error"
        );
    }

    // ============ Constructors ============

    /**
     * Creates a new AuthorizationException with the specified error code.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     */
    public OAuth2AuthorizationException(OAuth2RfcErrorCode rfcErrorCode) {
        this(rfcErrorCode, null);
    }

    /**
     * Creates a new AuthorizationException with the specified error code and description.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorDescription the error description
     */
    public OAuth2AuthorizationException(OAuth2RfcErrorCode rfcErrorCode, String errorDescription) {
        super(rfcErrorCode, ERROR_CODE, errorDescription);
    }

    /**
     * Creates a new AuthorizationException with the specified error code, description, and cause.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorDescription the error description
     * @param cause the underlying cause
     */
    public OAuth2AuthorizationException(OAuth2RfcErrorCode rfcErrorCode, String errorDescription, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, errorDescription);
    }

    @Override
    public String toString() {
        return "AuthorizationException{" +
                "rfcErrorCode='" + getRfcErrorCode() + '\'' +
                '}';
    }
}