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
 * Exception thrown when token operations fail.
 * <p>
 * This exception encapsulates errors that occur during OAuth 2.0 token endpoint
 * operations according to RFC 6749 specification. It provides static factory
 * methods for creating standard OAuth 2.0 error responses.
 * </p>
 * <p>
 * <b>Standard Error Codes (RFC 6749 Section 5.2):</b></p>
 * <ul>
 *   <li><b>invalid_request:</b> The request is missing a required parameter,
 *       includes an unsupported parameter value (other than grant type),
 *       repeats a parameter, includes multiple credentials, utilizes more than
 *       one mechanism for authenticating the client, or is otherwise malformed</li>
 *   <li><b>invalid_client:</b> Client authentication failed (e.g., unknown client,
 *       no client authentication included, or unsupported authentication method)</li>
 *   <li><b>invalid_grant:</b> The provided authorization grant (e.g., authorization
 *       code) is invalid, expired, revoked, does not match the redirection URI used
 *       in the authorization request, or was issued to another client</li>
 *   <li><b>unauthorized_client:</b> The authenticated client is not authorized to
 *       use this authorization grant type</li>
 *   <li><b>unsupported_grant_type:</b> The authorization grant type is not supported
 *       by the authorization server</li>
 *   <li><b>invalid_scope:</b> The requested scope is invalid, unknown, malformed,
 *       or exceeds the scope granted by the resource owner</li>
 * </ul>
 *
 * <p><b>Usage Example:</b></p>
 * <pre>{@code
 * // Using static factory methods (recommended)
 * throw TokenException.invalidGrant("Authorization code has expired");
 * 
 * // With cause
 * throw TokenException.serverError("Failed to connect to token endpoint", e);
 * 
 * // Using constructor (for custom error codes)
 * throw new TokenException(OAuth2RfcErrorCode.INVALID_GRANT, "Custom error description", 400);
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 - Token Error Response</a>
 * @since 1.0
 */
public class OAuth2TokenException extends OAuth2Exception {

    /**
     * The error code for this exception.
     */
    private static final OAuth2ErrorCode ERROR_CODE = OAuth2ErrorCode.TOKEN_ERROR;

    // ============ Static Factory Methods ============

    /**
     * Creates an exception for invalid request.
     *
     * @param description the error description
     * @return a new TokenException with INVALID_REQUEST error code
     */
    public static OAuth2TokenException invalidRequest(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_REQUEST, description);
    }

    /**
     * Creates an exception for invalid request with a cause.
     *
     * @param description the error description
     * @param cause the underlying cause
     * @return a new TokenException with INVALID_REQUEST error code
     */
    public static OAuth2TokenException invalidRequest(String description, Throwable cause) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_REQUEST, description, cause);
    }

    /**
     * Creates an exception for client authentication failures.
     *
     * @param description the error description
     * @return a new TokenException with INVALID_CLIENT error code
     */
    public static OAuth2TokenException invalidClient(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_CLIENT, description);
    }

    /**
     * Creates an exception for invalid grant.
     *
     * @param description the error description
     * @return a new TokenException with INVALID_GRANT error code
     */
    public static OAuth2TokenException invalidGrant(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_GRANT, description);
    }

    /**
     * Creates an exception for invalid grant with a cause.
     *
     * @param description the error description
     * @param cause the underlying cause
     * @return a new TokenException with INVALID_GRANT error code
     */
    public static OAuth2TokenException invalidGrant(String description, Throwable cause) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_GRANT, description, cause);
    }

    /**
     * Creates an exception for unauthorized client.
     *
     * @param description the error description
     * @return a new TokenException with UNAUTHORIZED_CLIENT error code
     */
    public static OAuth2TokenException unauthorizedClient(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.UNAUTHORIZED_CLIENT, description);
    }

    /**
     * Creates an exception for unsupported grant type.
     *
     * @param description the error description
     * @return a new TokenException with UNSUPPORTED_GRANT_TYPE error code
     */
    public static OAuth2TokenException unsupportedGrantType(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.UNSUPPORTED_GRANT_TYPE, description);
    }

    /**
     * Creates an exception for invalid scope.
     *
     * @param description the error description
     * @return a new TokenException with INVALID_SCOPE error code
     */
    public static OAuth2TokenException invalidScope(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_SCOPE, description);
    }

    /**
     * Creates an exception for server error.
     *
     * @param description the error description
     * @return a new TokenException with SERVER_ERROR error code
     */
    public static OAuth2TokenException serverError(String description) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.SERVER_ERROR, description);
    }

    /**
     * Creates an exception for server error with a cause.
     *
     * @param description the error description
     * @param cause the underlying cause
     * @return a new TokenException with SERVER_ERROR error code
     */
    public static OAuth2TokenException serverError(String description, Throwable cause) {
        return new OAuth2TokenException(OAuth2RfcErrorCode.SERVER_ERROR, description, cause);
    }

    /**
     * Creates an exception for OAuth 2.0 error response from token server.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code from the response
     * @param errorDescription the error description from the response
     * @return a new TokenException
     */
    public static OAuth2TokenException oauthError(String rfcErrorCode, String errorDescription) {
        OAuth2RfcErrorCode errorCode = null;
        try {
            errorCode = OAuth2RfcErrorCode.fromValue(rfcErrorCode);
        } catch (IllegalArgumentException e) {
            // Use null for unknown error codes
        }
        return new OAuth2TokenException(
                errorCode,
                errorDescription != null ? errorDescription : "OAuth error"
        );
    }

    // ============ Constructors ============

    /**
     * Creates a new TokenException with the specified error code.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     */
    public OAuth2TokenException(OAuth2RfcErrorCode rfcErrorCode) {
        this(rfcErrorCode, null);
    }

    /**
     * Creates a new TokenException with the specified error code and description.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorDescription the error description
     */
    public OAuth2TokenException(OAuth2RfcErrorCode rfcErrorCode, String errorDescription) {
        super(rfcErrorCode, ERROR_CODE, errorDescription);
    }

    /**
     * Creates a new TokenException with the specified error code, description, and cause.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorDescription the error description
     * @param cause the underlying cause
     */
    public OAuth2TokenException(OAuth2RfcErrorCode rfcErrorCode, String errorDescription, Throwable cause) {
        super(rfcErrorCode, ERROR_CODE, cause, errorDescription);
    }

    @Override
    public String toString() {
        return "TokenException{" +
                "rfcErrorCode='" + getRfcErrorCode() + '\'' +
                '}';
    }
}