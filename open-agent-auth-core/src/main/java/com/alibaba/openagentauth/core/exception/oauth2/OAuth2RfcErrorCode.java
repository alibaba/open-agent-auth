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
 * OAuth 2.0 RFC error codes enumeration.
 * <p>
 * This enum provides standard OAuth 2.0 error codes defined in RFC 6749 and related specifications.
 * It mirrors the standard error codes used throughout the OAuth 2.0 protocol.
 * </p>
 * <p>
 * <b>Note:</b> OAuth 2.0 RFC specifications define error code values (e.g., "invalid_request")
 * but do not mandate specific HTTP status codes for each error. HTTP status codes are
 * implementation choices based on the context and transport layer.
 * </p>
 * <p>
 * <b>Error Codes defined in RFC 6749 Section 4.1.2.1 (Authorization Error):</b></p>
 * <ul>
 *   <li><b>invalid_request:</b> The request is missing a required parameter, includes an invalid
 *       parameter value, includes a parameter more than once, or is otherwise malformed</li>
 *   <li><b>unauthorized_client:</b> The client is not authorized to request an authorization
 *       code using this method</li>
 *   <li><b>access_denied:</b> The resource owner or authorization server denied the request</li>
 *   <li><b>unsupported_response_type:</b> The authorization server does not support obtaining
 *       an authorization code using this method</li>
 *   <li><b>invalid_scope:</b> The requested scope is invalid, unknown, or malformed</li>
 *   <li><b>server_error:</b> The authorization server encountered an unexpected condition that
 *       prevented it from fulfilling the request</li>
 *   <li><b>temporarily_unavailable:</b> The authorization server is currently unable to handle
 *       the request due to a temporary overloading or maintenance</li>
 * </ul>
 * <p>
 * <b>Error Codes defined in RFC 6749 Section 5.2 (Token Error):</b></p>
 * <ul>
 *   <li><b>invalid_client:</b> Client authentication failed (e.g., unknown client, no client
 *       authentication included, or unsupported authentication method)</li>
 *   <li><b>invalid_grant:</b> The provided authorization grant (e.g., authorization code, resource
 *       owner credentials) or refresh token is invalid, expired, revoked, does not match the
 *       redirection URI used in the authorization request, or was issued to another client</li>
 *   <li><b>unsupported_grant_type:</b> The authorization grant type is not supported by the
 *       authorization server</li>
 * </ul>
 * <p>
 * <b>Error Codes defined in RFC 7591 (Dynamic Client Registration):</b></p>
 * <ul>
 *   <li><b>invalid_redirect_uri:</b> The value of one or more redirect_uris is invalid</li>
 *   <li><b>invalid_client_metadata:</b> The value of one of the client metadata fields is invalid</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">RFC 6749 - Authorization Error Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 - Token Error Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 * @since 1.0
 */
public enum OAuth2RfcErrorCode {

    // ============ Authorization Error Codes (RFC 6749 Section 4.1.2.1) ============

    /**
     * invalid_request
     * <p>
     * The request is missing a required parameter, includes an invalid parameter value,
     * includes a parameter more than once, or is otherwise malformed.
     * </p>
     */
    INVALID_REQUEST("invalid_request", "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed"),

    /**
     * unauthorized_client
     * <p>
     * The client is not authorized to request an authorization code using this method.
     * </p>
     */
    UNAUTHORIZED_CLIENT("unauthorized_client", "The client is not authorized to request an authorization code using this method"),

    /**
     * access_denied
     * <p>
     * The resource owner or authorization server denied the request.
     * </p>
     */
    ACCESS_DENIED("access_denied", "The resource owner or authorization server denied the request"),

    /**
     * unsupported_response_type
     * <p>
     * The authorization server does not support obtaining an authorization code using this method.
     * </p>
     */
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", "The authorization server does not support obtaining an authorization code using this method"),

    /**
     * invalid_scope
     * <p>
     * The requested scope is invalid, unknown, or malformed.
     * </p>
     */
    INVALID_SCOPE("invalid_scope", "The requested scope is invalid, unknown, or malformed"),

    /**
     * server_error
     * <p>
     * The authorization server encountered an unexpected condition that prevented it from fulfilling the request.
     * </p>
     */
    SERVER_ERROR("server_error", "The authorization server encountered an unexpected condition that prevented it from fulfilling the request"),

    /**
     * temporarily_unavailable
     * <p>
     * The authorization server is currently unable to handle the request due to a temporary overloading or maintenance.
     * </p>
     */
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable", "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance"),

    // ============ Token Error Codes (RFC 6749 Section 5.2) ============

    /**
     * invalid_client
     * <p>
     * Client authentication failed (e.g., unknown client, no client authentication included,
     * or unsupported authentication method).
     * </p>
     */
    INVALID_CLIENT("invalid_client", "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method)"),

    /**
     * invalid_grant
     * <p>
     * The provided authorization grant (e.g., authorization code, resource owner credentials)
     * or refresh token is invalid, expired, revoked, does not match the redirection URI used
     * in the authorization request, or was issued to another client.
     * </p>
     */
    INVALID_GRANT("invalid_grant", "The provided authorization grant or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client"),

    /**
     * unsupported_grant_type
     * <p>
     * The authorization grant type is not supported by the authorization server.
     * </p>
     */
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", "The authorization grant type is not supported by the authorization server"),

    // ============ Dynamic Client Registration Error Codes (RFC 7591) ============

    /**
     * invalid_redirect_uri
     * <p>
     * The value of one or more redirect_uris is invalid.
     * </p>
     */
    INVALID_REDIRECT_URI("invalid_redirect_uri", "The value of one or more redirect_uris is invalid"),

    /**
     * invalid_client_metadata
     * <p>
     * The value of one of the client metadata fields is invalid.
     * </p>
     */
    INVALID_CLIENT_METADATA("invalid_client_metadata", "The value of one of the client metadata fields is invalid");

    private final String value;
    private final String description;

    /**
     * Creates a new OAuth 2.0 RFC error code.
     *
     * @param value the RFC error code value (e.g., "invalid_request")
     * @param description the human-readable description of the error
     */
    OAuth2RfcErrorCode(String value, String description) {
        this.value = value;
        this.description = description;
    }

    /**
     * Gets the RFC error code value.
     * <p>
     * This is the string value that should be used in OAuth 2.0 error responses.
     * </p>
     *
     * @return the RFC error code value (e.g., "invalid_request")
     */
    public String getValue() {
        return value;
    }

    /**
     * Gets the human-readable description of this error code.
     *
     * @return the error description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Returns the OAuth2RfcErrorCode enum constant for the given RFC error code value.
     *
     * @param value the RFC error code value (e.g., "invalid_request")
     * @return the OAuth2RfcErrorCode enum constant
     * @throws IllegalArgumentException if the value is not a valid OAuth 2.0 RFC error code
     */
    public static OAuth2RfcErrorCode fromValue(String value) {
        for (OAuth2RfcErrorCode errorCode : values()) {
            if (errorCode.value.equals(value)) {
                return errorCode;
            }
        }
        throw new IllegalArgumentException("No matching OAuth2RfcErrorCode for [" + value + "]");
    }

    /**
     * Returns whether this error code is an authorization error (from RFC 6749 Section 4.1.2.1).
     *
     * @return true if this is an authorization error code
     */
    public boolean isAuthorizationError() {
        return this == INVALID_REQUEST || this == UNAUTHORIZED_CLIENT || this == ACCESS_DENIED
                || this == UNSUPPORTED_RESPONSE_TYPE || this == INVALID_SCOPE
                || this == SERVER_ERROR || this == TEMPORARILY_UNAVAILABLE;
    }

    /**
     * Returns whether this error code is a token error (from RFC 6749 Section 5.2).
     *
     * @return true if this is a token error code
     */
    public boolean isTokenError() {
        return this == INVALID_CLIENT || this == INVALID_GRANT || this == UNSUPPORTED_GRANT_TYPE;
    }

    /**
     * Returns whether this error code is a client registration error (from RFC 7591).
     *
     * @return true if this is a client registration error code
     */
    public boolean isClientRegistrationError() {
        return this == INVALID_REDIRECT_URI || this == INVALID_CLIENT_METADATA;
    }

    @Override
    public String toString() {
        return value + ": " + description;
    }
}