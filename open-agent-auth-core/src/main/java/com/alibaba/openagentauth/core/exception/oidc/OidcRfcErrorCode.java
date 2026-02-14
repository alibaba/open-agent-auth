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
 * OpenID Connect (OIDC) RFC error codes enumeration.
 * <p>
 * This enum provides standard OIDC error codes defined in OpenID Connect Core 1.0
 * and related specifications. It mirrors the standard error codes used throughout
 * the OIDC protocol.
 * </p>
 * <p>
 * <b>Note:</b> OIDC RFC specifications define error code values (e.g., "invalid_request")
 * but do not mandate specific HTTP status codes for each error. HTTP status codes are
 * implementation choices based on the context and transport layer.
 * </p>
 * <p>
 * <b>Error Codes defined in OpenID Connect Core 1.0 Section 3.1.2.6 (Authentication Error):</b></p>
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
 *   <li><b>interaction_required:</b> The Authorization Server requires End-User authentication</li>
 *   <li><b>login_required:</b> The Authorization Server requires End-User authentication</li>
 *   <li><b>account_selection_required:</b> The End-User is required to select a session</li>
 *   <li><b>consent_required:</b> The Authorization Server requires End-User consent</li>
 *   <li><b>invalid_request_uri:</b> The request_uri in the Authorization Request returns an error</li>
 *   <li><b>invalid_request_object:</b> The request parameter contains an invalid Request Object</li>
 * </ul>
 * <p>
 * <b>Error Codes defined in OpenID Connect Core 1.0 Section 3.1.3.3 (ID Token Error):</b></p>
 * <ul>
 *   <li><b>invalid_id_token:</b> The ID Token is invalid</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthError">OpenID Connect Core 1.0 - Authentication Error Response</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect Core 1.0 - ID Token Validation</a>
 * @since 1.0
 */
public enum OidcRfcErrorCode {

    // ============ Authentication Error Codes (OpenID Connect Core 1.0 Section 3.1.2.6) ============

    /**
     * invalid_request
     * <p>
     * The request is missing a required parameter, includes an invalid parameter value,
     * includes a parameter more than once, or is otherwise malformed.
     * </p>
     */
    INVALID_REQUEST("invalid_request", "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed"),

    /**
     * invalid_grant
     * <p>
     * The provided authorization grant (e.g., authorization code, resource owner credentials)
     * or refresh token is invalid, expired, revoked, does not match the redirection URI used
     * in the authorization request, or was issued to another client.
     * </p>
     */
    INVALID_GRANT("invalid_grant", "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client"),

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

    /**
     * interaction_required
     * <p>
     * The Authorization Server requires End-User authentication.
     * </p>
     */
    INTERACTION_REQUIRED("interaction_required", "The Authorization Server requires End-User authentication"),

    /**
     * login_required
     * <p>
     * The Authorization Server requires End-User authentication.
     * </p>
     */
    LOGIN_REQUIRED("login_required", "The Authorization Server requires End-User authentication"),

    /**
     * account_selection_required
     * <p>
     * The End-User is required to select a session.
     * </p>
     */
    ACCOUNT_SELECTION_REQUIRED("account_selection_required", "The End-User is required to select a session"),

    /**
     * consent_required
     * <p>
     * The Authorization Server requires End-User consent.
     * </p>
     */
    CONSENT_REQUIRED("consent_required", "The Authorization Server requires End-User consent"),

    /**
     * invalid_request_uri
     * <p>
     * The request_uri in the Authorization Request returns an error.
     * </p>
     */
    INVALID_REQUEST_URI("invalid_request_uri", "The request_uri in the Authorization Request returns an error"),

    /**
     * invalid_request_object
     * <p>
     * The request parameter contains an invalid Request Object.
     * </p>
     */
    INVALID_REQUEST_OBJECT("invalid_request_object", "The request parameter contains an invalid Request Object"),

    // ============ ID Token Error Codes (OpenID Connect Core 1.0 Section 3.1.3.3) ============

    /**
     * invalid_id_token
     * <p>
     * The ID Token is invalid.
     * </p>
     */
    INVALID_ID_TOKEN("invalid_id_token", "The ID Token is invalid"),

    /**
     * invalid_id_token_hint
     * <p>
     * The ID Token hint is invalid.
     */
    INVALID_ID_TOKEN_HINT("invalid_id_token_hint", "The ID Token hint is invalid");

    private final String value;
    private final String description;

    /**
     * Creates a new OIDC RFC error code.
     *
     * @param value the RFC error code value (e.g., "invalid_request")
     * @param description the human-readable description of the error
     */
    OidcRfcErrorCode(String value, String description) {
        this.value = value;
        this.description = description;
    }

    /**
     * Gets the RFC error code value.
     * <p>
     * This is the string value that should be used in OIDC error responses.
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
     * Returns the OidcRfcErrorCode enum constant for the given RFC error code value.
     *
     * @param value the RFC error code value (e.g., "invalid_request")
     * @return the OidcRfcErrorCode enum constant
     * @throws IllegalArgumentException if the value is not a valid OIDC RFC error code
     */
    public static OidcRfcErrorCode fromValue(String value) {
        for (OidcRfcErrorCode errorCode : values()) {
            if (errorCode.value.equals(value)) {
                return errorCode;
            }
        }
        throw new IllegalArgumentException("No matching OidcRfcErrorCode for [" + value + "]");
    }

    /**
     * Returns whether this error code is an authentication error (from OpenID Connect Core 1.0 Section 3.1.2.6).
     *
     * @return true if this is an authentication error code
     */
    public boolean isAuthenticationError() {
        return this == INVALID_REQUEST || this == UNAUTHORIZED_CLIENT || this == ACCESS_DENIED
                || this == UNSUPPORTED_RESPONSE_TYPE || this == INVALID_SCOPE
                || this == SERVER_ERROR || this == TEMPORARILY_UNAVAILABLE
                || this == INTERACTION_REQUIRED || this == LOGIN_REQUIRED
                || this == ACCOUNT_SELECTION_REQUIRED || this == CONSENT_REQUIRED
                || this == INVALID_REQUEST_URI || this == INVALID_REQUEST_OBJECT;
    }

    /**
     * Returns whether this error code is an ID token error (from OpenID Connect Core 1.0 Section 3.1.3.3).
     *
     * @return true if this is an ID token error code
     */
    public boolean isIdTokenError() {
        return this == INVALID_ID_TOKEN;
    }

    @Override
    public String toString() {
        return value + ": " + description;
    }
}
