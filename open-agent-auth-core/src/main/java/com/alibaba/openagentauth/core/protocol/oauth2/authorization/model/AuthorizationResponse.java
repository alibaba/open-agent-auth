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
package com.alibaba.openagentauth.core.protocol.oauth2.authorization.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Authorization Response according to OAuth 2.0 Authorization Code Flow.
 * <p>
 * This class represents the response returned by the Authorization Server's
 * authorization endpoint after processing an authorization request. The response
 * can be either a success response containing an authorization code or an error
 * response with error details.
 * </p>
 * <p>
 * <b>Success Response Fields (RFC 6749 Section 4.1.2):</b></p>
 * <ul>
 *   <li><b>code:</b> REQUIRED - The authorization code</li>
 *   <li><b>state:</b> REQUIRED if present in request - The state parameter for CSRF protection</li>
 *   <li><b>redirect_uri:</b> The redirect URI where the response is sent</li>
 * </ul>
 * <p>
 * <b>Error Response Fields (RFC 6749 Section 4.1.2.1):</b></p>
 * <ul>
 *   <li><b>error:</b> REQUIRED - The error code</li>
 *   <li><b>error_description:</b> OPTIONAL - Human-readable description</li>
 *   <li><b>error_uri:</b> OPTIONAL - URI with more information about the error</li>
 *   <li><b>state:</b> REQUIRED if present in request - The state parameter</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2">RFC 6749 - Authorization Response</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationResponse {

    /**
     * The redirect URI where the authorization response is sent.
     * <p>
     * This is the URI to which the authorization server redirects the user-agent
     * with the authorization response.
     * </p>
     */
    @JsonProperty("redirect_uri")
    private final String redirectUri;

    /**
     * The authorization code.
     * <p>
     * This is the authorization code issued by the authorization server. The client
     * will use this code to obtain an access token from the token endpoint.
     * </p>
     */
    @JsonProperty("code")
    private final String authorizationCode;

    /**
     * The state parameter.
     * <p>
     * This parameter is used to prevent CSRF attacks. If the client included a
     * state parameter in the authorization request, the authorization server must
     * include the same value in the response.
     * </p>
     */
    @JsonProperty("state")
    private final String state;

    /**
     * The error code.
     * <p>
     * This field is present only in error responses. It contains a single ASCII
     * error code from the following set: invalid_request, unauthorized_client,
     * access_denied, unsupported_response_type, invalid_scope, server_error,
     * temporarily_unavailable.
     * </p>
     */
    @JsonProperty("error")
    private final String error;

    /**
     * Human-readable error description.
     * <p>
     * This field is present only in error responses. It provides additional
     * information about the error to assist the client developer.
     * </p>
     */
    @JsonProperty("error_description")
    private final String errorDescription;

    /**
     * URI with more information about the error.
     * <p>
     * This field is present only in error responses. It points to a web page with
     * more information about the error, intended for the client developer.
     * </p>
     */
    @JsonProperty("error_uri")
    private final String errorUri;

    private AuthorizationResponse(Builder builder) {
        this.redirectUri = builder.redirectUri;
        this.authorizationCode = builder.authorizationCode;
        this.state = builder.state;
        this.error = builder.error;
        this.errorDescription = builder.errorDescription;
        this.errorUri = builder.errorUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public String getState() {
        return state;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String getErrorUri() {
        return errorUri;
    }

    /**
     * Checks if this is a successful authorization response.
     *
     * @return true if the response is successful (no error), false otherwise
     */
    public boolean isSuccess() {
        return error == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationResponse that = (AuthorizationResponse) o;
        return Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(authorizationCode, that.authorizationCode) &&
                Objects.equals(state, that.state) &&
                Objects.equals(error, that.error) &&
                Objects.equals(errorDescription, that.errorDescription) &&
                Objects.equals(errorUri, that.errorUri);
    }

    @Override
    public int hashCode() {
        return Objects.hash(redirectUri, authorizationCode, state, error, errorDescription, errorUri);
    }

    @Override
    public String toString() {
        return "AuthorizationResponse{" +
                "redirectUri='" + redirectUri + '\'' +
                ", authorizationCode='" + authorizationCode + '\'' +
                ", state='" + state + '\'' +
                ", error='" + error + '\'' +
                ", errorDescription='" + errorDescription + '\'' +
                ", errorUri='" + errorUri + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AuthorizationResponse}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AuthorizationResponse}.
     */
    public static class Builder {
        private String redirectUri;
        private String authorizationCode;
        private String state;
        private String error;
        private String errorDescription;
        private String errorUri;

        /**
         * Sets the redirect URI.
         *
         * @param redirectUri the redirect URI
         * @return this builder instance
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        /**
         * Sets the authorization code.
         *
         * @param authorizationCode the authorization code
         * @return this builder instance
         */
        public Builder authorizationCode(String authorizationCode) {
            this.authorizationCode = authorizationCode;
            return this;
        }

        /**
         * Sets the state parameter.
         *
         * @param state the state parameter
         * @return this builder instance
         */
        public Builder state(String state) {
            this.state = state;
            return this;
        }

        /**
         * Sets the error code.
         *
         * @param error the error code
         * @return this builder instance
         */
        public Builder error(String error) {
            this.error = error;
            return this;
        }

        /**
         * Sets the error description.
         *
         * @param errorDescription the error description
         * @return this builder instance
         */
        public Builder errorDescription(String errorDescription) {
            this.errorDescription = errorDescription;
            return this;
        }

        /**
         * Sets the error URI.
         *
         * @param errorUri the error URI
         * @return this builder instance
         */
        public Builder errorUri(String errorUri) {
            this.errorUri = errorUri;
            return this;
        }

        /**
         * Builds the {@link AuthorizationResponse}.
         *
         * @return the built authorization response
         * @throws IllegalStateException if required fields are missing
         */
        public AuthorizationResponse build() {
            // For success responses, authorization code is required
            // For error responses, error is required
            if (error == null && authorizationCode == null) {
                throw new IllegalStateException("Either authorization code or error is required");
            }
            if (error != null && authorizationCode != null) {
                throw new IllegalStateException("Cannot have both authorization code and error");
            }
            return new AuthorizationResponse(this);
        }
    }
}
