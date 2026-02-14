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
package com.alibaba.openagentauth.core.model.oidc;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;
import java.util.Objects;

/**
 * Represents an OpenID Connect Authentication Request.
 * <p>
 * This class encapsulates the parameters sent to the Authorization Endpoint
 * to initiate an authentication request. It supports both OAuth 2.0 Authorization
 * Code Flow and Implicit Flow as defined in OpenID Connect Core 1.0.
 * </p>
 * <p>
 * <b>Standard Parameters:</b></p>
 * <ul>
 *   <li><b>response_type:</b> REQUIRED - Value that determines the authorization processing flow</li>
 *   <li><b>client_id:</b> REQUIRED - Client identifier</li>
 *   <li><b>redirect_uri:</b> REQUIRED - Redirection URI</li>
 *   <li><b>scope:</b> REQUIRED - Scope values</li>
 *   <li><b>state:</b> RECOMMENDED - Opaque value to maintain state between request and callback</li>
 *   <li><b>nonce:</b> OPTIONAL - String value used to mitigate replay attacks</li>
 *   <li><b>display:</b> OPTIONAL - ASCII string value that specifies how the Authorization Server displays the authentication and consent UI</li>
 *   <li><b>prompt:</b> OPTIONAL - Space delimited, case sensitive list of ASCII string values</li>
 *   <li><b>max_age:</b> OPTIONAL - Maximum Authentication Age</li>
 *   <li><b>ui_locales:</b> OPTIONAL - End-User's preferred languages and scripts for UI</li>
 *   <li><b>id_token_hint:</b> OPTIONAL - ID Token previously issued by the Authorization Server</li>
 *   <li><b>login_hint:</b> OPTIONAL - Hint about the End-User's login identifier</li>
 *   <li><b>acr_values:</b> OPTIONAL - Requested Authentication Context Class Reference values</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#AuthenticationRequest">OpenID Connect Core 1.0 - Authentication Request</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthenticationRequest {

    /**
     * Response type.
     * <p>
     * REQUIRED. Value that determines the authorization processing flow to be used,
     * including what parameters are returned from the endpoints.
     * </p>
     */
    private final String responseType;

    /**
     * Client identifier.
     * <p>
     * REQUIRED. OAuth 2.0 Client Identifier valid at the Authorization Server.
     * </p>
     */
    private final String clientId;

    /**
     * Redirection URI.
     * <p>
     * REQUIRED. Redirection URI to which the response will be sent. This URI MUST
     * exactly match one of the Redirection URI values for the Client pre-registered
     * at the Authorization Server.
     * </p>
     */
    private final String redirectUri;

    /**
     * Scope.
     * <p>
     * REQUIRED. OpenID Connect requests MUST contain the openid scope value.
     * Other scope values MAY be present.
     * </p>
     */
    private final String scope;

    /**
     * State.
     * <p>
     * RECOMMENDED. Opaque value used to maintain state between the request and the callback.
     * </p>
     */
    private final String state;

    /**
     * Nonce.
     * <p>
     * OPTIONAL. String value used to associate a Client session with an ID Token,
     * and to mitigate replay attacks.
     * </p>
     */
    private final String nonce;

    /**
     * Display.
     * <p>
     * OPTIONAL. ASCII string value that specifies how the Authorization Server
     * displays the authentication and consent user interface pages to the End-User.
     * </p>
     */
    private final String display;

    /**
     * Prompt.
     * <p>
     * OPTIONAL. Space delimited, case sensitive list of ASCII string values that
     * specifies whether the Authorization Server prompts the End-User for reauthentication
     * and consent.
     * </p>
     */
    private final String prompt;

    /**
     * Maximum authentication age.
     * <p>
     * OPTIONAL. Specifies the allowable elapsed time in seconds since the last time
     * the End-User was actively authenticated by the OP.
     * </p>
     */
    private final Integer maxAge;

    /**
     * UI locales.
     * <p>
     * OPTIONAL. End-User's preferred languages and scripts for the user interface,
     * represented as a space-separated list of BCP 47 language tag values.
     * </p>
     */
    private final String uiLocales;

    /**
     * ID token hint.
     * <p>
     * OPTIONAL. ID Token previously issued by the Authorization Server being passed
     * as a hint about the End-User's current or past authenticated session.
     * </p>
     */
    private final String idTokenHint;

    /**
     * Login hint.
     * <p>
     * OPTIONAL. Hint to the Authorization Server about the login identifier the
     * End-User might use to log in.
     * </p>
     */
    private final String loginHint;

    /**
     * ACR values.
     * <p>
     * OPTIONAL. Requested Authentication Context Class Reference values.
     * </p>
     */
    private final String acrValues;

    /**
     * Additional parameters.
     * <p>
     * OPTIONAL. Additional custom parameters that may be included in the request.
     * </p>
     */
    private final Map<String, String> additionalParameters;

    private AuthenticationRequest(Builder builder) {
        this.responseType = builder.responseType;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.scope = builder.scope;
        this.state = builder.state;
        this.nonce = builder.nonce;
        this.display = builder.display;
        this.prompt = builder.prompt;
        this.maxAge = builder.maxAge;
        this.uiLocales = builder.uiLocales;
        this.idTokenHint = builder.idTokenHint;
        this.loginHint = builder.loginHint;
        this.acrValues = builder.acrValues;
        this.additionalParameters = builder.additionalParameters;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getState() {
        return state;
    }

    public String getNonce() {
        return nonce;
    }

    public String getDisplay() {
        return display;
    }

    public String getPrompt() {
        return prompt;
    }

    public Integer getMaxAge() {
        return maxAge;
    }

    public String getUiLocales() {
        return uiLocales;
    }

    public String getIdTokenHint() {
        return idTokenHint;
    }

    public String getLoginHint() {
        return loginHint;
    }

    public String getAcrValues() {
        return acrValues;
    }

    public Map<String, String> getAdditionalParameters() {
        return additionalParameters;
    }

    /**
     * Checks if this request is for the Authorization Code Flow.
     *
     * @return true if response_type is "code"
     */
    public boolean isAuthorizationCodeFlow() {
        return "code".equals(responseType);
    }

    /**
     * Checks if this request is for the Implicit Flow.
     *
     * @return true if response_type contains "id_token"
     */
    public boolean isImplicitFlow() {
        return responseType != null && responseType.contains("id_token");
    }

    /**
     * Checks if the scope includes "openid".
     *
     * @return true if scope contains "openid"
     */
    public boolean hasOpenidScope() {
        return scope != null && scope.contains("openid");
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationRequest that = (AuthenticationRequest) o;
        return Objects.equals(responseType, that.responseType) &&
               Objects.equals(clientId, that.clientId) &&
               Objects.equals(redirectUri, that.redirectUri) &&
               Objects.equals(scope, that.scope) &&
               Objects.equals(state, that.state);
    }

    @Override
    public int hashCode() {
        return Objects.hash(responseType, clientId, redirectUri, scope, state);
    }

    @Override
    public String toString() {
        return "AuthenticationRequest{" +
                "responseType='" + responseType + '\'' +
                ", clientId='" + clientId + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", scope='" + scope + '\'' +
                ", state='" + state + '\'' +
                ", nonce='" + nonce + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AuthenticationRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AuthenticationRequest}.
     */
    public static class Builder {
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String nonce;
        private String display;
        private String prompt;
        private Integer maxAge;
        private String uiLocales;
        private String idTokenHint;
        private String loginHint;
        private String acrValues;
        private Map<String, String> additionalParameters;

        /**
         * Sets the response type.
         *
         * @param responseType the response type (e.g., "code", "id_token", "token")
         * @return this builder instance
         */
        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

        /**
         * Sets the client ID.
         *
         * @param clientId the client ID
         * @return this builder instance
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

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
         * Sets the scope.
         *
         * @param scope the scope (must include "openid")
         * @return this builder instance
         */
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        /**
         * Sets the state.
         *
         * @param state the state parameter
         * @return this builder instance
         */
        public Builder state(String state) {
            this.state = state;
            return this;
        }

        /**
         * Sets the nonce.
         *
         * @param nonce the nonce parameter
         * @return this builder instance
         */
        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        /**
         * Sets the display parameter.
         *
         * @param display the display parameter
         * @return this builder instance
         */
        public Builder display(String display) {
            this.display = display;
            return this;
        }

        /**
         * Sets the prompt parameter.
         *
         * @param prompt the prompt parameter
         * @return this builder instance
         */
        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        /**
         * Sets the maximum authentication age.
         *
         * @param maxAge the maximum age in seconds
         * @return this builder instance
         */
        public Builder maxAge(Integer maxAge) {
            this.maxAge = maxAge;
            return this;
        }

        /**
         * Sets the UI locales.
         *
         * @param uiLocales the UI locales
         * @return this builder instance
         */
        public Builder uiLocales(String uiLocales) {
            this.uiLocales = uiLocales;
            return this;
        }

        /**
         * Sets the ID token hint.
         *
         * @param idTokenHint the ID token hint
         * @return this builder instance
         */
        public Builder idTokenHint(String idTokenHint) {
            this.idTokenHint = idTokenHint;
            return this;
        }

        /**
         * Sets the login hint.
         *
         * @param loginHint the login hint
         * @return this builder instance
         */
        public Builder loginHint(String loginHint) {
            this.loginHint = loginHint;
            return this;
        }

        /**
         * Sets the ACR values.
         *
         * @param acrValues the ACR values
         * @return this builder instance
         */
        public Builder acrValues(String acrValues) {
            this.acrValues = acrValues;
            return this;
        }

        /**
         * Sets additional parameters.
         *
         * @param additionalParameters the additional parameters map
         * @return this builder instance
         */
        public Builder additionalParameters(Map<String, String> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }

        /**
         * Adds an additional parameter.
         *
         * @param key the parameter key
         * @param value the parameter value
         * @return this builder instance
         */
        public Builder addAdditionalParameter(String key, String value) {
            if (this.additionalParameters == null) {
                this.additionalParameters = new java.util.HashMap<>();
            }
            this.additionalParameters.put(key, value);
            return this;
        }

        /**
         * Builds the {@link AuthenticationRequest}.
         *
         * @return the built authentication request
         * @throws IllegalStateException if required fields are missing
         */
        public AuthenticationRequest build() {
            if (ValidationUtils.isNullOrEmpty(responseType)) {
                throw new IllegalStateException("response_type is required");
            }
            if (ValidationUtils.isNullOrEmpty(clientId)) {
                throw new IllegalStateException("client_id is required");
            }
            if (ValidationUtils.isNullOrEmpty(redirectUri)) {
                throw new IllegalStateException("redirect_uri is required");
            }
            if (ValidationUtils.isNullOrEmpty(scope)) {
                throw new IllegalStateException("scope is required");
            }
            if (!hasOpenidScope()) {
                throw new IllegalStateException("scope must include 'openid'");
            }
            return new AuthenticationRequest(this);
        }

        /**
         * Checks if the current scope includes "openid".
         *
         * @return true if scope contains "openid"
         */
        private boolean hasOpenidScope() {
            return scope != null && scope.contains("openid");
        }
    }
}
