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
package com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * OAuth 2.0 Client capability properties.
 * <p>
 * This class defines configuration for the OAuth 2.0 Client capability,
 * which enables applications to act as OAuth 2.0 clients and obtain tokens
 * from authorization servers.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     oauth2-client:
 *       enabled: true
 *       authentication:
 *         enabled: true
 *         include-paths:
 *           - /api/v1/**
 *         exclude-paths:
 *           - /health
 *       callback:
 *         enabled: true
 *         endpoint: /callback
 *         client-id: my-client
 *         client-secret: my-secret
 * </pre>
 *
 * @since 2.0
 * @see OAuth2ClientAuthenticationProperties
 * @see OAuth2ClientCallbackProperties
 */
@ConfigurationProperties(prefix = "open-agent-auth.capabilities.oauth2-client")
public class OAuth2ClientProperties {

    /**
     * Whether OAuth 2.0 Client capability is enabled.
     * <p>
     * When enabled, the application can act as an OAuth 2.0 client and
     * authenticate users using OAuth 2.0 authorization flows.
     * </p>
     * <p>
     * Default value: {@code false}
     * </p>
     */
    private boolean enabled = false;

    /**
     * Authentication configuration for protecting endpoints.
     * <p>
     * Defines which endpoints require OAuth 2.0 authentication and how
     * paths are included or excluded from authentication.
     * </p>
     */
    private OAuth2ClientAuthenticationProperties authentication = new OAuth2ClientAuthenticationProperties();

    /**
     * Callback configuration for OAuth 2.0 authorization flow.
     * <p>
     * Defines the callback endpoint and credentials for handling OAuth 2.0
     * authorization code responses.
     * </p>
     */
    private OAuth2ClientCallbackProperties callback = new OAuth2ClientCallbackProperties();

    /**
     * Gets whether the OAuth 2.0 Client capability is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the OAuth 2.0 Client capability is enabled.
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the authentication configuration.
     *
     * @return the authentication configuration
     */
    public OAuth2ClientAuthenticationProperties getAuthentication() {
        return authentication;
    }

    /**
     * Sets the authentication configuration.
     *
     * @param authentication the authentication configuration to set
     */
    public void setAuthentication(OAuth2ClientAuthenticationProperties authentication) {
        this.authentication = authentication;
    }

    /**
     * Gets the callback configuration.
     *
     * @return the callback configuration
     */
    public OAuth2ClientCallbackProperties getCallback() {
        return callback;
    }

    /**
     * Sets the callback configuration.
     *
     * @param callback the callback configuration to set
     */
    public void setCallback(OAuth2ClientCallbackProperties callback) {
        this.callback = callback;
    }

    /**
     * OAuth 2.0 Client authentication configuration.
     * <p>
     * This inner class defines how OAuth 2.0 client authentication is applied
     * to protect application endpoints.
     * </p>
     */
    public static class OAuth2ClientAuthenticationProperties {
        /**
         * Whether authentication is enabled.
         * <p>
         * When enabled, requests to included paths will require valid OAuth 2.0 tokens.
         * </p>
         * <p>
         * Default value: {@code true}
         * </p>
         */
        private boolean enabled = true;

        /**
         * Include paths for authentication.
         * <p>
         * A list of path patterns that require OAuth 2.0 authentication.
         * Supports Ant-style path patterns (e.g., {@code /api/v1/**}).
         * </p>
         * <p>
         * Default value: {@code ["/**"]} - protects all API endpoints by default for security.
         * </p>
         */
        private List<String> includePaths = List.of("/**");

        /**
         * Exclude paths from authentication.
         * <p>
         * A list of path patterns that should be excluded from OAuth 2.0 authentication,
         * even if they match include paths. Supports Ant-style path patterns.
         * </p>
         * <p>
         * Default value: {@code ["/login", "/callback", "/public/**", "/oauth2/consent", "/oauth2/authorize", "/.well-known/**"]}
         * </p>
         */
        private List<String> excludePaths = List.of("/login", "/callback", "/public/**", "/oauth2/consent", "/oauth2/authorize", "/.well-known/**");

        /**
         * Gets whether authentication is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether authentication is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the include paths.
         *
         * @return the list of include paths
         */
        public List<String> getIncludePaths() {
            return includePaths;
        }

        /**
         * Sets the include paths.
         *
         * @param includePaths the list of include paths to set
         */
        public void setIncludePaths(List<String> includePaths) {
            this.includePaths = includePaths;
        }

        /**
         * Gets the exclude paths.
         *
         * @return the list of exclude paths
         */
        public List<String> getExcludePaths() {
            return excludePaths;
        }

        /**
         * Sets the exclude paths.
         *
         * @param excludePaths the list of exclude paths to set
         */
        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }
    }

    /**
     * OAuth 2.0 Client callback configuration.
     * <p>
     * This inner class defines the callback endpoint and credentials for
     * handling OAuth 2.0 authorization code responses from the authorization server.
     * </p>
     */
    public static class OAuth2ClientCallbackProperties {
        /**
         * Whether callback is enabled.
         * <p>
         * When enabled, the application will expose a callback endpoint to receive
         * OAuth 2.0 authorization code responses.
         * </p>
         * <p>
         * Default value: {@code false}
         * </p>
         */
        private boolean enabled = false;

        /**
         * Callback endpoint path.
         * <p>
         * The endpoint path where the authorization server will redirect the user
         * after authorization with the authorization code.
         * </p>
         * <p>
         * Default value: {@code /callback}
         * </p>
         */
        private String endpoint = "/callback";

        /**
         * Client ID for token exchange.
         * <p>
         * The OAuth 2.0 client identifier used to exchange the authorization code
         * for an access token at the authorization server.
         * </p>
         */
        private String clientId;

        /**
         * Client secret for token exchange.
         * <p>
         * The OAuth 2.0 client secret used to authenticate the client when exchanging
         * the authorization code for an access token.
         * </p>
         */
        private String clientSecret;

        /**
         * Whether to auto-register the client.
         * <p>
         * When enabled, the client will be automatically registered with the
         * authorization server using Dynamic Client Registration (DCR).
         * </p>
         * <p>
         * Default value: {@code false}
         * </p>
         */
        private boolean autoRegister = false;

        /**
         * Gets whether callback is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether callback is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the callback endpoint path.
         *
         * @return the callback endpoint path
         */
        public String getEndpoint() {
            return endpoint;
        }

        /**
         * Sets the callback endpoint path.
         *
         * @param endpoint the callback endpoint path to set
         */
        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        /**
         * Gets the client ID.
         *
         * @return the client ID
         */
        public String getClientId() {
            return clientId;
        }

        /**
         * Sets the client ID.
         *
         * @param clientId the client ID to set
         */
        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        /**
         * Gets the client secret.
         *
         * @return the client secret
         */
        public String getClientSecret() {
            return clientSecret;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret to set
         */
        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        /**
         * Gets whether auto-registration is enabled.
         *
         * @return {@code true} if auto-registration is enabled, {@code false} otherwise
         */
        public boolean isAutoRegister() {
            return autoRegister;
        }

        /**
         * Sets whether auto-registration is enabled.
         *
         * @param autoRegister {@code true} to enable auto-registration, {@code false} to disable
         */
        public void setAutoRegister(boolean autoRegister) {
            this.autoRegister = autoRegister;
        }
    }
}