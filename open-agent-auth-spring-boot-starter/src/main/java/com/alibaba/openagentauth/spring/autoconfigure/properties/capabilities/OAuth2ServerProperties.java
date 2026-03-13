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

import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * OAuth 2.0 Server capability properties.
 * <p>
 * This class defines configuration for the OAuth 2.0 Authorization Server capability,
 * which provides OAuth 2.0 authorization flows including authorization code, client credentials,
 * and other grant types.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link CapabilitiesProperties} and bound as part of
 * the {@code open-agent-auth.capabilities.oauth2-server} prefix through the parent class hierarchy.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     oauth2-server:
 *       enabled: true
 *       endpoints:
 *         authorize: /oauth2/authorize
 *         token: /oauth2/token
 *       token:
 *         access-token-expiry: 3600
 *         refresh-token-expiry: 2592000
 *       auto-register-clients:
 *         enabled: true
 *         endpoints:
 *           oauth2:
 *             authorize: /oauth2/authorize
 *             token: /oauth2/token
 *             par: /par
 *             userinfo: /oauth2/userinfo
 *             dcr: /oauth2/register
 *             logout: /oauth2/logout
 *         token:
 *           access-token-expiry: 3600
 *           refresh-token-expiry: 2592000
 *         auto-register-clients:
 *           enabled: true
 *           clients:
 *             - client-name: My Client
 *               client-id: my-client
 *               client-secret: my-secret
 *         clients:
 *           - client-name: My Client
 *             client-id: my-client
 *             client-secret: my-secret
 * </pre>
 *
 * @since 2.0
 * @see OAuth2EndpointsProperties
 * @see OAuth2TokenProperties
 * @see AutoRegisterClientsProperties
 */
public class OAuth2ServerProperties {

    /**
     * Whether OAuth 2.0 Server capability is enabled.
     * <p>
     * When enabled, the application will act as an OAuth 2.0 authorization server
     * and expose OAuth 2.0 endpoints for authorization and token issuance.
     * </p>
     * <p>
     * Default value: {@code false}
     * </p>
     */
    private boolean enabled = false;

    /**
     * Endpoint configurations for OAuth 2.0 flows.
     * <p>
     * Defines the REST API endpoints for OAuth 2.0 authorization, token,
     * userinfo, and other OAuth 2.0 related operations.
     * </p>
     */
    private OAuth2EndpointsProperties endpoints = new OAuth2EndpointsProperties();

    /**
     * Token configuration.
     * <p>
     * Defines the expiry times and other settings for OAuth 2.0 tokens
     * including access tokens, refresh tokens, ID tokens, and authorization codes.
     * </p>
     */
    private OAuth2TokenProperties token = new OAuth2TokenProperties();

    /**
     * Auto-register clients configuration.
     * <p>
     * Defines the list of OAuth 2.0 clients that should be automatically
     * registered with the authorization server at startup.
     * </p>
     */
    private AutoRegisterClientsProperties autoRegisterClients = new AutoRegisterClientsProperties();

    /**
     * Gets whether the OAuth 2.0 Server capability is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the OAuth 2.0 Server capability is enabled.
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the endpoint configurations.
     *
     * @return the endpoint configurations
     */
    public OAuth2EndpointsProperties getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the endpoint configurations.
     *
     * @param endpoints the endpoint configurations to set
     */
    public void setEndpoints(OAuth2EndpointsProperties endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Gets the token configuration.
     *
     * @return the token configuration
     */
    public OAuth2TokenProperties getToken() {
        return token;
    }

    /**
     * Sets the token configuration.
     *
     * @param token the token configuration to set
     */
    public void setToken(OAuth2TokenProperties token) {
        this.token = token;
    }

    /**
     * Gets the auto-register clients configuration.
     *
     * @return the auto-register clients configuration
     */
    public AutoRegisterClientsProperties getAutoRegisterClients() {
        return autoRegisterClients;
    }

    /**
     * Sets the auto-register clients configuration.
     *
     * @param autoRegisterClients the auto-register clients configuration to set
     */
    public void setAutoRegisterClients(AutoRegisterClientsProperties autoRegisterClients) {
        this.autoRegisterClients = autoRegisterClients;
    }

    /**
     * OAuth 2.0 endpoints configuration.
     * <p>
     * This inner class defines all REST API endpoints for the OAuth 2.0 authorization server,
     * including authorization, token, userinfo, PAR, DCR, and logout endpoints.
     * </p>
     */
    public static class OAuth2EndpointsProperties {

        /**
         * OAuth 2.0 REST API endpoint configurations.
         * <p>
         * This nested class contains the specific endpoint paths for OAuth 2.0 operations
         * such as authorize, token, userinfo, PAR, DCR, and logout.
         * </p>
         */
        private OAuth2EndpointPaths oauth2 = new OAuth2EndpointPaths();

        /**
         * Gets the OAuth 2.0 endpoint paths.
         *
         * @return the OAuth 2.0 endpoint paths
         */
        public OAuth2EndpointPaths getOauth2() {
            return oauth2;
        }

        /**
         * Sets the OAuth 2.0 endpoint paths.
         *
         * @param oauth2 the OAuth 2.0 endpoint paths to set
         */
        public void setOauth2(OAuth2EndpointPaths oauth2) {
            this.oauth2 = oauth2;
        }

        /**
         * OAuth 2.0 endpoint paths configuration.
         * <p>
         * This inner class defines the specific REST API endpoint paths for
         * OAuth 2.0 authorization server operations.
         * </p>
         */
        public static class OAuth2EndpointPaths {

            /**
             * Authorization endpoint path.
             * <p>
             * The endpoint where the authorization server redirects the user for authentication
             * and consent in the authorization code flow.
             * </p>
             * <p>
             * Default value: {@code /oauth2/authorize}
             * </p>
             */
            private String authorize = "/oauth2/authorize";

            /**
             * Token endpoint path.
             * <p>
             * The endpoint where clients exchange authorization codes, refresh tokens, or
             * client credentials for access tokens.
             * </p>
             * <p>
             * Default value: {@code /oauth2/token}
             * </p>
             */
            private String token = "/oauth2/token";

            /**
             * PAR (Pushed Authorization Request) endpoint path.
             * <p>
             * The endpoint where clients can push authorization request parameters to the
             * authorization server to receive a request URI, improving security and preventing
             * request parameter leakage.
             * </p>
             * <p>
             * Default value: {@code /par}
             * </p>
             */
            private String par = "/par";

            /**
             * Userinfo endpoint path.
             * <p>
             * The endpoint where clients can retrieve user profile information using an access token.
             * </p>
             * <p>
             * Default value: {@code /oauth2/userinfo}
             * </p>
             */
            private String userinfo = "/oauth2/userinfo";

            /**
             * DCR (Dynamic Client Registration) endpoint path.
             * <p>
             * The endpoint where clients can dynamically register themselves with the authorization server.
             * </p>
             * <p>
             * Default value: {@code /oauth2/register}
             * </p>
             */
            private String dcr = "/oauth2/register";

            /**
             * Logout endpoint path.
             * <p>
             * The endpoint where users can log out and invalidate their session.
             * </p>
             * <p>
             * Default value: {@code /oauth2/logout}
             * </p>
             */
            private String logout = "/oauth2/logout";

            /**
             * Gets the authorization endpoint path.
             *
             * @return the authorization endpoint path
             */
            public String getAuthorize() {
                return authorize;
            }

            /**
             * Sets the authorization endpoint path.
             *
             * @param authorize the authorization endpoint path to set
             */
            public void setAuthorize(String authorize) {
                this.authorize = authorize;
            }

            /**
             * Gets the token endpoint path.
             *
             * @return the token endpoint path
             */
            public String getToken() {
                return token;
            }

            /**
             * Sets the token endpoint path.
             *
             * @param token the token endpoint path to set
             */
            public void setToken(String token) {
                this.token = token;
            }

            /**
             * Gets the PAR endpoint path.
             *
             * @return the PAR endpoint path
             */
            public String getPar() {
                return par;
            }

            /**
             * Sets the PAR endpoint path.
             *
             * @param par the PAR endpoint path to set
             */
            public void setPar(String par) {
                this.par = par;
            }

            /**
             * Gets the userinfo endpoint path.
             *
             * @return the userinfo endpoint path
             */
            public String getUserinfo() {
                return userinfo;
            }

            /**
             * Sets the userinfo endpoint path.
             *
             * @param userinfo the userinfo endpoint path to set
             */
            public void setUserinfo(String userinfo) {
                this.userinfo = userinfo;
            }

            /**
             * Gets the DCR endpoint path.
             *
             * @return the DCR endpoint path
             */
            public String getDcr() {
                return dcr;
            }

            /**
             * Sets the DCR endpoint path.
             *
             * @param dcr the DCR endpoint path to set
             */
            public void setDcr(String dcr) {
                this.dcr = dcr;
            }

            /**
             * Gets the logout endpoint path.
             *
             * @return the logout endpoint path
             */
            public String getLogout() {
                return logout;
            }

            /**
             * Sets the logout endpoint path.
             *
             * @param logout the logout endpoint path to set
             */
            public void setLogout(String logout) {
                this.logout = logout;
            }
        }
    }

    /**
     * OAuth 2.0 token configuration.
     * <p>
     * This inner class defines the expiry times for various OAuth 2.0 token types
     * issued by the authorization server.
     * </p>
     */
    public static class OAuth2TokenProperties {
        /**
         * Access token expiry in seconds.
         * <p>
         * The lifetime of access tokens issued by the authorization server.
         * </p>
         * <p>
         * Default value: {@code 3600} (1 hour)
         * </p>
         */
        private int accessTokenExpiry = 3600;

        /**
         * Refresh token expiry in seconds.
         * <p>
         * The lifetime of refresh tokens issued by the authorization server.
         * Refresh tokens are long-lived and used to obtain new access tokens.
         * </p>
         * <p>
         * Default value: {@code 2592000} (30 days)
         * </p>
         */
        private int refreshTokenExpiry = 2592000;

        /**
         * ID token expiry in seconds.
         * <p>
         * The lifetime of ID tokens issued by the authorization server.
         * ID tokens contain user identity claims in OpenID Connect.
         * </p>
         * <p>
         * Default value: {@code 3600} (1 hour)
         * </p>
         */
        private int idTokenExpiry = 3600;

        /**
         * Authorization code expiry in seconds.
         * <p>
         * The lifetime of authorization codes issued by the authorization server.
         * Authorization codes are short-lived and must be exchanged for tokens quickly.
         * </p>
         * <p>
         * Default value: {@code 600} (10 minutes)
         * </p>
         */
        private int authorizationCodeExpiry = 600;

        /**
         * Pushed Authorization Request (PAR) expiry in seconds.
         * <p>
         * The lifetime of PAR request URIs issued by the authorization server.
         * PAR requests must be used within this time window. In flows involving
         * user authentication redirects (e.g., to an external IDP), this value
         * should be large enough to accommodate the entire authentication flow.
         * </p>
         * <p>
         * Default value: {@code 600} (10 minutes)
         * </p>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
         */
        private int parRequestExpiry = 600;

        /**
         * Gets the access token expiry in seconds.
         *
         * @return the access token expiry in seconds
         */
        public int getAccessTokenExpiry() {
            return accessTokenExpiry;
        }

        /**
         * Sets the access token expiry in seconds.
         *
         * @param accessTokenExpiry the access token expiry in seconds to set
         */
        public void setAccessTokenExpiry(int accessTokenExpiry) {
            this.accessTokenExpiry = accessTokenExpiry;
        }

        /**
         * Gets the refresh token expiry in seconds.
         *
         * @return the refresh token expiry in seconds
         */
        public int getRefreshTokenExpiry() {
            return refreshTokenExpiry;
        }

        /**
         * Sets the refresh token expiry in seconds.
         *
         * @param refreshTokenExpiry the refresh token expiry in seconds to set
         */
        public void setRefreshTokenExpiry(int refreshTokenExpiry) {
            this.refreshTokenExpiry = refreshTokenExpiry;
        }

        /**
         * Gets the ID token expiry in seconds.
         *
         * @return the ID token expiry in seconds
         */
        public int getIdTokenExpiry() {
            return idTokenExpiry;
        }

        /**
         * Sets the ID token expiry in seconds.
         *
         * @param idTokenExpiry the ID token expiry in seconds to set
         */
        public void setIdTokenExpiry(int idTokenExpiry) {
            this.idTokenExpiry = idTokenExpiry;
        }

        /**
         * Gets the authorization code expiry in seconds.
         *
         * @return the authorization code expiry in seconds
         */
        public int getAuthorizationCodeExpiry() {
            return authorizationCodeExpiry;
        }

        /**
         * Sets the authorization code expiry in seconds.
         *
         * @param authorizationCodeExpiry the authorization code expiry in seconds to set
         */
        public void setAuthorizationCodeExpiry(int authorizationCodeExpiry) {
            this.authorizationCodeExpiry = authorizationCodeExpiry;
        }

        /**
         * Gets the PAR request expiry in seconds.
         *
         * @return the PAR request expiry in seconds
         */
        public int getParRequestExpiry() {
            return parRequestExpiry;
        }

        /**
         * Sets the PAR request expiry in seconds.
         *
         * @param parRequestExpiry the PAR request expiry in seconds to set
         */
        public void setParRequestExpiry(int parRequestExpiry) {
            this.parRequestExpiry = parRequestExpiry;
        }
    }

    /**
     * Auto-register clients configuration.
     * <p>
     * This inner class defines the list of OAuth 2.0 clients that should be automatically
     * registered with the authorization server at startup using Dynamic Client Registration (DCR).
     * </p>
     */
    public static class AutoRegisterClientsProperties {
        /**
         * Whether auto-register clients is enabled.
         * <p>
         * When enabled, the authorization server will automatically register the clients
         * defined in the {@code clients} list at startup.
         * </p>
         * <p>
         * Default value: {@code false}
         * </p>
         */
        private boolean enabled = false;

        /**
         * Client configurations.
         * <p>
         * A list of OAuth 2.0 client configurations to be automatically registered.
         * </p>
         * <p>
         * Default value: empty list
         * </p>
         */
        private List<AutoRegisterClientItemProperties> clients = new ArrayList<>();

        /**
         * Gets whether auto-register clients is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether auto-register clients is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the client configurations.
         *
         * @return the list of client configurations
         */
        public List<AutoRegisterClientItemProperties> getClients() {
            return clients;
        }

        /**
         * Sets the client configurations.
         *
         * @param clients the list of client configurations to set
         */
        public void setClients(List<AutoRegisterClientItemProperties> clients) {
            this.clients = clients;
        }

        /**
         * Auto-register client item configuration.
         * <p>
         * This inner class defines the configuration for a single OAuth 2.0 client
         * that will be automatically registered with the authorization server.
         * </p>
         */
        public static class AutoRegisterClientItemProperties {
            /**
             * Client name.
             * <p>
             * A human-readable name for the OAuth 2.0 client.
             * </p>
             */
            private String clientName;

            /**
             * Client ID.
             * <p>
             * The unique identifier for the OAuth 2.0 client.
             * </p>
             */
            private String clientId;

            /**
             * Client secret.
             * <p>
             * The secret used to authenticate the client with the authorization server.
             * </p>
             */
            private String clientSecret;

            /**
             * Redirect URIs.
             * <p>
             * A list of URIs where the authorization server will redirect the user after
             * successful authorization. At least one redirect URI is required.
             * </p>
             * <p>
             * Default value: empty list
             * </p>
             */
            private List<String> redirectUris = new ArrayList<>();

            /**
             * Grant types.
             * <p>
             * A list of OAuth 2.0 grant types that the client is allowed to use,
             * such as {@code authorization_code}, {@code client_credentials}, {@code refresh_token}.
             * </p>
             * <p>
             * Default value: empty list
             * </p>
             */
            private List<String> grantTypes = new ArrayList<>();

            /**
             * Response types.
             * <p>
             * A list of OAuth 2.0 response types that the client is allowed to use,
             * such as {@code code} for authorization code flow.
             * </p>
             * <p>
             * Default value: empty list
             * </p>
             */
            private List<String> responseTypes = new ArrayList<>();

            /**
             * Token endpoint authentication method.
             * <p>
             * The method used to authenticate the client at the token endpoint.
             * Common values include {@code client_secret_basic}, {@code client_secret_post},
             * {@code private_key_jwt}, {@code none}.
             * </p>
             * <p>
             * Default value: {@code client_secret_basic}
             * </p>
             */
            private String tokenEndpointAuthMethod = "client_secret_basic";

            /**
             * Scopes.
             * <p>
             * A list of OAuth 2.0 scopes that the client is allowed to request.
             * Scopes define the permissions granted to the access token.
             * </p>
             * <p>
             * Default value: empty list
             * </p>
             */
            private List<String> scopes = new ArrayList<>();

            /**
             * Gets the client name.
             *
             * @return the client name
             */
            public String getClientName() {
                return clientName;
            }

            /**
             * Sets the client name.
             *
             * @param clientName the client name to set
             */
            public void setClientName(String clientName) {
                this.clientName = clientName;
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
             * Gets the redirect URIs.
             *
             * @return the list of redirect URIs
             */
            public List<String> getRedirectUris() {
                return redirectUris;
            }

            /**
             * Sets the redirect URIs.
             *
             * @param redirectUris the list of redirect URIs to set
             */
            public void setRedirectUris(List<String> redirectUris) {
                this.redirectUris = redirectUris;
            }

            /**
             * Gets the grant types.
             *
             * @return the list of grant types
             */
            public List<String> getGrantTypes() {
                return grantTypes;
            }

            /**
             * Sets the grant types.
             *
             * @param grantTypes the list of grant types to set
             */
            public void setGrantTypes(List<String> grantTypes) {
                this.grantTypes = grantTypes;
            }

            /**
             * Gets the response types.
             *
             * @return the list of response types
             */
            public List<String> getResponseTypes() {
                return responseTypes;
            }

            /**
             * Sets the response types.
             *
             * @param responseTypes the list of response types to set
             */
            public void setResponseTypes(List<String> responseTypes) {
                this.responseTypes = responseTypes;
            }

            /**
             * Gets the token endpoint authentication method.
             *
             * @return the token endpoint authentication method
             */
            public String getTokenEndpointAuthMethod() {
                return tokenEndpointAuthMethod;
            }

            /**
             * Sets the token endpoint authentication method.
             *
             * @param tokenEndpointAuthMethod the token endpoint authentication method to set
             */
            public void setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
                this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
            }

            /**
             * Gets the scopes.
             *
             * @return the list of scopes
             */
            public List<String> getScopes() {
                return scopes;
            }

            /**
             * Sets the scopes.
             *
             * @param scopes the list of scopes to set
             */
            public void setScopes(List<String> scopes) {
                this.scopes = scopes;
            }
        }
    }
}