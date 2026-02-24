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

/**
 * Operation Authorization capability properties.
 * <p>
 * This class defines configuration for the Operation Authorization capability,
 * which provides fine-grained authorization for agent operations including
 * prompt protection and policy evaluation.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link CapabilitiesProperties} and bound as part of
 * the {@code open-agent-auth.capabilities.operation-authorization} prefix through the parent class hierarchy.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     operation-authorization:
 *       enabled: true
 *       endpoints:
 *         policy:
 *           registry: /api/v1/policies
 *           delete: /api/v1/policies/{policyId}
 *           get: /api/v1/policies/{policyId}
 *         binding:
 *           registry: /api/v1/bindings
 *           get: /api/v1/bindings/{bindingInstanceId}
 *           delete: /api/v1/bindings/{bindingInstanceId}
 *       # Prompt encryption configuration (technical implementation)
 *       prompt-encryption:
 *         enabled: true
 *         encryption-key-id: jwe-encryption-key-001
 *       # Prompt protection configuration (business logic)
 *       prompt-protection:
 *         enabled: true
 *         sanitization-level: MEDIUM
 *       # Agent context configuration (runtime information)
 *       agent-context:
 *         agent-client: my-agent
 *         channel: web
 *       # OAuth2 client configuration (authentication credentials)
 *       oauth2-client:
 *         client-id: my-agent
 *         client-secret: my-secret
 *       # Authorization behavior configuration (authorization policy)
 *       authorization:
 *         require-user-interaction: false
 *         expiration-seconds: 3600
 * </pre>
 *
 * @since 2.0
 * @see OperationAuthorizationEndpointsProperties
 * @see PromptEncryptionProperties
 * @see PromptProtectionProperties
 * @see AgentContextProperties
 * @see OAuth2ClientProperties
 * @see AuthorizationBehaviorProperties
 */
public class OperationAuthorizationProperties {

    /**
     * Whether Operation Authorization capability is enabled.
     * <p>
     * When enabled, the application will enforce fine-grained authorization
     * policies for agent operations, including prompt protection and policy evaluation.
     * </p>
     * <p>
     * Default value: {@code false}
     * </p>
     */
    private boolean enabled = false;

    /**
     * Endpoint configurations for Operation Authorization.
     * <p>
     * Defines the REST API endpoints for policy management, binding management,
     * and authorization operations.
     * </p>
     */
    private OperationAuthorizationEndpointsProperties endpoints = new OperationAuthorizationEndpointsProperties();

    /**
     * Prompt encryption configuration (technical implementation layer).
     * <p>
     * Defines settings for encrypting agent prompts to protect sensitive information,
     * including encryption algorithms and key management.
     * </p>
     */
    private PromptEncryptionProperties promptEncryption = new PromptEncryptionProperties();

    /**
     * Prompt protection configuration (business logic layer).
     * <p>
     * Defines settings for protecting agent prompts through sanitization
     * and encryption before being processed.
     * </p>
     */
    private PromptProtectionProperties promptProtection = new PromptProtectionProperties();

    /**
     * Agent context configuration (runtime information layer).
     * <p>
     * Defines runtime context information for the agent, including client identifier,
     * channel type, language preference, platform, and device fingerprint.
     * </p>
     */
    private AgentContextProperties agentContext = new AgentContextProperties();

    /**
     * OAuth2 client configuration (authentication credentials layer).
     * <p>
     * Defines OAuth2 client credentials for authentication with the authorization server.
     * </p>
     */
    private OAuth2ClientProperties oauth2Client = new OAuth2ClientProperties();

    /**
     * Authorization behavior configuration (authorization policy layer).
     * <p>
     * Defines authorization behavior settings, including user interaction requirements
     * and token expiration time.
     * </p>
     */
    private AuthorizationBehaviorProperties authorization = new AuthorizationBehaviorProperties();

    /**
     * Gets whether the Operation Authorization capability is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the Operation Authorization capability is enabled.
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
    public OperationAuthorizationEndpointsProperties getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the endpoint configurations.
     *
     * @param endpoints the endpoint configurations to set
     */
    public void setEndpoints(OperationAuthorizationEndpointsProperties endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Gets the prompt encryption configuration.
     *
     * @return the prompt encryption configuration
     */
    public PromptEncryptionProperties getPromptEncryption() {
        return promptEncryption;
    }

    /**
     * Sets the prompt encryption configuration.
     *
     * @param promptEncryption the prompt encryption configuration to set
     */
    public void setPromptEncryption(PromptEncryptionProperties promptEncryption) {
        this.promptEncryption = promptEncryption;
    }

    /**
     * Gets the prompt protection configuration.
     *
     * @return the prompt protection configuration
     */
    public PromptProtectionProperties getPromptProtection() {
        return promptProtection;
    }

    /**
     * Sets the prompt protection configuration.
     *
     * @param promptProtection the prompt protection configuration to set
     */
    public void setPromptProtection(PromptProtectionProperties promptProtection) {
        this.promptProtection = promptProtection;
    }

    /**
     * Gets the agent context configuration.
     *
     * @return the agent context configuration
     */
    public AgentContextProperties getAgentContext() {
        return agentContext;
    }

    /**
     * Sets the agent context configuration.
     *
     * @param agentContext the agent context configuration to set
     */
    public void setAgentContext(AgentContextProperties agentContext) {
        this.agentContext = agentContext;
    }

    /**
     * Gets the OAuth2 client configuration.
     *
     * @return the OAuth2 client configuration
     */
    public OAuth2ClientProperties getOauth2Client() {
        return oauth2Client;
    }

    /**
     * Sets the OAuth2 client configuration.
     *
     * @param oauth2Client the OAuth2 client configuration to set
     */
    public void setOauth2Client(OAuth2ClientProperties oauth2Client) {
        this.oauth2Client = oauth2Client;
    }

    /**
     * Gets the authorization behavior configuration.
     *
     * @return the authorization behavior configuration
     */
    public AuthorizationBehaviorProperties getAuthorization() {
        return authorization;
    }

    /**
     * Sets the authorization behavior configuration.
     *
     * @param authorization the authorization behavior configuration to set
     */
    public void setAuthorization(AuthorizationBehaviorProperties authorization) {
        this.authorization = authorization;
    }

    /**
     * Operation Authorization endpoints configuration.
     * <p>
     * This inner class defines all REST API endpoints for the Operation Authorization capability,
     * including policy registry, binding management, and authorization operations.
     * </p>
     */
    public static class OperationAuthorizationEndpointsProperties {

        /**
         * Policy endpoint configurations.
         * <p>
         * Defines REST API endpoints for policy management operations.
         * </p>
         */
        private PolicyEndpointPaths policy = new PolicyEndpointPaths();

        /**
         * Binding endpoint configurations.
         * <p>
         * Defines REST API endpoints for binding management operations.
         * </p>
         */
        private BindingEndpointPaths binding = new BindingEndpointPaths();

        /**
         * Gets the policy endpoint paths.
         *
         * @return the policy endpoint paths
         */
        public PolicyEndpointPaths getPolicy() {
            return policy;
        }

        /**
         * Sets the policy endpoint paths.
         *
         * @param policy the policy endpoint paths to set
         */
        public void setPolicy(PolicyEndpointPaths policy) {
            this.policy = policy;
        }

        /**
         * Gets the binding endpoint paths.
         *
         * @return the binding endpoint paths
         */
        public BindingEndpointPaths getBinding() {
            return binding;
        }

        /**
         * Sets the binding endpoint paths.
         *
         * @param binding the binding endpoint paths to set
         */
        public void setBinding(BindingEndpointPaths binding) {
            this.binding = binding;
        }

        /**
         * Policy endpoint paths configuration.
         * <p>
         * This inner class defines the specific REST API endpoint paths for
         * policy management operations.
         * </p>
         */
        public static class PolicyEndpointPaths {

            /**
             * Policy registry endpoint path.
             * <p>
             * The endpoint for managing authorization policies, including creating,
             * updating, and deleting policies.
             * </p>
             * <p>
             * Default value: {@code /api/v1/policies}
             * </p>
             */
            private String registry = "/api/v1/policies";

            /**
             * Delete policy endpoint path.
             * <p>
             * The endpoint for deleting a specific authorization policy.
             * </p>
             * <p>
             * Default value: {@code /api/v1/policies/{policyId}}
             * </p>
             */
            private String delete = "/api/v1/policies/{policyId}";

            /**
             * Get policy endpoint path.
             * <p>
             * The endpoint for retrieving a specific authorization policy.
             * </p>
             * <p>
             * Default value: {@code /api/v1/policies/{policyId}}
             * </p>
             */
            private String get = "/api/v1/policies/{policyId}";

            /**
             * Gets the policy registry endpoint path.
             *
             * @return the policy registry endpoint path
             */
            public String getRegistry() {
                return registry;
            }

            /**
             * Sets the policy registry endpoint path.
             *
             * @param registry the policy registry endpoint path to set
             */
            public void setRegistry(String registry) {
                this.registry = registry;
            }

            /**
             * Gets the delete policy endpoint path.
             *
             * @return the delete policy endpoint path
             */
            public String getDelete() {
                return delete;
            }

            /**
             * Sets the delete policy endpoint path.
             *
             * @param delete the delete policy endpoint path to set
             */
            public void setDelete(String delete) {
                this.delete = delete;
            }

            /**
             * Gets the get policy endpoint path.
             *
             * @return the get policy endpoint path
             */
            public String getGet() {
                return get;
            }

            /**
             * Sets the get policy endpoint path.
             *
             * @param get the get policy endpoint path to set
             */
            public void setGet(String get) {
                this.get = get;
            }
        }

        /**
         * Binding endpoint paths configuration.
         * <p>
         * This inner class defines the specific REST API endpoint paths for
         * binding management operations.
         * </p>
         */
        public static class BindingEndpointPaths {

            /**
             * Binding registry endpoint path.
             * <p>
             * The endpoint for managing policy bindings, which associate policies
             * with specific users, workloads, or agents.
             * </p>
             * <p>
             * Default value: {@code /api/v1/bindings}
             * </p>
             */
            private String registry = "/api/v1/bindings";

            /**
             * Get binding endpoint path.
             * <p>
             * The endpoint for retrieving a specific policy binding by its instance ID.
             * </p>
             * <p>
             * Default value: {@code /api/v1/bindings/{bindingInstanceId}}
             * </p>
             */
            private String get = "/api/v1/bindings/{bindingInstanceId}";

            /**
             * Delete binding endpoint path.
             * <p>
             * The endpoint for deleting a specific policy binding.
             * </p>
             * <p>
             * Default value: {@code /api/v1/bindings/{bindingInstanceId}}
             * </p>
             */
            private String delete = "/api/v1/bindings/{bindingInstanceId}";

            /**
             * Gets the binding registry endpoint path.
             *
             * @return the binding registry endpoint path
             */
            public String getRegistry() {
                return registry;
            }

            /**
             * Sets the binding registry endpoint path.
             *
             * @param registry the binding registry endpoint path to set
             */
            public void setRegistry(String registry) {
                this.registry = registry;
            }

            /**
             * Gets the get binding endpoint path.
             *
             * @return the get binding endpoint path
             */
            public String getGet() {
                return get;
            }

            /**
             * Sets the get binding endpoint path.
             *
             * @param get the get binding endpoint path to set
             */
            public void setGet(String get) {
                this.get = get;
            }

            /**
             * Gets the delete binding endpoint path.
             *
             * @return the delete binding endpoint path
             */
            public String getDelete() {
                return delete;
            }

            /**
             * Sets the delete binding endpoint path.
             *
             * @param delete the delete binding endpoint path to set
             */
            public void setDelete(String delete) {
                this.delete = delete;
            }
        }
    }

    /**
     * Prompt encryption configuration.
     * <p>
     * This inner class defines settings for encrypting agent prompts to protect
     * sensitive information, including encryption algorithms and key management.
     * </p>
     */
    public static class PromptEncryptionProperties {

        /**
         * Whether prompt encryption is enabled.
         * <p>
         * When enabled, agent prompts will be encrypted using JWE (JSON Web Encryption)
         * before being sent to the authorization server.
         * </p>
         * <p>
         * Default value: {@code false}
         * </p>
         */
        private boolean enabled = false;

        /**
         * Encryption key ID.
         * <p>
         * The identifier of the public key used for encryption. This key ID is used
         * to locate the appropriate public key in the authorization server's JWKS endpoint.
         * </p>
         * <p>
         * Default value: {@code jwe-encryption-key-001}
         * </p>
         */
        private String encryptionKeyId = "jwe-encryption-key-001";

        /**
         * Encryption algorithm.
         * <p>
         * The JWE key encryption algorithm used to encrypt the content encryption key.
         * Common values include {@code RSA-OAEP-256}, {@code RSA-OAEP}, {@code ECDH-ES}.
         * </p>
         * <p>
         * Default value: {@code RSA-OAEP-256}
         * </p>
         */
        private String encryptionAlgorithm = "RSA-OAEP-256";

        /**
         * Content encryption algorithm.
         * <p>
         * The JWE content encryption algorithm used to encrypt the actual prompt content.
         * Common values include {@code A256GCM}, {@code A128GCM}, {@code A256CBC-HS512}.
         * </p>
         * <p>
         * Default value: {@code A256GCM}
         * </p>
         */
        private String contentEncryptionAlgorithm = "A256GCM";

        /**
         * JWKS consumer name for fetching encryption public key.
         * <p>
         * The name of the JWKS consumer defined in {@code open-agent-auth.infrastructures.jwks.consumers}
         * that provides the public keys used for encryption. This allows reusing existing JWKS
         * configurations instead of duplicating the URL.
         * </p>
         * <p>
         * Example: If you have configured {@code open-agent-auth.infrastructures.jwks.consumers.authorization-server},
         * you can set this value to {@code authorization-server}.
         * </p>
         * <p>
         * When this property is set, the application will automatically fetch the JWKS endpoint
         * URL from the corresponding consumer configuration.
         * </p>
         */
        private String jwksConsumer;

        /**
         * Gets whether prompt encryption is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether prompt encryption is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the encryption key ID.
         *
         * @return the encryption key ID
         */
        public String getEncryptionKeyId() {
            return encryptionKeyId;
        }

        /**
         * Sets the encryption key ID.
         *
         * @param encryptionKeyId the encryption key ID to set
         */
        public void setEncryptionKeyId(String encryptionKeyId) {
            this.encryptionKeyId = encryptionKeyId;
        }

        /**
         * Gets the encryption algorithm.
         *
         * @return the encryption algorithm
         */
        public String getEncryptionAlgorithm() {
            return encryptionAlgorithm;
        }

        /**
         * Sets the encryption algorithm.
         *
         * @param encryptionAlgorithm the encryption algorithm to set
         */
        public void setEncryptionAlgorithm(String encryptionAlgorithm) {
            this.encryptionAlgorithm = encryptionAlgorithm;
        }

        /**
         * Gets the content encryption algorithm.
         *
         * @return the content encryption algorithm
         */
        public String getContentEncryptionAlgorithm() {
            return contentEncryptionAlgorithm;
        }

        /**
         * Sets the content encryption algorithm.
         *
         * @param contentEncryptionAlgorithm the content encryption algorithm to set
         */
        public void setContentEncryptionAlgorithm(String contentEncryptionAlgorithm) {
            this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        }

        /**
         * Gets the JWKS consumer name.
         *
         * @return the JWKS consumer name
         */
        public String getJwksConsumer() {
            return jwksConsumer;
        }

        /**
         * Sets the JWKS consumer name.
         *
         * @param jwksConsumer the JWKS consumer name to set
         */
        public void setJwksConsumer(String jwksConsumer) {
            this.jwksConsumer = jwksConsumer;
        }
    }

    /**
     * Prompt protection configuration (business logic layer).
     * <p>
     * Defines settings for protecting agent prompts through sanitization
     * and encryption before being processed.
     * </p>
     */
    public static class PromptProtectionProperties {

        /**
         * Whether prompt protection is enabled.
         * <p>
         * When enabled, agent prompts will be protected through sanitization
         * and encryption before being processed.
         * </p>
         * <p>
         * Default value: {@code true}
         * </p>
         */
        private boolean enabled = true;

        /**
         * Whether encryption is enabled.
         * <p>
         * When enabled, agent prompts will be encrypted before being sent to
         * the authorization server.
         * </p>
         * <p>
         * Default value: {@code true}
         * </p>
         */
        private boolean encryptionEnabled = true;

        /**
         * Sanitization level.
         * <p>
         * The level of sanitization applied to agent prompts before authorization.
         * Common values include {@code LOW}, {@code MEDIUM}, {@code HIGH}.
         * </p>
         * <p>
         * Default value: {@code MEDIUM}
         * </p>
         */
        private String sanitizationLevel = "MEDIUM";

        /**
         * Gets whether prompt protection is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether prompt protection is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets whether encryption is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEncryptionEnabled() {
            return encryptionEnabled;
        }

        /**
         * Sets whether encryption is enabled.
         *
         * @param encryptionEnabled {@code true} to enable, {@code false} to disable
         */
        public void setEncryptionEnabled(boolean encryptionEnabled) {
            this.encryptionEnabled = encryptionEnabled;
        }

        /**
         * Gets the sanitization level.
         *
         * @return the sanitization level
         */
        public String getSanitizationLevel() {
            return sanitizationLevel;
        }

        /**
         * Sets the sanitization level.
         *
         * @param sanitizationLevel the sanitization level to set
         */
        public void setSanitizationLevel(String sanitizationLevel) {
            this.sanitizationLevel = sanitizationLevel;
        }
    }

    /**
     * Agent context configuration (runtime information layer).
     * <p>
     * Defines default runtime context information for the agent, including client identifier,
     * channel type, language preference, platform, and device fingerprint.
     * </p>
     * <p>
     * These values serve as defaults and can be overridden at runtime when making
     * authorization requests. Runtime values take precedence over these defaults.
     * </p>
     */
    public static class AgentContextProperties {

        /**
         * Default agent client identifier.
         * <p>
         * A user-friendly identifier for this agent client, used for logging and
         * identification purposes. This value can be overridden at runtime.
         * </p>
         * <p>
         * Default value: {@code sample-agent-client}
         * </p>
         */
        private String defaultClient = "sample-agent-client";

        /**
         * Default channel type.
         * <p>
         * The type of channel through which the agent is operating, such as
         * {@code web}, {@code mobile}, {@code desktop}, etc. This value can be overridden at runtime.
         * </p>
         * <p>
         * Default value: {@code web}
         * </p>
         */
        private String defaultChannel = "web";

        /**
         * Default language preference.
         * <p>
         * The preferred language for authorization prompts and messages,
         * such as {@code zh-CN}, {@code en-US}, {@code ja-JP}, etc. This value can be overridden at runtime.
         * </p>
         * <p>
         * Default value: {@code zh-CN}
         * </p>
         */
        private String defaultLanguage = "zh-CN";

        /**
         * Default platform identifier.
         * <p>
         * The platform on which the agent is running, such as {@code macOS},
         * {@code Windows}, {@code Linux}, {@code iOS}, {@code Android}, etc. This value can be overridden at runtime.
         * </p>
         * <p>
         * Default value: {@code sample-agent.platform}
         * </p>
         */
        private String defaultPlatform = "sample-agent.platform";

        /**
         * Default device fingerprint for tracking.
         * <p>
         * A unique identifier for the device on which the agent is running,
         * used for security and tracking purposes. This value can be overridden at runtime.
         * </p>
         * <p>
         * Default value: {@code sample-device}
         * </p>
         */
        private String defaultDeviceFingerprint = "sample-device";

        /**
         * Gets the default agent client identifier.
         *
         * @return the default agent client identifier
         */
        public String getDefaultClient() {
            return defaultClient;
        }

        /**
         * Sets the default agent client identifier.
         *
         * @param defaultClient the default agent client identifier to set
         */
        public void setDefaultClient(String defaultClient) {
            this.defaultClient = defaultClient;
        }

        /**
         * Gets the default channel type.
         *
         * @return the default channel type
         */
        public String getDefaultChannel() {
            return defaultChannel;
        }

        /**
         * Sets the default channel type.
         *
         * @param defaultChannel the default channel type to set
         */
        public void setDefaultChannel(String defaultChannel) {
            this.defaultChannel = defaultChannel;
        }

        /**
         * Gets the default language preference.
         *
         * @return the default language preference
         */
        public String getDefaultLanguage() {
            return defaultLanguage;
        }

        /**
         * Sets the default language preference.
         *
         * @param defaultLanguage the default language preference to set
         */
        public void setDefaultLanguage(String defaultLanguage) {
            this.defaultLanguage = defaultLanguage;
        }

        /**
         * Gets the default platform identifier.
         *
         * @return the default platform identifier
         */
        public String getDefaultPlatform() {
            return defaultPlatform;
        }

        /**
         * Sets the default platform identifier.
         *
         * @param defaultPlatform the default platform identifier to set
         */
        public void setDefaultPlatform(String defaultPlatform) {
            this.defaultPlatform = defaultPlatform;
        }

        /**
         * Gets the default device fingerprint.
         *
         * @return the default device fingerprint
         */
        public String getDefaultDeviceFingerprint() {
            return defaultDeviceFingerprint;
        }

        /**
         * Sets the default device fingerprint.
         *
         * @param defaultDeviceFingerprint the default device fingerprint to set
         */
        public void setDefaultDeviceFingerprint(String defaultDeviceFingerprint) {
            this.defaultDeviceFingerprint = defaultDeviceFingerprint;
        }
    }

    /**
     * OAuth2 client configuration (authentication credentials layer).
     * <p>
     * Defines OAuth2 client credentials for authentication with the authorization server.
     * </p>
     */
    public static class OAuth2ClientProperties {
        /**
         * OAuth 2.0 client ID for this agent.
         * <p>
         * The unique identifier for this agent as an OAuth 2.0 client with the
         * authorization server.
         * </p>
         */
        private String clientId;

        /**
         * OAuth 2.0 client secret for this agent.
         * <p>
         * The secret used to authenticate this agent with the authorization server.
         * </p>
         */
        private String clientSecret;

        /**
         * OAuth callbacks redirect URI.
         * <p>
         * The URI where the authorization server will redirect the user after
         * successful authorization for operation authorization requests.
         * </p>
         */
        private String oauthCallbacksRedirectUri;

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
         * Gets the OAuth callbacks redirect URI.
         *
         * @return the OAuth callbacks redirect URI
         */
        public String getOauthCallbacksRedirectUri() {
            return oauthCallbacksRedirectUri;
        }

        /**
         * Sets the OAuth callbacks redirect URI.
         *
         * @param oauthCallbacksRedirectUri the OAuth callbacks redirect URI to set
         */
        public void setOauthCallbacksRedirectUri(String oauthCallbacksRedirectUri) {
            this.oauthCallbacksRedirectUri = oauthCallbacksRedirectUri;
        }
    }

    /**
     * Authorization behavior configuration (authorization policy layer).
     * <p>
     * Defines authorization behavior settings, including user interaction requirements
     * and token expiration time.
     * </p>
     */
    public static class AuthorizationBehaviorProperties {

        /**
         * Whether user interaction is required for sensitive operations.
         * <p>
         * When enabled, the user will be required to explicitly approve sensitive
         * operations before they are executed.
         * </p>
         * <p>
         * Default value: {@code false}
         * </p>
         */
        private boolean requireUserInteraction = false;

        /**
         * Expiration time in seconds for Agent Operation Authorization tokens.
         * <p>
         * The lifetime of operation authorization tokens issued by the authorization server.
         * </p>
         * <p>
         * Default value: {@code 3600} (1 hour)
         * </p>
         */
        private int expirationSeconds = 3600;

        /**
         * Gets whether user interaction is required.
         *
         * @return {@code true} if required, {@code false} otherwise
         */
        public boolean isRequireUserInteraction() {
            return requireUserInteraction;
        }

        /**
         * Sets whether user interaction is required.
         *
         * @param requireUserInteraction {@code true} to require, {@code false} to not require
         */
        public void setRequireUserInteraction(boolean requireUserInteraction) {
            this.requireUserInteraction = requireUserInteraction;
        }

        /**
         * Gets the expiration time in seconds.
         *
         * @return the expiration time in seconds
         */
        public int getExpirationSeconds() {
            return expirationSeconds;
        }

        /**
         * Sets the expiration time in seconds.
         *
         * @param expirationSeconds the expiration time in seconds to set
         */
        public void setExpirationSeconds(int expirationSeconds) {
            this.expirationSeconds = expirationSeconds;
        }
    }
}