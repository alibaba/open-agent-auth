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
package com.alibaba.openagentauth.framework.executor.config;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.executor.strategy.impl.DefaultDeviceFingerprintStrategy;
import com.alibaba.openagentauth.framework.executor.strategy.impl.DefaultStateGenerationStrategy;
import com.alibaba.openagentauth.framework.executor.strategy.DeviceFingerprintStrategy;
import com.alibaba.openagentauth.framework.executor.strategy.StateGenerationStrategy;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationRequestStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationRequestStorage;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * Configuration for AgentAapExecutor.
 * <p>
 * This class provides a centralized configuration mechanism for the Agent AAP (Agent Operation Authorization Protocol) executor.
 * It encapsulates all configurable parameters required for OIDC-based authorization flows, including client credentials,
 * OAuth callback settings, and strategy implementations for device fingerprinting and state generation.
 * </p>
 * <p>
 * Instances should be created using the {@link Builder} pattern to ensure all required parameters are validated
 * before the configuration is used.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentAapExecutorConfig {

    /**
     * The OAuth 2.0 client identifier used for audience validation in OIDC flows.
     * This value is used as the {@code client_id} parameter in authorization requests.
     */
    private final String clientId;
    
    /**
     * The OAuth 2.0 redirect URI where the authorization server sends the user after authorization.
     * This URI must be pre-registered with the authorization server and must use HTTPS.
     */
    private final String redirectUri;
    
    /**
     * The channel through which the authorization request is made (e.g., "web", "mobile", "desktop").
     * This value may be used for analytics, logging, or policy enforcement.
     */
    private final String channel;
    
    /**
     * The language code for the authorization flow (e.g., "en-US", "zh-CN").
     * This determines the language of consent screens and error messages.
     */
    private final String language;
    
    /**
     * The platform identifier for the client application (e.g., "personal-agent.myassistant.example").
     * This represents the logical service namespace or platform where the agent operates.
     */
    private final String platform;
    
    /**
     * The identifier for the agent client instance.
     * Combined with device fingerprint, this uniquely identifies a specific client instance.
     */
    private final String agentClient;

    /**
     * Issuer URL for the agent.
     */
    private final String issuer;

    /**
     * Device fingerprint for this executor instance.
     */
    private final String deviceFingerprint;

    /**
     * Strategy for generating device fingerprints.
     * Implementations should provide stable, privacy-preserving identifiers derived from hardware and app properties.
     */
    private final DeviceFingerprintStrategy deviceFingerprintStrategy;

    /**
     * Strategy for generating OAuth state parameters.
     * Implementations should provide cryptographically secure, unguessable values to prevent CSRF attacks.
     */
    private final StateGenerationStrategy stateGenerationStrategy;

    /**
     * The expiration time for PAR-JWT (Pushed Authorization Request JWT) in seconds.
     * After this time, the authorization request will be rejected by the authorization server.
     */
    private final Integer expirationSeconds;

    /**
     * Whether prompt protection is enabled.
     * <p>
     * When set to true, all prompts will be processed through the three-layer
     * protection mechanism. When set to false, prompts are processed without protection.
     * </p>
     */
    private final Boolean promptProtectionEnabled;

    /**
     * The sanitization level for prompt protection.
     */
    private final String sanitizationLevel;

    /**
     * Whether to require user interaction for high-severity sensitive information.
     */
    private final Boolean requireUserInteraction;

    /**
     * Whether encryption is enabled for sensitive data.
     * <p>
     * When set to true, sensitive information detected in prompts will be encrypted
     * before storage or transmission. This provides an additional layer of security
     * beyond sanitization.
     * </p>
     */
    private final Boolean encryptionEnabled;

    /**
     * Storage for OAuth2 authorization requests keyed by opaque state values.
     * <p>
     * This storage enables the RFC 6749-compliant opaque state pattern where
     * flow type metadata (e.g., AGENT_OPERATION_AUTH) is stored server-side
     * rather than encoded in the state parameter itself.
     * </p>
     */
    private final OAuth2AuthorizationRequestStorage authorizationRequestStorage;

    private AgentAapExecutorConfig(Builder builder) {
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.channel = builder.channel;
        this.language = builder.language;
        this.platform = builder.platform;
        this.agentClient = builder.agentClient;
        this.issuer = builder.issuer;
        this.deviceFingerprint = builder.deviceFingerprint;
        this.deviceFingerprintStrategy = builder.deviceFingerprintStrategy;
        this.stateGenerationStrategy = builder.stateGenerationStrategy;
        this.expirationSeconds = builder.expirationSeconds;
        this.promptProtectionEnabled = builder.promptProtectionEnabled;
        this.sanitizationLevel = builder.sanitizationLevel;
        this.requireUserInteraction = builder.requireUserInteraction;
        this.encryptionEnabled = builder.encryptionEnabled;
        this.authorizationRequestStorage = builder.authorizationRequestStorage;
    }
    
    /**
     * Returns the OAuth 2.0 client identifier.
     *
     * @return the client ID
     */
    public String getClientId() {
        return clientId;
    }
    
    /**
     * Returns the OAuth 2.0 redirect URI.
     *
     * @return the redirect URI
     */
    public String getRedirectUri() {
        return redirectUri;
    }
    
    /**
     * Returns the channel identifier.
     *
     * @return the channel
     */
    public String getChannel() {
        return channel;
    }
    
    /**
     * Returns the language code.
     *
     * @return the language code
     */
    public String getLanguage() {
        return language;
    }
    
    /**
     * Returns the platform identifier.
     *
     * @return the platform identifier
     */
    public String getPlatform() {
        return platform;
    }
    
    /**
     * Returns the agent client identifier.
     *
     * @return the agent client identifier
     */
    public String getAgentClient() {
        return agentClient;
    }

    /**
     * Gets the issuer URL for the agent.
     *
     * @return the issuer URL, or null if not configured
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the device fingerprint from configuration.
     * <p>
     * This value is used when deviceFingerprint is not provided in the request.
     * For multi-device deployments, leave this field null and
     * provide device-specific fingerprints via request.
     * </p>
     *
     * @return the device fingerprint, or null if not configured
     */
    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    /**
     * Returns the state parameter generation strategy.
     *
     * @return the state generation strategy
     */
    public StateGenerationStrategy getStateGenerationStrategy() {
        return stateGenerationStrategy;
    }

    /**
     * Returns the device fingerprint generation strategy.
     *
     * @return the device fingerprint strategy
     */
    public DeviceFingerprintStrategy getDeviceFingerprintStrategy() {
        return deviceFingerprintStrategy;
    }
    
    /**
     * Returns the PAR-JWT expiration time in seconds.
     *
     * @return the expiration time in seconds
     */
    public Integer getExpirationSeconds() {
        return expirationSeconds;
    }

    /**
     * Returns whether prompt protection is enabled.
     *
     * @return true if prompt protection is enabled, false otherwise
     */
    public Boolean getPromptProtectionEnabled() {
        return promptProtectionEnabled;
    }

    /**
     * Returns the sanitization level for prompt protection.
     *
     * @return the sanitization level, or null if not configured
     */
    public String getSanitizationLevel() {
        return sanitizationLevel;
    }

    /**
     * Returns whether user interaction is required for high-severity sensitive information.
     *
     * @return true if user interaction is required, false otherwise
     */
    public Boolean getRequireUserInteraction() {
        return requireUserInteraction;
    }

    /**
     * Returns whether encryption is enabled for sensitive data.
     *
     * @return true if encryption is enabled, false otherwise
     */
    public Boolean getEncryptionEnabled() {
        return encryptionEnabled;
    }

    /**
     * Returns the authorization request storage.
     *
     * @return the authorization request storage
     */
    public OAuth2AuthorizationRequestStorage getAuthorizationRequestStorage() {
        return authorizationRequestStorage;
    }

    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for creating {@link AgentAapExecutorConfig} instances.
     * <p>
     * This builder provides a fluent API for constructing configuration objects with validated parameters.
     * All required fields must be set before calling {@link #build()}.
     * </p>
     * <p>
     * Example usage:
     * <pre>{@code
     * AgentAapExecutorConfig config = AgentAapExecutorConfig.builder()
     *     .clientId("my-agent")
     *     .redirectUri("https://example.com/callback")
     *     .platform("personal-agent.example.com")
     *     .agentClient("mobile-app-v1")
     *     .build();
     * }</pre>
     * </p>
     */
    public static class Builder {
        private String clientId = "default-agent";
        private String redirectUri;
        private String channel = "web";
        private String language = "en-US";
        private String platform;
        private String agentClient;
        private String issuer;
        private String deviceFingerprint;
        private DeviceFingerprintStrategy deviceFingerprintStrategy = new DefaultDeviceFingerprintStrategy();
        private StateGenerationStrategy stateGenerationStrategy = new DefaultStateGenerationStrategy();
        private Integer expirationSeconds = 3600;
        private Boolean promptProtectionEnabled;
        private String sanitizationLevel;
        private Boolean requireUserInteraction;
        private Boolean encryptionEnabled;
        private OAuth2AuthorizationRequestStorage authorizationRequestStorage = new InMemoryOAuth2AuthorizationRequestStorage();

        /**
         * Sets the OAuth 2.0 client identifier.
         *
         * @param clientId the client ID (required)
         * @return this builder instance
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }
        
        /**
         * Sets the OAuth 2.0 redirect URI.
         *
         * @param redirectUri the redirect URI (required)
         * @return this builder instance
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        
        /**
         * Sets the channel identifier.
         *
         * @param channel the channel (optional, defaults to "web")
         * @return this builder instance
         */
        public Builder channel(String channel) {
            this.channel = channel;
            return this;
        }
        
        /**
         * Sets the language code.
         *
         * @param language the language code (optional, defaults to "en-US")
         * @return this builder instance
         */
        public Builder language(String language) {
            this.language = language;
            return this;
        }
        
        /**
         * Sets the platform identifier.
         *
         * @param platform the platform identifier (required)
         * @return this builder instance
         */
        public Builder platform(String platform) {
            this.platform = platform;
            return this;
        }
        
        /**
         * Sets the agent client identifier.
         *
         * @param agentClient the agent client identifier (required)
         * @return this builder instance
         */
        public Builder agentClient(String agentClient) {
            this.agentClient = agentClient;
            return this;
        }

        /**
         * Sets the issuer URL for the agent.
         *
         * @param issuer the issuer URL (required)
         * @return this builder instance
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }
        
        /**
         * Sets the device fingerprint for this executor instance.
         *
         * @param deviceFingerprint the device fingerprint
         * @return this builder instance
         */
        public Builder deviceFingerprint(String deviceFingerprint) {
            this.deviceFingerprint = deviceFingerprint;
            return this;
        }

        /**
         * Sets the device fingerprint generation strategy.
         *
         * @param strategy the device fingerprint strategy (required)
         * @return this builder instance
         * @throws NullPointerException if strategy is null
         */
        public Builder deviceFingerprintStrategy(
                DeviceFingerprintStrategy strategy) {
            this.deviceFingerprintStrategy = Objects.requireNonNull(strategy, "DeviceFingerprintStrategy cannot be null");
            return this;
        }

        /**
         * Sets the state parameter generation strategy.
         *
         * @param strategy the state generation strategy (required)
         * @return this builder instance
         * @throws NullPointerException if strategy is null
         */
        public Builder stateGenerationStrategy(
                StateGenerationStrategy strategy) {
            this.stateGenerationStrategy = Objects.requireNonNull(strategy, "StateGenerationStrategy cannot be null");
            return this;
        }
        
        /**
         * Sets the PAR-JWT expiration time.
         *
         * @param expirationSeconds the expiration time in seconds (optional, defaults to 3600)
         * @return this builder instance
         */
        public Builder expirationSeconds(Integer expirationSeconds) {
            this.expirationSeconds = expirationSeconds;
            return this;
        }

        /**
         * Sets whether prompt protection is enabled.
         *
         * @param enabled true to enable prompt protection, false otherwise
         * @return this builder instance
         */
        public Builder promptProtectionEnabled(Boolean enabled) {
            this.promptProtectionEnabled = enabled;
            return this;
        }

        /**
         * Sets the sanitization level for prompt protection.
         *
         * @param sanitizationLevel the sanitization level
         * @return this builder instance
         */
        public Builder sanitizationLevel(String sanitizationLevel) {
            this.sanitizationLevel = sanitizationLevel;
            return this;
        }

        /**
         * Sets whether user interaction is required for high-severity sensitive information.
         *
         * @param requireUserInteraction true to require user interaction, false otherwise
         * @return this builder instance
         */
        public Builder requireUserInteraction(Boolean requireUserInteraction) {
            this.requireUserInteraction = requireUserInteraction;
            return this;
        }

        /**
         * Sets whether encryption is enabled for sensitive data.
         *
         * @param encryptionEnabled true to enable encryption, false otherwise
         * @return this builder instance
         */
        public Builder encryptionEnabled(Boolean encryptionEnabled) {
            this.encryptionEnabled = encryptionEnabled;
            return this;
        }

        /**
         * Sets the authorization request storage.
         * <p>
         * For distributed deployments, provide a shared storage implementation
         * (e.g., Redis-backed) to ensure state can be resolved across instances.
         * </p>
         *
         * @param storage the authorization request storage
         * @return this builder instance
         * @throws NullPointerException if storage is null
         */
        public Builder authorizationRequestStorage(OAuth2AuthorizationRequestStorage storage) {
            this.authorizationRequestStorage = Objects.requireNonNull(storage, "OAuth2AuthorizationRequestStorage cannot be null");
            return this;
        }

        /**
         * Builds and returns a new {@link AgentAapExecutorConfig} instance.
         * <p>
         * This method validates all required fields before creating the configuration.
         * </p>
         *
         * @return a new configuration instance
         * @throws IllegalArgumentException if any required field is null or empty
         */
        public AgentAapExecutorConfig build() {
            validate();
            return new AgentAapExecutorConfig(this);
        }

        /**
         * Validates that all required configuration parameters are set.
         *
         * @throws IllegalArgumentException if any required parameter is null or empty
         */
        private void validate() {
            ValidationUtils.validateNotEmpty(clientId, "clientId");
            ValidationUtils.validateNotEmpty(redirectUri, "redirectUri");
            ValidationUtils.validateNotEmpty(channel, "channel");
            ValidationUtils.validateNotEmpty(language, "language");
            ValidationUtils.validateNotEmpty(platform, "platform");
            ValidationUtils.validateNotEmpty(agentClient, "agentClient");
            ValidationUtils.validateNotEmpty(issuer, "issuer");
            ValidationUtils.validateNotNull(deviceFingerprintStrategy, "deviceFingerprintStrategy");
            ValidationUtils.validateNotNull(stateGenerationStrategy, "stateGenerationStrategy");
            ValidationUtils.validateNotNull(expirationSeconds, "expirationSeconds");
            ValidationUtils.validateNotNull(promptProtectionEnabled, "promptProtectionEnabled");
            ValidationUtils.validateNotNull(sanitizationLevel, "sanitizationLevel");
            ValidationUtils.validateNotNull(requireUserInteraction, "requireUserInteraction");
            ValidationUtils.validateNotNull(encryptionEnabled, "encryptionEnabled");
        }
    }
}