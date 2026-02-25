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
package com.alibaba.openagentauth.spring.autoconfigure.core;

import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.crypto.key.resolve.JwksConsumerKeyResolver;
import com.alibaba.openagentauth.core.crypto.key.resolve.KeyResolver;

import com.alibaba.openagentauth.core.crypto.key.resolve.LocalKeyResolver;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants;
import com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.web.controller.JwksController;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Core auto-configuration for Open Agent Auth framework.
 * <p>
 * This configuration provides the fundamental infrastructure beans that are shared
 * across all roles, including:
 * </p>
 * <ul>
 *   <li>KeyManager: Centralized key management for signing and verification</li>
 *   <li>TrustDomain: Trust domain configuration for workload identity</li>
 *   <li>WitValidator: WIT validation for verifying workload identity tokens</li>
 *   <li>TokenService: Token generation and validation capabilities</li>
 * </ul>
 * <p>
 * This configuration is loaded first and provides the foundation for all role-specific
 * configurations. It is always enabled when the framework is enabled.
 * </p>
 *
 * @since 1.0
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenAgentAuthProperties.class)
@ConditionalOnProperty(prefix = "open-agent-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CoreAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(CoreAutoConfiguration.class);

    private static final String DEFAULT_WIT_SIGNING_KEY_ID = "wit-signing-key";
    private static final KeyAlgorithm DEFAULT_WIT_SIGNING_ALGORITHM = KeyAlgorithm.ES256;

    /**
     * Default constructor.
     */
    public CoreAutoConfiguration() {
        logger.info("CoreAutoConfiguration initialized");
    }

    /**
     * Creates the KeyStore bean if not already defined.
     * <p>
     * The KeyStore provides the underlying storage mechanism for cryptographic keys.
     * Developers can override this bean to provide custom storage implementations
     * (e.g., file-based, database-backed, or external KMS).
     * </p>
     *
     * @return the KeyStore bean
     */
    @Bean
    @ConditionalOnMissingBean
    public KeyStore keyStore() {
        logger.info("Creating InMemoryKeyStore bean");
        return new InMemoryKeyStore();
    }

    /**
     * Creates the JwksConsumerKeyResolver bean if not already defined.
     * <p>
     * The JwksConsumerKeyResolver resolves keys from remote JWKS endpoints.
     * It builds the consumer-to-endpoint mapping from the configured JWKS consumers.
     * </p>
     *
     * @param properties the configuration properties
     * @return the JwksConsumerKeyResolver bean
     */
    @Bean
    @ConditionalOnMissingBean
    public JwksConsumerKeyResolver jwksConsumerKeyResolver(OpenAgentAuthProperties properties) {
        Map<String, String> consumerEndpoints = buildJwksConsumerEndpoints(properties);
        logger.info("Creating JwksConsumerKeyResolver bean with {} consumer(s)", consumerEndpoints.size());
        return new JwksConsumerKeyResolver(consumerEndpoints);
    }

    /**
     * Creates the KeyManager bean if not already defined.
     * <p>
     * The KeyManager provides centralized key management for all cryptographic operations,
     * including key generation, storage, retrieval, and unified key resolution via the
     * {@link KeyResolver} chain.
     * </p>
     * <p>
     * This enhanced KeyManager accepts a list of external {@link KeyResolver} implementations
     * (e.g., {@link JwksConsumerKeyResolver}) and a map of {@link KeyDefinition} objects
     * derived from the configuration properties. A {@link LocalKeyResolver} is automatically
     * created internally by the {@link DefaultKeyManager} to avoid circular dependencies.
     * </p>
     *
     * @param keyStore the key store
     * @param keyResolvers the list of registered key resolvers
     * @param properties the configuration properties
     * @return the KeyManager bean
     */
    @Bean
    @ConditionalOnMissingBean
    public KeyManager keyManager(KeyStore keyStore, List<KeyResolver> keyResolvers,
                                 OpenAgentAuthProperties properties) {
        Map<String, KeyDefinition> keyDefinitions = buildKeyDefinitions(properties);
        logger.info("Creating KeyManager bean with {} resolver(s) and {} key definition(s)",
                keyResolvers.size(), keyDefinitions.size());
        return new DefaultKeyManager(keyStore, keyResolvers, keyDefinitions);
    }

    /**
     * Creates the TrustDomain bean if not already defined.
     * <p>
     * The TrustDomain represents the trust boundary for workload identity management.
     * It is used to validate that WITs are issued within the expected trust domain.
     * </p>
     *
     * @param properties the configuration properties
     * @return the TrustDomain bean
     * @throws IllegalStateException if trust domain is not configured
     */
    @Bean
    @ConditionalOnMissingBean
    public TrustDomain trustDomain(OpenAgentAuthProperties properties) {
        String trustDomain = properties.getInfrastructures().getTrustDomain();
        if (ValidationUtils.isNullOrEmpty(trustDomain)) {
            throw new IllegalStateException(
                "Trust domain is not configured. Please set 'open-agent-auth.infrastructure.trust-domain' in your configuration. " +
                "This is a required configuration for workload identity management."
            );
        }
        logger.info("Creating TrustDomain bean: {}", trustDomain);
        return new TrustDomain(trustDomain);
    }

    /**
     * Creates the TokenService bean if not already defined.
     * <p>
     * The TokenService provides token generation and validation capabilities for WITs.
     * This bean is shared across all roles and provides the core token functionality.
     * </p>
     * <p>
     * The WIT signing key configuration is read from the {@code key-management.keys}
     * properties. The method searches for a key definition whose name contains "wit-signing"
     * and has a local provider. If no matching configuration is found, it falls back to
     * the default key ID "wit-signing-key" with ES256 algorithm for backward compatibility.
     * </p>
     *
     * @param keyManager the key manager
     * @param trustDomain the trust domain
     * @param properties the configuration properties
     * @return the TokenService bean
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenService tokenService(KeyManager keyManager, TrustDomain trustDomain,
                                     OpenAgentAuthProperties properties) {
        logger.info("Creating TokenService bean");

        // Resolve WIT signing key configuration from properties
        String keyId = DEFAULT_WIT_SIGNING_KEY_ID;
        KeyAlgorithm keyAlgorithm = DEFAULT_WIT_SIGNING_ALGORITHM;

        InfrastructureProperties infra = properties.getInfrastructures();
        if (infra != null && infra.getKeyManagement() != null && infra.getKeyManagement().getKeys() != null) {
            for (Map.Entry<String, KeyDefinitionProperties> entry : infra.getKeyManagement().getKeys().entrySet()) {
                String keyName = entry.getKey();
                KeyDefinitionProperties keyProps = entry.getValue();

                if (keyName.contains(ConfigConstants.KEY_WIT_SIGNING) && keyProps.getProvider() != null) {
                    keyId = keyProps.getKeyId();
                    if (keyProps.getAlgorithm() != null && !keyProps.getAlgorithm().isBlank()) {
                        try {
                            keyAlgorithm = KeyAlgorithm.fromValue(keyProps.getAlgorithm());
                        } catch (IllegalArgumentException e) {
                            logger.warn("Unknown algorithm '{}' for WIT signing key '{}', using default {}",
                                    keyProps.getAlgorithm(), keyName, DEFAULT_WIT_SIGNING_ALGORITHM);
                        }
                    }
                    logger.info("Found WIT signing key configuration: name={}, keyId={}, algorithm={}",
                            keyName, keyId, keyAlgorithm);
                    break;
                }
            }
        }

        logger.info("Getting or generating WIT signing key with ID: {}, algorithm: {}", keyId, keyAlgorithm);

        JWK signingJWK;
        try {
            signingJWK = (JWK) keyManager.getOrGenerateKey(keyId, keyAlgorithm);
            logger.info("WIT signing key ready. Key ID: {}", keyId);
        } catch (Exception e) {
            logger.error("Failed to get or generate signing key: {}", e.getMessage(), e);
            throw new IllegalStateException("Failed to initialize WIT signing key", e);
        }

        JWSAlgorithm jwsAlgorithm = keyAlgorithm.getJwsAlgorithm();
        return new TokenService(signingJWK, trustDomain, jwsAlgorithm);
    }

    /**
     * Builds the mapping from JWKS consumer name to its endpoint URL.
     *
     * @param properties the configuration properties
     * @return the consumer-to-endpoint mapping
     */
    private Map<String, String> buildJwksConsumerEndpoints(OpenAgentAuthProperties properties) {
        Map<String, String> endpoints = new HashMap<>();

        InfrastructureProperties infra = properties.getInfrastructures();
        if (infra == null) {
            return endpoints;
        }

        JwksInfrastructureProperties jwksProps = infra.getJwks();
        if (jwksProps == null || jwksProps.getConsumers() == null) {
            return endpoints;
        }

        for (Map.Entry<String, JwksConsumerProperties> entry : jwksProps.getConsumers().entrySet()) {
            JwksConsumerProperties consumer = entry.getValue();
            if (consumer != null && consumer.isEnabled()) {
                String jwksEndpoint = consumer.getJwksEndpoint();
                if (jwksEndpoint != null && !jwksEndpoint.isBlank()) {
                    endpoints.put(entry.getKey(), jwksEndpoint);
                }
            }
        }

        return endpoints;
    }

    /**
     * Creates the JwksController bean if the JWKS provider is enabled.
     * <p>
     * The JWKS provider enabled flag may be set either explicitly in YAML or
     * automatically by the role-aware inference logic (e.g., for roles like
     * {@code authorization-server}, {@code agent-idp}, etc.). Since the inference
     * runs during {@code @ConfigurationProperties} binding (via
     * {@link OpenAgentAuthProperties#afterPropertiesSet()}), the Java object property
     * is already up-to-date when this {@code @Bean} method is evaluated.
     * </p>
     * <p>
     * This replaces the previous {@code @ConditionalOnExpression} approach on
     * {@link JwksController}, which checked the Spring Environment property and
     * could not see values set by the inference logic.
     * </p>
     *
     * @param properties the configuration properties
     * @param keyManager the key manager for retrieving active keys
     * @return the JwksController bean, or {@code null} if JWKS provider is disabled
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    public JwksController jwksController(OpenAgentAuthProperties properties, KeyManager keyManager) {
        boolean jwksProviderEnabled = properties.getInfrastructures().getJwks().getProvider().isEnabled();
        if (!jwksProviderEnabled) {
            logger.info("JWKS provider is disabled, skipping JwksController registration");
            return null;
        }
        logger.info("Creating JwksController bean (JWKS provider enabled)");
        return new JwksController(properties, keyManager);
    }

    /**
     * Builds the mapping from key name to {@link KeyDefinition} from configuration properties.
     * <p>
     * Each key definition in the configuration is converted to a {@link KeyDefinition}
     * value object that captures the key's identity, algorithm, provider, and JWKS consumer.
     * </p>
     *
     * @param properties the configuration properties
     * @return the key name to key definition mapping
     */
    private Map<String, KeyDefinition> buildKeyDefinitions(OpenAgentAuthProperties properties) {
        Map<String, KeyDefinition> definitions = new HashMap<>();

        InfrastructureProperties infra = properties.getInfrastructures();
        if (infra == null || infra.getKeyManagement() == null || infra.getKeyManagement().getKeys() == null) {
            return definitions;
        }

        for (Map.Entry<String, KeyDefinitionProperties> entry : infra.getKeyManagement().getKeys().entrySet()) {
            String keyName = entry.getKey();
            KeyDefinitionProperties keyProps = entry.getValue();

            if (keyProps == null || keyProps.getKeyId() == null) {
                continue;
            }

            KeyDefinition.Builder builder = KeyDefinition.builder()
                    .keyId(keyProps.getKeyId())
                    .provider(keyProps.getProvider())
                    .jwksConsumer(keyProps.getJwksConsumer());

            if (keyProps.getAlgorithm() != null && !keyProps.getAlgorithm().isBlank()) {
                try {
                    builder.algorithm(KeyAlgorithm.fromValue(keyProps.getAlgorithm()));
                } catch (IllegalArgumentException e) {
                    logger.warn("Unknown algorithm '{}' for key '{}', skipping algorithm binding",
                            keyProps.getAlgorithm(), keyName);
                }
            }

            definitions.put(keyName, builder.build());
        }

        return definitions;
    }
}