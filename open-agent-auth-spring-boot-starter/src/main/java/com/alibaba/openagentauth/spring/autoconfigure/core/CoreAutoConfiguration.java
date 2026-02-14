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
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.AuditProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.UserAuthenticationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.WorkloadIdentityProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyManagementProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDiscoveryProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

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
@EnableConfigurationProperties({
    OpenAgentAuthProperties.class,
    InfrastructureProperties.class,
    CapabilitiesProperties.class,
    OAuth2ServerProperties.class,
    OAuth2ClientProperties.class,
    WorkloadIdentityProperties.class,
    OperationAuthorizationProperties.class,
    UserAuthenticationProperties.class,
    KeyManagementProperties.class,
    JwksInfrastructureProperties.class,
    ServiceDiscoveryProperties.class,
    AuditProperties.class
})
@ConditionalOnProperty(prefix = "open-agent-auth", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CoreAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(CoreAutoConfiguration.class);

    /**
     * Default constructor.
     */
    public CoreAutoConfiguration() {
        logger.info("CoreAutoConfiguration initialized");
    }

    /**
     * Creates the KeyManager bean if not already defined.
     * <p>
     * The KeyManager provides centralized key management for all cryptographic operations,
     * including key generation, storage, and retrieval.
     * </p>
     *
     * @return the KeyManager bean
     */
    @Bean
    @ConditionalOnMissingBean
    public KeyManager keyManager() {
        logger.info("Creating KeyManager bean with InMemoryKeyStore");
        return new DefaultKeyManager(new InMemoryKeyStore());
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
     *
     * @param keyManager the key manager
     * @param trustDomain the trust domain
     * @return the TokenService bean
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenService tokenService(KeyManager keyManager, TrustDomain trustDomain) {
        logger.info("Creating TokenService bean");
        
        // Define key ID for WIT signing key
        String keyId = "wit-signing-key";
        logger.info("Getting or generating WIT signing key with ID: {}", keyId);
        
        // Get or generate WIT signing key from KeyManager
        JWK signingJWK;
        try {
            signingJWK = (JWK) keyManager.getOrGenerateKey(keyId, KeyAlgorithm.ES256);
            logger.info("WIT signing key ready. Key ID: {}", keyId);
        } catch (Exception e) {
            logger.error("Failed to get or generate signing key: {}", e.getMessage(), e);
            throw new IllegalStateException("Failed to initialize WIT signing key", e);
        }
        
        return new TokenService(signingJWK, trustDomain, JWSAlgorithm.ES256);
    }

}