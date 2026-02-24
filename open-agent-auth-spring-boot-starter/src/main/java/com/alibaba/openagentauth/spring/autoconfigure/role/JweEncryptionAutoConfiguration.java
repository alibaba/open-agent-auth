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
package com.alibaba.openagentauth.spring.autoconfigure.role;

import com.alibaba.openagentauth.core.crypto.jwe.JweDecoder;
import com.alibaba.openagentauth.core.crypto.jwe.JweEncoder;
import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweDecoder;
import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweEncoder;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptEncryptionService;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

import java.net.URL;
import java.security.PrivateKey;

/**
 * Auto-configuration for JWE encryption protection mechanism.
 * <p>
 * This configuration class automatically configures JWE encryption beans
 * when open-agent-auth.authorization-server.prompt-encryption.enabled is set to true.
 * </p>
 * <p>
 * This configuration is specific to the Agent Operation Authorization protocol
 * for securing Evidence VCs (user input) using JWE encryption.
 * </p>
 * <p>
 * <b>Configuration:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     operation-authorization:
 *       prompt-encryption:
 *         enabled: true
 *         encryption-key-id: "jwe-encryption-key-001"
 *         encryption-algorithm: "RSA-OAEP-256"
 *         content-encryption-algorithm: "A256GCM"
 * </pre>
 *
 * @since 1.0
 */
@AutoConfiguration(after = CoreAutoConfiguration.class)
@ConditionalOnProperty(prefix = "open-agent-auth.capabilities.operation-authorization.prompt-encryption", name = "enabled", havingValue = "true")
public class JweEncryptionAutoConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(JweEncryptionAutoConfiguration.class);

    /**
     * Creates the JWE encoder bean.
     * <p>
     * For Agent role, if jwksConsumer is configured, the encoder will
     * fetch the public key from the Authorization Server's JWKS endpoint. This ensures
     * that only the Authorization Server can decrypt the encrypted prompts.
     * </p>
     * <p>
     * For Authorization Server role or when jwksConsumer is not configured,
     * the encoder will use the local KeyManager's key for encryption.
     * </p>
     *
     * @param keyManager the key manager for retrieving encryption keys
 * @param openAgentAuthProperties the OpenAgentAuth properties
 * @return the JWE encoder instance
     * @throws IllegalStateException if key retrieval fails
     */
    @Bean
    @ConditionalOnMissingBean
    public JweEncoder jweEncoder(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
        try {
            OperationAuthorizationProperties.PromptEncryptionProperties properties = 
                openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption();
            
            // Validate encryption key ID
            String encryptionKeyId = properties.getEncryptionKeyId();
            if (encryptionKeyId == null || encryptionKeyId.isBlank()) {
                throw new IllegalStateException("Encryption key ID must be configured via " +
                        "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id");
            }
            
            Object encryptionJwk;
            String keySource;
            
            // Check if JWKS consumer is configured (Agent role scenario)
            if (properties.getJwksConsumer() != null 
                    && !properties.getJwksConsumer().isEmpty()) {
                // Fetch JWKS URL from consumer configuration
                String consumerName = properties.getJwksConsumer();
                var jwksConsumers = openAgentAuthProperties.getInfrastructures().getJwks().getConsumers();

                if (jwksConsumers == null || !jwksConsumers.containsKey(consumerName)) {
                    throw new IllegalStateException(
                        "JWKS consumer not found: " + consumerName +
                        ". Please configure it in open-agent-auth.infrastructures.jwks.consumers");
                }

                String jwksUrl = jwksConsumers.get(consumerName).getJwksEndpoint();
                logger.info("Fetching encryption public key from JWKS consumer '{}': {}", consumerName, jwksUrl);
                
                try {
                    JWKSet jwkSet = JWKSet.load(new URL(jwksUrl));
                    // Find the key with matching key ID
                    encryptionJwk = jwkSet.getKeyByKeyId(encryptionKeyId);
                    
                    if (encryptionJwk == null) {
                        throw new IllegalStateException(
                            "Encryption key not found in JWKS endpoint. Consumer: " + consumerName + 
                            ", Key ID: " + encryptionKeyId);
                    }
                    
                    keySource = "JWKS consumer '" + consumerName + "'";
                    logger.info("Successfully retrieved encryption key from JWKS consumer '{}'", consumerName);
                } catch (Exception e) {
                    throw new IllegalStateException(
                        "Failed to fetch encryption key from JWKS consumer '" + consumerName + 
                        "': " + jwksUrl, e);
                }
            } else {
                // Use local KeyManager (Authorization Server role or backward compatibility)
                logger.info("Using local KeyManager for encryption key");
                encryptionJwk = keyManager.getSigningJWK(encryptionKeyId);
                keySource = "local KeyManager";
            }

            // Parse algorithms
            JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(properties.getEncryptionAlgorithm());
            EncryptionMethod encryptionMethod = EncryptionMethod.parse(properties.getContentEncryptionAlgorithm());

            logger.info("Creating JweEncoder with algorithm: {}, method: {}, key source: {}", 
                    jweAlgorithm.getName(), encryptionMethod.getName(), keySource);

            return new NimbusJweEncoder((JWK) encryptionJwk, jweAlgorithm, encryptionMethod);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to get encryption key from KeyManager", e);
        }
    }

    /**
     * Creates the JWE decoder bean.
     *
     * @param keyManager the key manager for retrieving decryption keys
     * @param openAgentAuthProperties the OpenAgentAuth properties
     * @return the JWE decoder instance
     * @throws IllegalStateException if key retrieval fails
     */
    @Bean
    @ConditionalOnMissingBean
    public JweDecoder jweDecoder(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
        try {
            OperationAuthorizationProperties.PromptEncryptionProperties properties = 
                openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption();
            
            // Validate encryption key ID
            String keyId = properties.getEncryptionKeyId();
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalStateException("Encryption key ID must be configured via " +
                        "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id");
            }
            
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            
            try {
                keyManager.getOrGenerateKey(keyId, algorithm);
                logger.info("JWE encryption key ready. Key ID: {}", keyId);
            } catch (KeyManagementException e) {
                logger.error("Failed to generate JWE encryption key", e);
                throw new IllegalStateException("Failed to initialize JWE encryption key", e);
            }
            
            // Retrieve decryption private key from KeyManager
            PrivateKey decryptionKey = keyManager.getSigningKey(keyId);

            logger.info("Creating JweDecoder");

            return new NimbusJweDecoder(decryptionKey);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to get decryption key from KeyManager", e);
        }
    }

    /**
     * Creates the prompt encryption service bean.
     *
     * @param jweEncoder the JWE encoder
     * @param openAgentAuthProperties the OpenAgentAuth properties
     * @return the prompt encryption service instance
     */
    @Bean
    @ConditionalOnMissingBean
    public PromptEncryptionService promptEncryptionService(JweEncoder jweEncoder, 
                                                          OpenAgentAuthProperties openAgentAuthProperties) {
        OperationAuthorizationProperties.PromptEncryptionProperties properties = 
            openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption();
        return new PromptEncryptionService(jweEncoder, properties.isEnabled());
    }

    /**
     * Creates the prompt decryption service bean.
     *
     * @param jweDecoder the JWE decoder
     * @param openAgentAuthProperties the OpenAgentAuth properties
     * @return the prompt decryption service instance
     */
    @Bean
    @ConditionalOnMissingBean
    public PromptDecryptionService promptDecryptionService(JweDecoder jweDecoder, 
                                                          OpenAgentAuthProperties openAgentAuthProperties) {
        OperationAuthorizationProperties.PromptEncryptionProperties properties = 
            openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption();
        return new PromptDecryptionService(jweDecoder, properties.isEnabled());
    }
}