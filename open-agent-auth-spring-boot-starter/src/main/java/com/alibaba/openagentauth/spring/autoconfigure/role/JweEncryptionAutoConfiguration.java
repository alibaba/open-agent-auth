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
import com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RoleProfile;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RoleProfileRegistry;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.security.PrivateKey;
import java.util.Map;

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
     * The encoder retrieves the encryption key via KeyManager's resolveKey method,
     * which automatically determines whether to fetch the key from local storage
     * or remote JWKS endpoint based on the KeyDefinition configuration.
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
            
            // Resolve encryption key: first try by key definition name (supports peers-based config),
            // then try local decryption key (AS role), then fall back to explicit encryption-key-id
            JWK encryptionJwk = resolveEncryptionKey(keyManager, properties, openAgentAuthProperties);
            
            JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(properties.getEncryptionAlgorithm());
            EncryptionMethod encryptionMethod = EncryptionMethod.parse(properties.getContentEncryptionAlgorithm());
            
            logger.info("Creating JweEncoder with algorithm: {}, method: {}", 
                    jweAlgorithm.getName(), encryptionMethod.getName());
            
            return new NimbusJweEncoder(encryptionJwk, jweAlgorithm, encryptionMethod);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to resolve encryption key from KeyManager", e);
        }
    }

    /**
     * Resolves the encryption JWK using a multi-step strategy:
     * <ol>
     *   <li>Try resolving by key definition name ({@code jwe-encryption}), which works with
     *       the peers-based auto-configuration where keys are inferred from role profiles.
     *       This is the typical path for the <b>Agent</b> role, which fetches the public key
     *       from the Authorization Server's JWKS endpoint.</li>
     *   <li>If a local {@code jwe-decryption} key definition exists (typical for the
     *       <b>Authorization Server</b> role), use its keyId to retrieve the local key pair.
     *       The returned JWK contains both the private and public key; the public key portion
     *       is used for encryption.</li>
     *   <li>Fall back to the explicit {@code encryption-key-id} from capabilities configuration,
     *       which supports legacy explicit key configuration.</li>
     * </ol>
     */
    private JWK resolveEncryptionKey(KeyManager keyManager,
                                     OperationAuthorizationProperties.PromptEncryptionProperties properties,
                                     OpenAgentAuthProperties openAgentAuthProperties)
            throws KeyManagementException {
        // Strategy 1: Resolve by key definition name "jwe-encryption" (Agent role — remote key)
        try {
            logger.info("Resolving encryption key by definition name: {}", ConfigConstants.KEY_JWE_ENCRYPTION);
            JWK encryptionJwk = (JWK) keyManager.resolveKey(ConfigConstants.KEY_JWE_ENCRYPTION);
            logger.info("Successfully resolved encryption key by definition name");
            return encryptionJwk;
        } catch (KeyManagementException e) {
            logger.debug("Could not resolve encryption key by definition name, trying local decryption key", e);
        }

        // Strategy 2: Use local jwe-decryption key (Authorization Server role — local key pair)
        // The AS role stores the decryption key locally; its public key portion is used for encryption.
        KeyDefinitionProperties decryptionKeyDef = openAgentAuthProperties.getInfrastructures()
                .getKeyManagement().getKeys().get(ConfigConstants.KEY_JWE_DECRYPTION);
        if (decryptionKeyDef != null && decryptionKeyDef.getKeyId() != null) {
            String decryptionKeyId = decryptionKeyDef.getKeyId();
            logger.info("Resolving encryption key from local decryption key: {}", decryptionKeyId);
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            keyManager.getOrGenerateKey(decryptionKeyId, algorithm);
            JWK encryptionJwk = (JWK) keyManager.getSigningJWK(decryptionKeyId);
            logger.info("Successfully resolved encryption key from local decryption key");
            return encryptionJwk;
        }

        // Strategy 3: Fall back to explicit encryption-key-id
        String encryptionKeyId = properties.getEncryptionKeyId();
        if (encryptionKeyId == null || encryptionKeyId.isBlank()) {
            throw new KeyManagementException(
                    "Encryption key could not be resolved. Either configure peers for automatic key inference, " +
                    "or set open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id");
        }

        logger.info("Resolving encryption key by explicit key ID: {}", encryptionKeyId);
        JWK encryptionJwk = (JWK) keyManager.resolveKey(encryptionKeyId);
        logger.info("Successfully resolved encryption key by explicit key ID: {}", encryptionKeyId);
        return encryptionJwk;
    }

    /**
     * Resolves the decryption key ID using a two-step strategy.
     * Returns {@code null} if no decryption key is available (e.g., Agent role only encrypts).
     */
    static String resolveDecryptionKeyId(
            OperationAuthorizationProperties.PromptEncryptionProperties properties,
            OpenAgentAuthProperties openAgentAuthProperties
    ) {
        // Strategy 1: Look up jwe-decryption key definition from inferred config
        KeyDefinitionProperties decryptionKeyDef = openAgentAuthProperties.getInfrastructures()
                .getKeyManagement().getKeys().get(ConfigConstants.KEY_JWE_DECRYPTION);
        if (decryptionKeyDef != null && decryptionKeyDef.getKeyId() != null) {
            logger.info("Found decryption key definition '{}' with keyId: {}",
                    ConfigConstants.KEY_JWE_DECRYPTION, decryptionKeyDef.getKeyId());
            return decryptionKeyDef.getKeyId();
        }

        // Strategy 2: Fall back to explicit encryption-key-id
        String keyId = properties.getEncryptionKeyId();
        if (keyId != null && !keyId.isBlank()) {
            logger.info("Using explicit encryption key ID for decryption: {}", keyId);
            return keyId;
        }

        // No decryption key available — this is expected for roles that only encrypt (e.g., Agent)
        logger.info("No decryption key definition or explicit key ID found — decryption is not available");
        return null;
    }

    /**
     * Condition that checks whether a JWE decryption key is available.
     * <p>
     * This condition evaluates to {@code true} when any of the following holds:
     * <ol>
     *   <li>A {@code jwe-decryption} key definition exists explicitly in the YAML configuration.</li>
     *   <li>An explicit {@code encryption-key-id} is set in the prompt-encryption configuration.</li>
     *   <li>An enabled role's {@link RoleProfile} declares {@code decryptionKeys}, meaning the
     *       decryption key will be inferred at runtime by {@code RoleAwareEnvironmentPostProcessor}.
     *       This covers the Authorization Server role where the {@code jwe-decryption} key is
     *       auto-configured from peer declarations rather than explicit YAML.</li>
     * </ol>
     * This ensures that {@link JweDecoder} and {@link PromptDecryptionService} beans are only
     * registered for roles that actually perform decryption (e.g., Authorization Server), not
     * for roles that only encrypt (e.g., Agent).
     * </p>
     */
    static class DecryptionKeyAvailableCondition implements Condition {

        /**
         * Checks whether a JWE decryption key is available.
         *
         * @param context the condition context
         * @param metadata the annotated type metadata
         * @return {@code true} if a JWE decryption key is available, {@code false} otherwise
         */
        @Override
        public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
            Environment env = context.getEnvironment();

            // Strategy 1: Check if jwe-decryption key definition exists explicitly in YAML
            String decryptionKeyId = env.getProperty(
                    "open-agent-auth.infrastructures.key-management.keys.jwe-decryption.key-id");
            if (decryptionKeyId != null && !decryptionKeyId.isBlank()) {
                return true;
            }

            // Strategy 2: Check explicit encryption-key-id fallback
            String explicitKeyId = env.getProperty(
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id");
            if (explicitKeyId != null && !explicitKeyId.isBlank()) {
                return true;
            }

            // Strategy 3: Check if any enabled role's profile declares decryptionKeys.
            // The decryption key will be inferred by RoleAwareEnvironmentPostProcessor at runtime,
            // so it won't appear in the Environment yet, but we know it will be available.
            return hasEnabledRoleWithDecryptionKeys(env);
        }

        /**
         * Checks if any enabled role's profile declares decryptionKeys.
         *
         * @param env the environment
         * @return {@code true} if any enabled role's profile declares decryptionKeys, {@code false} otherwise
         */
        private boolean hasEnabledRoleWithDecryptionKeys(Environment env) {
            for (Map.Entry<String, RoleProfile> entry : RoleProfileRegistry.getAllProfiles().entrySet()) {
                String roleName = entry.getKey();
                RoleProfile profile = entry.getValue();
                if (!profile.getDecryptionKeys().isEmpty()) {
                    String roleEnabled = env.getProperty("open-agent-auth.roles." + roleName + ".enabled");
                    if ("true".equalsIgnoreCase(roleEnabled)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    /**
     * Creates the JWE decoder bean.
     * <p>
     * This bean is only registered when a decryption key is available, which is determined
     * by the {@link DecryptionKeyAvailableCondition}. The Agent role (which only encrypts)
     * will not have this bean registered.
     * </p>
     *
     * @param keyManager the key manager for retrieving decryption keys
     * @param openAgentAuthProperties the OpenAgentAuth properties
     * @return the JWE decoder instance
     * @throws IllegalStateException if key retrieval fails
     */
    @Bean
    @ConditionalOnMissingBean
    @Conditional(DecryptionKeyAvailableCondition.class)
    public JweDecoder jweDecoder(KeyManager keyManager, OpenAgentAuthProperties openAgentAuthProperties) {
        OperationAuthorizationProperties.PromptEncryptionProperties properties =
            openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption();

        String keyId = resolveDecryptionKeyId(properties, openAgentAuthProperties);
        if (keyId == null) {
            // Should not happen due to DecryptionKeyAvailableCondition, but defensive check
            throw new IllegalStateException("Decryption key ID resolved to null despite condition passing");
        }

        try {
            KeyAlgorithm algorithm = KeyAlgorithm.RS256;
            keyManager.getOrGenerateKey(keyId, algorithm);
            logger.info("JWE decryption key ready. Key ID: {}", keyId);

            PrivateKey decryptionKey = keyManager.getSigningKey(keyId);
            logger.info("Creating JweDecoder");
            return new NimbusJweDecoder(decryptionKey);
        } catch (KeyManagementException e) {
            throw new IllegalStateException("Failed to initialize JWE decryption key: " + keyId, e);
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
     * <p>
     * This bean is only registered when a decryption key is available (same condition as
     * {@link #jweDecoder}). The Agent role will not have this bean registered.
     * </p>
     *
     * @param jweDecoder the JWE decoder
     * @param openAgentAuthProperties the OpenAgentAuth properties
     * @return the prompt decryption service instance
     */
    @Bean
    @ConditionalOnMissingBean
    @Conditional(DecryptionKeyAvailableCondition.class)
    public PromptDecryptionService promptDecryptionService(JweDecoder jweDecoder, 
                                                          OpenAgentAuthProperties openAgentAuthProperties) {
        OperationAuthorizationProperties.PromptEncryptionProperties properties = 
            openAgentAuthProperties.getCapabilities().getOperationAuthorization().getPromptEncryption();
        return new PromptDecryptionService(jweDecoder, properties.isEnabled());
    }
}