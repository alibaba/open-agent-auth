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
package com.alibaba.openagentauth.spring.autoconfigure.discovery;

import com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.PeerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RoleProfile;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RoleProfileRegistry;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyProviderProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDefinitionProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Infers default infrastructure configuration from enabled roles and declared peers.
 * <p>
 * This processor operates on the already-bound {@link OpenAgentAuthProperties} Java object,
 * filling in missing configuration based on the enabled roles and declared peers. It is
 * designed to be called <b>after</b> {@code @ConfigurationProperties} binding is complete
 * but <b>before</b> any beans that depend on the configuration are created.
 * </p>
 * <p>
 * This approach avoids the pitfall of injecting flat properties via {@code EnvironmentPostProcessor},
 * which can interfere with Spring Boot's {@code @ConfigurationProperties} binding of {@code Map}
 * types. By operating directly on the Java object, we ensure that explicit YAML configuration
 * is preserved and only missing entries are filled in.
 * </p>
 *
 * <h3>What gets inferred:</h3>
 * <ol>
 *   <li><b>Peer expansion</b>: Each declared peer is expanded into a JWKS consumer
 *       and a service-discovery entry</li>
 *   <li><b>Key inference</b>: Based on the enabled role's profile, required signing keys,
 *       verification keys, encryption keys, and decryption keys are automatically configured</li>
 *   <li><b>Provider defaults</b>: If no key providers are configured, an in-memory
 *       provider is automatically added</li>
 *   <li><b>JWKS provider</b>: Automatically enabled if the role profile requires it</li>
 * </ol>
 *
 * <h3>Usage:</h3>
 * <p>
 * This class is instantiated and invoked by {@code CoreAutoConfiguration} during its
 * initialization, ensuring that all inferred configuration is available before any
 * infrastructure beans (KeyManager, JwksConsumerKeyResolver, etc.) are created.
 * </p>
 *
 * @since 2.1
 * @see RoleProfile
 * @see RoleProfileRegistry
 */
public class RoleAwareEnvironmentPostProcessor {

    /**
     * Logger for the role-aware environment post-processor.
     */
    private static final Logger logger = LoggerFactory.getLogger(RoleAwareEnvironmentPostProcessor.class);

    /**
     * The bound configuration properties.
     */
    private final OpenAgentAuthProperties properties;

    /**
     * Creates a new processor for the given properties.
     *
     * @param properties the bound configuration properties
     */
    public RoleAwareEnvironmentPostProcessor(OpenAgentAuthProperties properties) {
        this.properties = properties;
    }

    /**
     * Processes the configuration, inferring defaults from enabled roles and declared peers.
     * <p>
     * This method is idempotent — calling it multiple times has no additional effect
     * because it only fills in entries that are not already present.
     * </p>
     */
    public void processConfiguration() {
        List<String> enabledRoles = findEnabledRoles();
        if (enabledRoles.isEmpty()) {
            logger.debug("No roles enabled, skipping role-aware configuration processing");
            return;
        }

        logger.info("Role-aware configuration processing starting for roles: {}", enabledRoles);

        InfrastructureProperties infra = properties.getInfrastructures();

        // Step 1: Expand peers into JWKS consumers and service-discovery entries
        expandPeers(infra);

        // Step 2: Infer keys from role profiles
        boolean needsJwksProvider = false;
        for (String roleName : enabledRoles) {
            RoleProfile profile = RoleProfileRegistry.getProfile(roleName);
            if (profile != null) {
                inferKeysFromProfile(infra, roleName, profile);
                if (profile.isJwksProviderEnabled()) {
                    needsJwksProvider = true;
                }
            }
        }

        // Step 3: Enable JWKS provider if needed
        if (needsJwksProvider && !infra.getJwks().getProvider().isEnabled()) {
            infra.getJwks().getProvider().setEnabled(true);
            logger.debug("Auto-enabled JWKS provider");
        }

        // Step 4: Ensure default key provider exists
        ensureDefaultKeyProvider(infra);

        logger.info("Role-aware configuration processing complete for roles: {}", enabledRoles);
    }

    /**
     * Finds all roles that are explicitly enabled.
     */
    private List<String> findEnabledRoles() {
        List<String> enabledRoles = new ArrayList<>();
        Map<String, RolesProperties.RoleProperties> roles = properties.getRoles();
        if (roles == null || roles.isEmpty()) {
            return enabledRoles;
        }

        for (Map.Entry<String, RolesProperties.RoleProperties> entry : roles.entrySet()) {
            if (entry.getValue() != null && entry.getValue().isEnabled()) {
                enabledRoles.add(entry.getKey());
            }
        }
        return enabledRoles;
    }

    /**
     * Expands peer declarations into JWKS consumers and service-discovery entries.
     * Only adds entries that are not already explicitly configured.
     */
    private void expandPeers(InfrastructureProperties infra) {
        Map<String, PeerProperties> peers = properties.getPeers();
        if (peers == null || peers.isEmpty()) {
            return;
        }

        Map<String, JwksConsumerProperties> consumers = infra.getJwks().getConsumers();
        Map<String, ServiceDefinitionProperties> services = infra.getServiceDiscovery().getServices();

        for (Map.Entry<String, PeerProperties> entry : peers.entrySet()) {
            String peerName = entry.getKey();
            PeerProperties peer = entry.getValue();

            if (peer == null || !peer.isEnabled() || peer.getIssuer() == null || peer.getIssuer().isBlank()) {
                continue;
            }

            // Expand to JWKS consumer (only if not already configured)
            if (!consumers.containsKey(peerName)) {
                JwksConsumerProperties consumer = new JwksConsumerProperties();
                consumer.setEnabled(true);
                consumer.setIssuer(peer.getIssuer());
                consumers.put(peerName, consumer);
                logger.debug("Auto-configured JWKS consumer '{}' from peer (issuer: {})", peerName, peer.getIssuer());
            }

            // Expand to service-discovery entry (only if not already configured)
            if (!services.containsKey(peerName)) {
                ServiceDefinitionProperties service = new ServiceDefinitionProperties();
                service.setBaseUrl(peer.getIssuer());
                services.put(peerName, service);
                logger.debug("Auto-configured service-discovery '{}' from peer (base-url: {})", peerName, peer.getIssuer());
            }
        }
    }

    /**
     * Infers key definitions from the role profile.
     * Only adds keys that are not already explicitly configured.
     */
    private void inferKeysFromProfile(InfrastructureProperties infra, String roleName, RoleProfile profile) {
        Map<String, KeyDefinitionProperties> keys = infra.getKeyManagement().getKeys();

        // Process signing keys (local keys with private key)
        for (String keyName : profile.getSigningKeys()) {
            inferLocalKey(keys, keyName, profile, roleName, "signing");
        }

        // Process decryption keys (local keys with private key)
        for (String keyName : profile.getDecryptionKeys()) {
            inferLocalKey(keys, keyName, profile, roleName, "decryption");
        }

        // Process verification keys (remote keys from JWKS)
        for (String keyName : profile.getVerificationKeys()) {
            inferRemoteKey(keys, keyName, profile, roleName, "verification");
        }

        // Process encryption keys (remote public keys from JWKS)
        for (String keyName : profile.getEncryptionKeys()) {
            inferRemoteKey(keys, keyName, profile, roleName, "encryption");
        }
    }

    /**
     * Infers a local key (signing or decryption) with a local provider.
     */
    private void inferLocalKey(Map<String, KeyDefinitionProperties> keys, String keyName,
                               RoleProfile profile, String roleName, String keyType) {
        if (keys.containsKey(keyName)) {
            return;
        }

        KeyDefinitionProperties keyDef = new KeyDefinitionProperties();
        keyDef.setKeyId(keyName + "-key");
        keyDef.setAlgorithm(profile.getDefaultAlgorithm(keyName));
        keyDef.setProvider("local");
        keys.put(keyName, keyDef);

        logger.debug("Auto-configured {} key '{}' for role '{}' (algorithm: {}, provider: local)",
                keyType, keyName, roleName, profile.getDefaultAlgorithm(keyName));
    }

    /**
     * Infers a remote key (verification or encryption) from a JWKS consumer.
     */
    private void inferRemoteKey(Map<String, KeyDefinitionProperties> keys, String keyName,
                                RoleProfile profile, String roleName, String keyType) {
        if (keys.containsKey(keyName)) {
            return;
        }

        String peerName = profile.getPeerForKey(keyName);
        if (peerName == null) {
            return;
        }

        // Derive key-id from the corresponding signing/decryption key convention
        String correspondingKeyName = keyType.equals("verification")
                ? keyName.replace("-verification", "-signing")
                : keyName.replace("-encryption", "-decryption");

        KeyDefinitionProperties keyDef = new KeyDefinitionProperties();
        keyDef.setKeyId(correspondingKeyName + "-key");
        keyDef.setAlgorithm(profile.getDefaultAlgorithm(keyName));
        keyDef.setJwksConsumer(peerName);
        keys.put(keyName, keyDef);

        logger.debug("Auto-configured {} key '{}' for role '{}' (algorithm: {}, jwks-consumer: {})",
                keyType, keyName, roleName, profile.getDefaultAlgorithm(keyName), peerName);
    }

    /**
     * Ensures a default "local" key provider exists if none are configured.
     */
    private void ensureDefaultKeyProvider(InfrastructureProperties infra) {
        Map<String, KeyProviderProperties> providers = infra.getKeyManagement().getProviders();
        if (!providers.containsKey("local")) {
            KeyProviderProperties provider = new KeyProviderProperties();
            provider.setType("in-memory");
            providers.put("local", provider);
            logger.debug("Auto-configured default 'local' key provider (type: in-memory)");
        }
    }
}