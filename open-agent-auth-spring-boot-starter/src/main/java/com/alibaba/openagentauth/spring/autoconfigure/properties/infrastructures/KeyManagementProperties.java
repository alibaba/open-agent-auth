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
package com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.HashMap;
import java.util.Map;

/**
 * Key management configuration properties.
 * <p>
 * This class defines the configuration for cryptographic key management infrastructure,
 * including key providers and key definitions. It enables the application to manage
 * cryptographic keys from various sources such as in-memory storage.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     key-management:
 *       providers:
 *         local:
 *           type: in-memory
 *       keys:
 *         signing-key:
 *           key-id: agent-signing-key-001
 *           algorithm: RS256
 *           provider: local
 *         encryption-key:
 *           key-id: agent-encryption-key-001
 *           algorithm: RSA-OAEP-256
 *           provider: local
 * </pre>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern</p>
 * <p>
 * This configuration allows different key providers to be plugged in at runtime,
 * enabling flexible key management strategies based on deployment requirements.
 * </p>
 *
 * @since 2.0
 * @see KeyProviderProperties
 * @see KeyDefinitionProperties
 */
@ConfigurationProperties(prefix = "open-agent-auth.infrastructures.key-management")
public class KeyManagementProperties {

    /**
     * Key providers.
     * <p>
     * Map of key provider configurations keyed by provider name.
     * Each provider defines how keys are generated, stored, and managed.
     * </p>
     * <p>
     * Default value: empty map
     * </p>
     */
    @NestedConfigurationProperty
    private Map<String, KeyProviderProperties> providers = new HashMap<>();

    /**
     * Key definitions.
     * <p>
     * Map of key definitions keyed by key name.
     * Each definition specifies which provider to use, algorithm, and purpose.
     * </p>
     * <p>
     * Default value: empty map
     * </p>
     */
    @NestedConfigurationProperty
    private Map<String, KeyDefinitionProperties> keys = new HashMap<>();

    /**
     * Gets the key providers configuration.
     *
     * @return the map of provider name to provider configuration
     */
    public Map<String, KeyProviderProperties> getProviders() {
        return providers;
    }

    /**
     * Sets the key providers configuration.
     *
     * @param providers the map of provider name to provider configuration to set
     */
    public void setProviders(Map<String, KeyProviderProperties> providers) {
        this.providers = providers;
    }

    /**
     * Gets the key definitions.
     *
     * @return the map of logical key name to key definition
     */
    public Map<String, KeyDefinitionProperties> getKeys() {
        return keys;
    }

    /**
     * Sets the key definitions.
     *
     * @param keys the map of logical key name to key definition to set
     */
    public void setKeys(Map<String, KeyDefinitionProperties> keys) {
        this.keys = keys;
    }
}