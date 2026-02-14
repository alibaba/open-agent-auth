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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Key provider configuration properties.
 * <p>
 * This class defines configuration for cryptographic key providers used in the Open Agent Auth framework.
 * Key providers are responsible for managing cryptographic keys used for signing and verifying JWTs,
 * encrypting and decrypting sensitive data, and other security operations.
 * </p>
 * <p>
 * The framework supports the following key provider implementation:
 * </p>
 * <ul>
 *   <li>{@code in-memory} - Keys stored in memory for development and testing</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     key-management:
 *       providers:
 *         default:
 *           type: in-memory
 *       keys:
 *         wit-signing-key:
 *           key-id: wit-signing-key-001
 *           algorithm: ES256
 *           provider: default
 * </pre>
 *
 * @since 1.0
 * @see KeyManager
 * @see KeyDefinitionProperties
 * @see KeyManagementProperties
 */
public class KeyProviderProperties {

    /**
     * Provider type identifier.
     * <p>
     * Specifies the type of key provider to use. The value determines which
     * key provider implementation will be instantiated and configured by the
     * {@link KeyManager}.
     * </p>
     * <p>
     * Supported values:
     * </p>
     * <ul>
     *   <li>{@code in-memory} - In-memory key storage</li>
     * </ul>
     */
    private String type;

    /**
     * Provider-specific configuration parameters.
     * <p>
     * A map of configuration properties that are specific to the selected key provider type.
     * Each provider implementation may require different configuration parameters.
     * </p>
     * <p>
     * For the {@code in-memory} provider, no additional configuration is required.
     * This field is reserved for future provider implementations.
     * </p>
     * <p>
     * Default value: empty map
     * </p>
     */
    private Map<String, String> config = new HashMap<>();

    /**
     * Gets the key provider type.
     *
     * @return the provider type identifier
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the key provider type.
     *
     * @param type the provider type identifier to set
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Gets the provider-specific configuration parameters.
     *
     * @return the map of configuration parameters
     */
    public Map<String, String> getConfig() {
        return config;
    }

    /**
     * Sets the provider-specific configuration parameters.
     *
     * @param config the map of configuration parameters to set
     */
    public void setConfig(Map<String, String> config) {
        this.config = config;
    }
}