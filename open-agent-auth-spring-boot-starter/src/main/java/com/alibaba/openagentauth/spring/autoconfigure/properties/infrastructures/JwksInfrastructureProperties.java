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

import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.HashMap;
import java.util.Map;

/**
 * JWKS infrastructure configuration properties.
 * <p>
 * This class defines configuration for the JWKS (JSON Web Key Set) infrastructure,
 * which provides key management for JWT token validation and signing.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties}
 * and bound as part of the {@code open-agent-auth.infrastructures.jwks} prefix through the parent class.
 * </p>
 * <p>
 * The infrastructure consists of two main components:
 * <ul>
 *   <li><b>Provider</b>: Exposes public keys for token validation by other services</li>
 *   <li><b>Consumers</b>: Fetches and caches public keys from external IDPs for token validation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     jwks:
 *       provider:
 *         enabled: true
 *         path: /.well-known/jwks.json
 *       consumers:
 *         external-idp:
 *           jwks-endpoint: https://external-idp.example.com/.well-known/jwks.json
 *           cache-duration-seconds: 300
 * </pre>
 *
 * @since 2.0
 * @see JwksProviderProperties
 * @see JwksConsumerProperties
 */
public class JwksInfrastructureProperties {

    /**
     * Provider configuration (for exposing this service's public keys).
     * <p>
     * When configured as a provider, this service will expose its public keys
     * through a JWKS endpoint, allowing other services to validate JWT tokens
     * issued by this service.
     * </p>
     */
    @NestedConfigurationProperty
    private JwksProviderProperties provider = new JwksProviderProperties();

    /**
     * Consumers configuration (for validating tokens from other IDPs).
     * <p>
     * Map of JWKS consumer configurations keyed by consumer name.
     * Each consumer will fetch and cache the public keys from the configured JWKS URI,
     * enabling efficient JWT signature validation without repeatedly fetching the keys.
     * </p>
     */
    @NestedConfigurationProperty
    private Map<String, JwksConsumerProperties> consumers = new HashMap<>();

    /**
     * Gets the provider configuration.
     *
     * @return the provider configuration for exposing public keys
     */
    public JwksProviderProperties getProvider() {
        return provider;
    }

    /**
     * Sets the provider configuration.
     *
     * @param provider the provider configuration to set
     */
    public void setProvider(JwksProviderProperties provider) {
        this.provider = provider;
    }

    /**
     * Gets the consumers configuration map.
     *
     * @return a map of consumer names to their corresponding JWKS consumer configurations
     */
    public Map<String, JwksConsumerProperties> getConsumers() {
        return consumers;
    }

    /**
     * Sets the consumers configuration map.
     *
     * @param consumers the map of consumer configurations to set
     */
    public void setConsumers(Map<String, JwksConsumerProperties> consumers) {
        this.consumers = consumers;
    }
}