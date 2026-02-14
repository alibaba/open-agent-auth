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

import com.alibaba.openagentauth.spring.autoconfigure.properties.DefaultEndpoints;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.HashMap;
import java.util.Map;

/**
 * Service discovery configuration properties.
 * <p>
 * This class defines configuration for service discovery infrastructure,
 * which provides the ability to discover and connect to services dynamically.
 * Supports multiple service discovery types including static configuration,
 * Consul, and Eureka.
 * </p>
 * <p>
 * <b>Note:</b> Endpoints can be partially configured. If an endpoint is not specified,
 * it will use the default value from {@link DefaultEndpoints}. To override a specific
 * endpoint, simply specify it in the YAML configuration. To use all defaults, you can
 * omit the entire endpoints section.
 * </p>
 *
 * @since 1.0
 * @see ServiceDefinitionProperties
 */
@ConfigurationProperties(prefix = "open-agent-auth.infrastructures.service-discovery")
public class ServiceDiscoveryProperties {

    /**
     * Whether service discovery is enabled.
     * <p>
     * When enabled, the application will use the configured service discovery
     * mechanism to locate and connect to services. When disabled, services must
     * be accessed through direct URLs or fallback mechanisms.
     * </p>
     * <p>
     * Default value: {@code true}
     * </p>
     */
    private boolean enabled = true;

    /**
     * Service discovery type.
     * <p>
     * Specifies the service discovery mechanism to use. Supported types include:
     * </p>
     * <ul>
     *   <li>{@code static} - Static configuration-based discovery (default)</li>
     *   <li>{@code consul} - Consul-based service discovery</li>
     *   <li>{@code eureka} - Netflix Eureka-based service discovery</li>
     * </ul>
     * <p>
     * Default value: {@code static}
     * </p>
     */
    private String type = "static";

    /**
     * Service definitions (services that can be discovered).
     * <p>
     * Map of service definitions keyed by service name (e.g., "agent-idp", "authorization-server").
     * Each service definition contains the URL and other metadata for the service.
     * </p>
     * <p>
     * Default value: Empty map (no services defined)
     * </p>
     */
    @NestedConfigurationProperty
    private Map<String, ServiceDefinitionProperties> services = new HashMap<>();

    /**
     * Gets whether service discovery is enabled.
     *
     * @return {@code true} if service discovery is enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether service discovery is enabled.
     *
     * @param enabled {@code true} to enable service discovery, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the service discovery type.
     *
     * @return the service discovery type (e.g., "static", "consul", "eureka")
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the service discovery type.
     *
     * @param type the service discovery type to set
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Gets the map of service definitions.
     *
     * @return the map of service definitions, where keys are service names
     */
    public Map<String, ServiceDefinitionProperties> getServices() {
        return services;
    }

    /**
     * Sets the map of service definitions.
     *
     * @param services the map of service definitions to set
     */
    public void setServices(Map<String, ServiceDefinitionProperties> services) {
        this.services = services;
    }

}