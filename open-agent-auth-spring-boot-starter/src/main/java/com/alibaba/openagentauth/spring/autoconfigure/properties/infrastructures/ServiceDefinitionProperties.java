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

import java.util.HashMap;
import java.util.Map;

/**
 * Service definition configuration properties.
 * <p>
 * This class defines configuration for a service definition, which represents
 * an external service or infrastructure component that the Open Agent Auth framework
 * needs to communicate with. Service definitions include base URLs and endpoint mappings
 * for various operations such as authorization, token issuance, and policy management.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     service-discovery:
 *       services:
 *         authorization-server:
 *           base-url: http://localhost:8080
 *           endpoints:
 *             authorize: /oauth2/authorize
 *             token: /oauth2/token
 *             jwks: /.well-known/jwks.json
 *         policy-server:
 *           base-url: http://localhost:8081
 *           endpoints:
 *             policies: /api/v1/policies
 *             bindings: /api/v1/bindings
 * </pre>
 *
 * @since 2.0
 */
public class ServiceDefinitionProperties {

    /**
     * Base URL of the service.
     * <p>
     * The root URL for the service, which is used as the prefix for all
     * endpoint paths. This URL should include the protocol (http or https),
     * hostname, and port number if applicable.
     * </p>
     * <p>
     * For example, if the base URL is {@code http://localhost:8080} and an
     * endpoint is defined as {@code /oauth2/token}, the full endpoint URL
     * will be {@code http://localhost:8080/oauth2/token}.
     * </p>
     */
    private String baseUrl;

    /**
     * Endpoint configurations.
     * <p>
     * A map of endpoint name to relative path that defines all available
     * endpoints for this service. Each key represents a logical endpoint name
     * (e.g., {@code authorize}, {@code token}, {@code jwks}), and the value
     * is the relative path from the base URL.
     * </p>
     * <p>
     * Endpoint paths should start with a forward slash ({@code /}) and can
     * include path variables using the format {@code {variableName}}.
     * </p>
     * <p>
     * Default value: empty map
     * </p>
     */
    private Map<String, String> endpoints = new HashMap<>();

    /**
     * Gets the base URL of the service.
     *
     * @return the base URL, or {@code null} if not configured
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Sets the base URL of the service.
     *
     * @param baseUrl the base URL to set, including protocol, hostname, and port
     */
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Gets the endpoint configurations with defaults merged.
     * <p>
     * If no endpoints are configured, returns all default endpoints.
     * If some endpoints are configured, returns user-provided endpoints merged
     * with defaults, where user-provided endpoints override defaults.
     * </p>
     *
     * @return a map of endpoint names to relative paths with defaults merged
     */
    public Map<String, String> getEndpoints() {

        // If no endpoints are configured, use defaults
        if (endpoints == null || endpoints.isEmpty()) {
            return new HashMap<>(DefaultEndpoints.getAllDefaults());
        }
        
        // Merge user endpoints with defaults
        Map<String, String> merged = new HashMap<>(DefaultEndpoints.getAllDefaults());
        merged.putAll(endpoints);
        return merged;
    }

    /**
     * Sets the endpoint configurations.
     * <p>
     * This method is called by Spring Boot during configuration binding when
     * binding to the {@code endpoints} field. The configuration under the
     * service's {@code endpoints} key will be bound to this map.
     * </p>
     *
     * @param endpoints the map of endpoint name to relative path to set
     */
    public void setEndpoints(Map<String, String> endpoints) {
        this.endpoints = endpoints;
    }
}