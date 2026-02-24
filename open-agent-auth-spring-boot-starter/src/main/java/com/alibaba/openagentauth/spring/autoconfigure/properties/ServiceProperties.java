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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import java.util.HashMap;
import java.util.Map;

/**
 * Service configuration properties for inter-service communication.
 * <p>
 * This class defines configuration for calling other services in the Open Agent Auth system.
 * Each service can be configured with its base URL. Applications can override these defaults
 * in their YAML configuration files.
 * </p>
 * <b>Note:</b> Endpoints can be partially configured. If an endpoint is not specified,
 * it will use the default value from {@link DefaultEndpoints}. To override a specific
 * endpoint, simply specify it in the YAML configuration. To use all defaults, you can
 * omit the entire endpoints section.
 * </p>
 *
 * @since 1.0
 */
public class ServiceProperties {

    /**
     * Provider configuration for the current application's own endpoints.
     * <p>
     * This configuration defines the endpoints that the current application exposes.
     * Unlike consumers, provider does not have application grouping since there is only
     * one application (itself). This structure allows code reuse with ConsumerServiceProperties
     * while removing the redundant application grouping layer.
     * </p>
     */
    private ProviderProperties provider = new ProviderProperties();

    /**
     * Consumer configuration for downstream services.
     * <p>
     * This configuration defines how to call other services in the system.
     * Services are grouped by application name (e.g., agent-idp, authorization-server).
     * </p>
     */
    private Map<String, ConsumerServiceProperties> consumers = new HashMap<>();

    /**
     * Post-process the configuration to merge user-provided endpoints with defaults.
     * <p>
     * This method is called by Spring Boot after all properties have been bound.
     * It ensures that any endpoints not explicitly configured will use the default values.
     * User-provided endpoints take precedence over defaults.
     * </p>
     */
    public void postProcess() {
        // Merge provider endpoints with defaults
        mergeEndpointsWithDefaults(provider.getEndpoints());
        
        // Merge consumer endpoints with defaults
        for (ConsumerServiceProperties consumer : consumers.values()) {
            mergeEndpointsWithDefaults(consumer.getEndpoints());
        }
    }

    /**
     * Merges user-provided endpoints with default endpoints.
     * <p>
     * User-provided endpoints take precedence. If an endpoint key is not provided,
     * the default value from {@link DefaultEndpoints} will be used.
     * </p>
     *
     * @param userEndpoints the user-provided endpoints map (may be empty)
     */
    private void mergeEndpointsWithDefaults(Map<String, String> userEndpoints) {
        if (userEndpoints == null || userEndpoints.isEmpty()) {
            // If no user endpoints provided, use all defaults
            if (userEndpoints == null) {
                return; // Will be initialized with empty map by constructor
            }
            return;
        }
        
        // Get all default endpoints
        Map<String, String> defaultEndpoints = DefaultEndpoints.getAllDefaults();
        
        // Merge: user endpoints override defaults, but we only add defaults for missing keys
        // We don't want to add all defaults to every service, only those that are relevant
        // So we check each default endpoint and add it if not present in user config
        for (Map.Entry<String, String> entry : defaultEndpoints.entrySet()) {
            String key = entry.getKey();
            if (!userEndpoints.containsKey(key)) {
                // Only add default if the user didn't specify this endpoint
                userEndpoints.put(key, entry.getValue());
            }
        }
    }

    public ProviderProperties getProvider() {
        return provider;
    }

    public void setProvider(ProviderProperties provider) {
        this.provider = provider;
    }

    public Map<String, ConsumerServiceProperties> getConsumers() {
        return consumers;
    }

    public void setConsumers(Map<String, ConsumerServiceProperties> consumers) {
        this.consumers = consumers;
    }



    /**
     * Provider configuration (reuses ConsumerServiceProperties structure without application grouping).
     * <p>
     * This class defines the endpoints that the current application exposes to other services.
     * It reuses the same structure as ConsumerServiceProperties (base-url + endpoints map)
     * but removes the redundant application grouping layer since there is only one application.
     * </p>
     */
    public static class ProviderProperties {
        /**
         * Whether the provider configuration is enabled.
         */
        private boolean enabled = true;

        /**
         * The base URL of the current application.
         * <p>
         * This should typically be set to ${open-agent-auth.issuer} to use the issuer URL.
         * </p>
         */
        private String baseUrl;

        /**
         * Endpoint configurations (key -> full path).
         * <p>
         * All paths are full paths without base path prefix.
         * For example: /api/v1/workloads/create instead of /create
         * </p>
         * <p>
         * If not configured, default values from {@link DefaultEndpoints} will be used.
         * Partial configuration is supported - only specify the endpoints you want to override.
         * </p>
         */
        private Map<String, String> endpoints = new HashMap<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public Map<String, String> getEndpoints() {
            return endpoints;
        }

        public void setEndpoints(Map<String, String> endpoints) {
            this.endpoints = endpoints;
        }
    }

    /**
     * Base class for consumer service configuration.
     * <p>
     * All consumer service configurations extend this class to provide a common structure
     * for base URL and endpoint configuration.
     * </p>
     */
    public static class ConsumerServiceProperties {
        /**
         * The base URL of the consumer service.
         * <p>
         * Applications can override this in their YAML configuration.
         * Default values are provided for each service type.
         * </p>
         */
        private String baseUrl;

        /**
         * Endpoint configurations (key -> full path).
         * <p>
         * All paths are full paths without base path prefix.
         * For example: /api/v1/workloads/create instead of /create
         * </p>
         * <p>
         * If not configured, default values from {@link DefaultEndpoints} will be used.
         * Partial configuration is supported - only specify the endpoints you want to override.
         * </p>
         */
        private Map<String, String> endpoints = new HashMap<>();

        /**
         * Whether to use the issuer URL as base URL (if available).
         * <p>
         * If true, baseUrl will be derived from the issuer URL configured in JWKS consumers.
         * This allows automatic discovery of service URLs based on their issuer configuration.
         * Default: false
         * </p>
         */
        private boolean useIssuerAsBaseUrl = false;

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public Map<String, String> getEndpoints() {
            return endpoints;
        }

        public void setEndpoints(Map<String, String> endpoints) {
            this.endpoints = endpoints;
        }

        public boolean isUseIssuerAsBaseUrl() {
            return useIssuerAsBaseUrl;
        }

        public void setUseIssuerAsBaseUrl(boolean useIssuerAsBaseUrl) {
            this.useIssuerAsBaseUrl = useIssuerAsBaseUrl;
        }
    }
}