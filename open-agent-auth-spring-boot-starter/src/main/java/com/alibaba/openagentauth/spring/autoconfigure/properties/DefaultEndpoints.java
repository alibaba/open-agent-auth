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
 * Default endpoint configurations for all service types.
 * <p>
 * This is a utility class that provides default endpoint paths for various service
 * categories in the Open Agent Auth system. These defaults are used when endpoints
 * are not explicitly configured in the application YAML.
 * </p>
 * <p>
 * The configuration supports hierarchical endpoint keys using dot notation,
 * such as "workload.issue", "oauth2.authorize", etc.
 * </p>
 * <p>
 * <b>Note:</b> This is a utility class and cannot be instantiated. All methods
 * are static and provide access to predefined endpoint configurations.
 * </p>
 *
 * @since 1.0
 */
public final class DefaultEndpoints {

    /**
     * Private constructor to prevent instantiation.
     * <p>
     * This is a utility class with only static methods, so instantiation is not allowed.
     * </p>
     */
    private DefaultEndpoints() {
        // Utility class - prevent instantiation
    }

    /**
     * Default workload endpoints.
     */
    public static final Map<String, String> WORKLOAD = createWorkloadEndpoints();

    /**
     * Default OAuth2 endpoints.
     */
    public static final Map<String, String> OAUTH2 = createOAuth2Endpoints();

    /**
     * Default policy endpoints.
     */
    public static final Map<String, String> POLICY = createPolicyEndpoints();

    /**
     * Default binding endpoints.
     */
    public static final Map<String, String> BINDING = createBindingEndpoints();

    /**
     * Default audit endpoints.
     */
    public static final Map<String, String> AUDIT = createAuditEndpoints();

    /**
     * Gets all default endpoints merged into a single map.
     *
     * @return a map of all default endpoints with hierarchical keys
     */
    public static Map<String, String> getAllDefaults() {
        Map<String, String> defaults = new HashMap<>();
        defaults.putAll(WORKLOAD);
        defaults.putAll(OAUTH2);
        defaults.putAll(POLICY);
        defaults.putAll(BINDING);
        defaults.putAll(AUDIT);
        return defaults;
    }

    private static Map<String, String> createWorkloadEndpoints() {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("workload.issue", "/api/v1/workloads/token/issue");
        endpoints.put("workload.revoke", "/api/v1/workloads/revoke");
        endpoints.put("workload.get", "/api/v1/workloads/get");
        return endpoints;
    }

    private static Map<String, String> createOAuth2Endpoints() {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("oauth2.authorize", "/oauth2/authorize");
        endpoints.put("oauth2.token", "/oauth2/token");
        endpoints.put("oauth2.par", "/par");
        endpoints.put("oauth2.dcr", "/oauth2/register");
        endpoints.put("oauth2.userinfo", "/oauth2/userinfo");
        endpoints.put("oauth2.logout", "/oauth2/logout");
        return endpoints;
    }

    private static Map<String, String> createPolicyEndpoints() {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("policy.registry", "/api/v1/policies");
        endpoints.put("policy.delete", "/api/v1/policies/{policyId}");
        endpoints.put("policy.get", "/api/v1/policies/{policyId}");
        return endpoints;
    }

    private static Map<String, String> createBindingEndpoints() {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("binding.registry", "/api/v1/bindings");
        endpoints.put("binding.get", "/api/v1/bindings/{bindingInstanceId}");
        endpoints.put("binding.delete", "/api/v1/bindings/{bindingInstanceId}");
        return endpoints;
    }

    private static Map<String, String> createAuditEndpoints() {
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("event.get", "/api/v1/audit/events/{eventId}");
        endpoints.put("event.list", "/api/v1/audit/events");
        return endpoints;
    }

}