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
package com.alibaba.openagentauth.core.resolver;

import java.util.Map;

/**
 * Service endpoint resolver for constructing and resolving service endpoints.
 * <p>
 * This interface provides methods to resolve provider endpoints (endpoints exposed by
 * the current application) and consumer endpoints (endpoints exposed by downstream services).
 * It handles the construction of full URLs by combining base URLs with endpoint paths.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>
 * // Resolve provider endpoint (current application's endpoint)
 * String url = endpointResolver.resolveProvider("workload.issue");
 * // Returns: http://localhost:8082/api/v1/workloads/token/issue
 * 
 * // Resolve consumer endpoint (downstream service endpoint)
 * String url = endpointResolver.resolveConsumer("agent-idp", "workload.issue");
 * // Returns: http://localhost:8082/api/v1/workloads/token/issue
 * 
 * // Resolve with path variables
 * Map<String, String> pathVars = Map.of("policyId", "123");
 * String url = endpointResolver.resolveConsumer("authorization-server", "policy.registry", pathVars);
 * // Returns: http://localhost:8085/api/v1/policies/123
 * </pre>
 *
 * @since 1.0
 */
public interface ServiceEndpointResolver {

    /**
     * Resolves a provider endpoint URL.
     * <p>
     * Provider endpoints are endpoints exposed by the current application.
     * </p>
     *
     * @param endpointKey the endpoint key (e.g., "workload.issue", "oauth2.authorize")
     * @return the full URL, or null if the endpoint is not configured
     * @throws IllegalArgumentException if endpointKey is null or empty
     */
    String resolveProvider(String endpointKey);

    /**
     * Resolves a consumer endpoint URL.
     * <p>
     * Consumer endpoints are endpoints exposed by downstream services.
     * </p>
     *
     * @param serviceName the service name (e.g., "agent-idp", "authorization-server")
     * @param endpointKey the endpoint key (e.g., "workload.issue", "oauth2.token")
     * @return the full URL, or null if the service or endpoint is not configured
     * @throws IllegalArgumentException if serviceName or endpointKey is null or empty
     */
    String resolveConsumer(String serviceName, String endpointKey);

    /**
     * Resolves a consumer endpoint URL with path variables.
     * <p>
     * Path variables are replaced in the endpoint path using the format {variableName}.
     * For example, if the endpoint path is "/api/v1/policies/{policyId}" and pathVariables
     * contains {"policyId": "123"}, the resulting path will be "/api/v1/policies/123".
     * </p>
     *
     * @param serviceName the service name (e.g., "authorization-server")
     * @param endpointKey the endpoint key (e.g., "policy.registry")
     * @param pathVariables the path variables to replace in the endpoint path
     * @return the full URL with path variables replaced, or null if the service or endpoint is not configured
     * @throws IllegalArgumentException if serviceName or endpointKey is null or empty
     */
    String resolveConsumer(String serviceName, String endpointKey, Map<String, String> pathVariables);

    /**
     * Resolves a consumer endpoint URL with path variables and query parameters.
     * <p>
     * Path variables are replaced in the endpoint path using the format {variableName}.
     * Query parameters are appended to the URL.
     * </p>
     *
     * @param serviceName the service name (e.g., "authorization-server")
     * @param endpointKey the endpoint key (e.g., "policy.registry")
     * @param pathVariables the path variables to replace in the endpoint path
     * @param queryParams the query parameters to append to the URL
     * @return the full URL with path variables and query parameters, or null if the service or endpoint is not configured
     * @throws IllegalArgumentException if serviceName or endpointKey is null or empty
     */
    String resolveConsumer(String serviceName, String endpointKey, Map<String, String> pathVariables, Map<String, String> queryParams);
}
