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
package com.alibaba.openagentauth.spring.util;

import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Default implementation of {@link ServiceEndpointResolver}.
 * <p>
 * This implementation resolves service endpoints by combining base URLs with endpoint paths
 * from the {@link ServiceProperties} configuration. It handles both provider endpoints
 * (endpoints exposed by the current application) and consumer endpoints (endpoints exposed
 * by downstream services).
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe as it does not maintain any mutable state
 * and relies on the immutable ServiceProperties configuration.
 * </p>
 *
 * @since 1.0
 */
public class DefaultServiceEndpointResolver implements ServiceEndpointResolver {

    private static final Logger logger = LoggerFactory.getLogger(DefaultServiceEndpointResolver.class);

    private final ServiceProperties serviceProperties;

    /**
     * Creates a new DefaultServiceEndpointResolver.
     *
     * @param serviceProperties the service properties configuration (must not be null)
     * @throws IllegalArgumentException if serviceProperties is null
     */
    public DefaultServiceEndpointResolver(ServiceProperties serviceProperties) {
        this.serviceProperties = ValidationUtils.validateNotNull(serviceProperties, "ServiceProperties cannot be null");
        logger.info("DefaultServiceEndpointResolver initialized");
    }

    @Override
    public String resolveProvider(String endpointKey) {
        ValidationUtils.validateNotEmpty(endpointKey, "Endpoint key");

        if (!serviceProperties.getProvider().isEnabled()) {
            logger.warn("Provider is disabled, cannot resolve endpoint: {}", endpointKey);
            return null;
        }

        String baseUrl = serviceProperties.getProvider().getBaseUrl();
        if (ValidationUtils.isNullOrEmpty(baseUrl)) {
            logger.warn("Provider base URL is not configured");
            return null;
        }

        String endpointPath = serviceProperties.getProvider().getEndpoints().get(endpointKey);
        if (ValidationUtils.isNullOrEmpty(endpointPath)) {
            logger.warn("Provider endpoint not found: {}", endpointKey);
            return null;
        }

        String url = buildUrl(baseUrl, endpointPath);
        logger.debug("Resolved provider endpoint: {} -> {}", endpointKey, url);
        return url;
    }

    @Override
    public String resolveConsumer(String serviceName, String endpointKey) {
        return resolveConsumer(serviceName, endpointKey, null, null);
    }

    @Override
    public String resolveConsumer(String serviceName, String endpointKey, Map<String, String> pathVariables) {
        return resolveConsumer(serviceName, endpointKey, pathVariables, null);
    }

    @Override
    public String resolveConsumer(String serviceName, String endpointKey, Map<String, String> pathVariables, Map<String, String> queryParams) {
        ValidationUtils.validateNotEmpty(serviceName, "Service name");
        ValidationUtils.validateNotEmpty(endpointKey, "Endpoint key");

        ServiceProperties.ConsumerServiceProperties service = serviceProperties.getConsumers().get(serviceName);
        if (service == null) {
            logger.warn("Consumer service not found: {}", serviceName);
            return null;
        }

        String baseUrl = service.getBaseUrl();
        if (ValidationUtils.isNullOrEmpty(baseUrl)) {
            logger.warn("Consumer service base URL is not configured: {}", serviceName);
            return null;
        }

        String endpointPath = service.getEndpoints().get(endpointKey);
        if (ValidationUtils.isNullOrEmpty(endpointPath)) {
            logger.warn("Consumer endpoint not found: {} in service {}", endpointKey, serviceName);
            return null;
        }

        // Replace path variables
        String resolvedPath = replacePathVariables(endpointPath, pathVariables);

        // Build URL
        String url = buildUrl(baseUrl, resolvedPath);

        // Append query parameters
        if (queryParams != null && !queryParams.isEmpty()) {
            url = appendQueryParameters(url, queryParams);
        }

        logger.debug("Resolved consumer endpoint: {}:{} -> {}", serviceName, endpointKey, url);
        return url;
    }

    /**
     * Builds a full URL by combining base URL and endpoint path.
     * <p>
     * This method ensures that the base URL does not end with a slash and the
     * endpoint path starts with a slash, then combines them.
     * </p>
     *
     * @param baseUrl the base URL
     * @param endpointPath the endpoint path
     * @return the full URL
     */
    private String buildUrl(String baseUrl, String endpointPath) {
        // Remove trailing slash from base URL
        String cleanBaseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        
        // Ensure endpoint path starts with slash
        String cleanPath = endpointPath.startsWith("/") ? endpointPath : "/" + endpointPath;
        
        return cleanBaseUrl + cleanPath;
    }

    /**
     * Replaces path variables in the endpoint path.
     * <p>
     * Path variables use the format {variableName}. For example, if the endpoint
     * path is "/api/v1/policies/{policyId}" and pathVariables contains {"policyId": "123"},
     * the resulting path will be "/api/v1/policies/123".
     * </p>
     *
     * @param endpointPath the endpoint path with placeholders
     * @param pathVariables the path variables to replace
     * @return the endpoint path with variables replaced
     */
    private String replacePathVariables(String endpointPath, Map<String, String> pathVariables) {
        if (pathVariables == null || pathVariables.isEmpty()) {
            return endpointPath;
        }

        String result = endpointPath;
        for (Map.Entry<String, String> entry : pathVariables.entrySet()) {
            String placeholder = "{" + entry.getKey() + "}";
            if (result.contains(placeholder)) {
                result = result.replace(placeholder, entry.getValue());
            }
        }

        return result;
    }

    /**
     * Appends query parameters to the URL.
     *
     * @param url the base URL
     * @param queryParams the query parameters
     * @return the URL with query parameters appended
     */
    private String appendQueryParameters(String url, Map<String, String> queryParams) {
        if (queryParams == null || queryParams.isEmpty()) {
            return url;
        }

        StringBuilder sb = new StringBuilder(url);
        sb.append("?");

        boolean first = true;
        for (Map.Entry<String, String> entry : queryParams.entrySet()) {
            if (!first) {
                sb.append("&");
            }
            sb.append(entry.getKey()).append("=").append(entry.getValue());
            first = false;
        }

        return sb.toString();
    }
}
