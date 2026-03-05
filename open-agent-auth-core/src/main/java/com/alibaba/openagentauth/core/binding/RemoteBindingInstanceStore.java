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
package com.alibaba.openagentauth.core.binding;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.fasterxml.jackson.databind.DeserializationFeature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Remote implementation of BindingInstanceStore that communicates with an Authorization Server
 * via REST API.
 * <p>
 * This implementation enables distributed binding management, allowing Resource Servers
 * to query binding instances from a centralized Authorization Server. All operations are performed
 * through HTTP requests to the BindingInstanceController endpoints.
 * </p>
 * <p>
 * <b>Architecture:</b></p>
 * <pre>
 * ┌─────────────────┐         HTTP          ┌──────────────────────────┐
 * │ Resource Server │ ────────────────────▶ │ Authorization Server     │
 * │  (RemoteBinding │   POST /api/v1/       │   (Local InMemory        │
 * │   InstanceStore)│   bindings/get        │    BindingInstanceStore) │
 * └─────────────────┘                       └──────────────────────────┘
 * </pre>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe. The underlying HttpClient is thread-safe,
 * and all operations are stateless.
 * </p>
 *
 * @see BindingInstanceStore
 * @since 1.0
 */
public class RemoteBindingInstanceStore implements BindingInstanceStore {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(RemoteBindingInstanceStore.class);

    /**
     * The ObjectMapper for parsing JSON.
     * Configured with JavaTimeModule to support Java 8 date/time types
     * and FAIL_ON_UNKNOWN_PROPERTIES disabled to ignore unknown fields.
     */
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    /**
     * The HTTP client for making requests.
     */
    private final HttpClient httpClient;

    /**
     * The service endpoint resolver for resolving endpoint URLs.
     */
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * Creates a new RemoteBindingInstanceStore.
     *
     * @param serviceEndpointResolver the service endpoint resolver
     */
    public RemoteBindingInstanceStore(ServiceEndpointResolver serviceEndpointResolver) {
        // Validate service endpoint resolver
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");

        // Initialize HTTP client with timeout
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        logger.info("RemoteBindingInstanceStore initialized with service endpoint resolver");
    }

    @Override
    public void store(BindingInstance bindingInstance) {
        logger.warn("Remote binding instance storage is not supported. " +
                "Bindings should be stored on the Authorization Server.");
        throw new UnsupportedOperationException("Remote binding instance storage is not supported. " +
                "Please store bindings on the Authorization Server.");
    }

    @Override
    public BindingInstance retrieve(String bindingInstanceId) {
        // Ensure binding instance ID is not null or empty
        if (ValidationUtils.isNullOrEmpty(bindingInstanceId)) {
            throw new IllegalArgumentException("Binding instance ID cannot be null or empty");
        }
        logger.debug("Retrieving binding instance with ID: {} from remote server", bindingInstanceId);

        try {
            // Build the HTTP request
            String url = serviceEndpointResolver.resolveConsumer("authorization-server", "binding.retrieve");
            if (url == null) {
                logger.error("Failed to resolve endpoint: binding.retrieve for service authorization-server");
                return null;
            }
            String requestBody = objectMapper.writeValueAsString(
                    java.util.Map.of("bindingInstanceId", bindingInstanceId));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            logger.debug("Sending POST request to: {}", url);

            // Send the request
            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            // Handle the response
            return switch (response.statusCode()) {
                case 200 -> {
                    logger.debug("Successfully retrieved binding instance: {}", bindingInstanceId);
                    yield parseBindingInstanceResponse(response.body());
                }
                case 404 -> {
                    logger.debug("Binding instance not found on remote server: {}", bindingInstanceId);
                    yield null;
                }
                default -> {
                    String errorMsg = String.format(
                            "Failed to retrieve binding instance: HTTP %d - %s",
                            response.statusCode(), response.body()
                    );
                    logger.error(errorMsg);
                    yield null;
                }
            };

        } catch (Exception e) {
            logger.error("Failed to retrieve binding instance from remote server", e);
            return null;
        }
    }

    @Override
    public BindingInstance retrieveByUserIdentity(String userIdentity) {
        logger.warn("Remote binding instance retrieval by user identity is not supported.");
        return null;
    }

    @Override
    public BindingInstance retrieveByWorkloadIdentity(String workloadIdentity) {
        logger.warn("Remote binding instance retrieval by workload identity is not supported.");
        return null;
    }

    @Override
    public void update(BindingInstance bindingInstance) {
        logger.warn("Remote binding instance update is not supported. " +
                "Bindings should be updated on the Authorization Server.");
        throw new UnsupportedOperationException("Remote binding instance update is not supported");
    }

    @Override
    public void delete(String bindingInstanceId) {
        logger.warn("Remote binding instance deletion is not supported. " +
                "Bindings should be deleted on the Authorization Server.");
        throw new UnsupportedOperationException("Remote binding instance deletion is not supported");
    }

    @Override
    public boolean exists(String bindingInstanceId) {
        return retrieve(bindingInstanceId) != null;
    }

    @Override
    public boolean isValid(String bindingInstanceId) {
        BindingInstance binding = retrieve(bindingInstanceId);
        return binding != null && !binding.isExpired();
    }

    @Override
    public int deleteExpired() {
        logger.warn("Remote binding instance deletion is not supported. " +
                "Expired bindings should be deleted on the Authorization Server.");
        return 0;
    }

    @Override
    public java.util.List<BindingInstance> listAll() {
        logger.debug("Listing all binding instances from remote server");

        try {
            String url = serviceEndpointResolver.resolveConsumer("authorization-server", "binding.list");
            if (url == null) {
                logger.error("Failed to resolve endpoint: binding.list for service authorization-server");
                return java.util.List.of();
            }

            String requestBody = objectMapper.writeValueAsString(
                    java.util.Map.of("page", 1, "size", 100));
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            logger.debug("Sending POST request to: {}", url);

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                logger.debug("Successfully retrieved binding instances from remote server");
                return parseBindingInstanceListResponse(response.body());
            }

            logger.error("Failed to list binding instances: HTTP {} - {}",
                    response.statusCode(), response.body());
            return java.util.List.of();
        } catch (Exception e) {
            logger.error("Failed to list binding instances from remote server", e);
            return java.util.List.of();
        }
    }

    /**
     * Parses the binding instance list response from the Authorization Server.
     * <p>
     * The response is expected to be a PageResponse containing an "items" field
     * with the list of binding instances.
     * </p>
     *
     * @param responseBody the JSON response body
     * @return the list of binding instances
     */
    private java.util.List<BindingInstance> parseBindingInstanceListResponse(String responseBody) {
        try {
            com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>> mapType =
                    new com.fasterxml.jackson.core.type.TypeReference<>() {};
            java.util.Map<String, Object> pageResponse = objectMapper.readValue(responseBody, mapType);
            Object itemsObj = pageResponse.get("items");
            if (itemsObj == null) {
                return java.util.List.of();
            }
            String itemsJson = objectMapper.writeValueAsString(itemsObj);
            com.fasterxml.jackson.core.type.TypeReference<java.util.List<BindingInstance>> listType =
                    new com.fasterxml.jackson.core.type.TypeReference<>() {};
            return objectMapper.readValue(itemsJson, listType);
        } catch (Exception e) {
            logger.error("Failed to parse binding instance list response", e);
            return java.util.List.of();
        }
    }

    /**
     * Parses the BindingInstance response from the Authorization Server.
     *
     * @param responseBody the JSON response body
     * @return the BindingInstance object
     */
    private BindingInstance parseBindingInstanceResponse(String responseBody) {
        try {
            BindingInstance binding = objectMapper.readValue(responseBody, BindingInstance.class);
            logger.debug("Successfully parsed binding instance: {}", binding.getBindingInstanceId());
            return binding;
        } catch (Exception e) {
            logger.error("Failed to parse binding instance response", e);
            return null;
        }
    }
}
