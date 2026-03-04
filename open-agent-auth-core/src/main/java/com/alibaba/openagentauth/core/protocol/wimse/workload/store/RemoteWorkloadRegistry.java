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
package com.alibaba.openagentauth.core.protocol.wimse.workload.store;

import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.core.type.TypeReference;
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
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Remote implementation of WorkloadRegistry that communicates with an Agent IDP
 * via REST API.
 * <p>
 * This implementation enables distributed workload identity querying, allowing Agents
 * to read workload information from a centralized Agent IDP. Write operations
 * (save, delete) are not supported since workload management should only be
 * performed on the Agent IDP.
 * </p>
 * <p>
 * <b>Architecture:</b></p>
 * <pre>
 * ┌─────────────────┐         HTTP          ┌──────────────────────┐
 * │     Agent       │ ────────────────────▶ │     Agent IDP        │
 * │ (RemoteWorkload │   POST /api/v1/       │   (Local InMemory    │
 * │  Registry)      │   workloads/list      │    WorkloadRegistry) │
 * └─────────────────┘                       └──────────────────────┘
 * </pre>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe. The underlying HttpClient is thread-safe,
 * and all operations are stateless.
 * </p>
 *
 * @see WorkloadRegistry
 * @since 1.0
 */
public class RemoteWorkloadRegistry implements WorkloadRegistry {

    private static final Logger logger = LoggerFactory.getLogger(RemoteWorkloadRegistry.class);

    private static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private final HttpClient httpClient;
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * Creates a new RemoteWorkloadRegistry.
     *
     * @param serviceEndpointResolver the service endpoint resolver for resolving
     *                                Agent IDP workload endpoints
     */
    public RemoteWorkloadRegistry(ServiceEndpointResolver serviceEndpointResolver) {
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(
                serviceEndpointResolver, "Service endpoint resolver");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        logger.info("RemoteWorkloadRegistry initialized with service endpoint resolver");
    }

    @Override
    public void save(WorkloadInfo workloadInfo) {
        throw new UnsupportedOperationException(
                "Remote workload saving is not supported. "
                        + "Workloads should be managed on the Agent IDP.");
    }

    @Override
    public Optional<WorkloadInfo> findById(String workloadId) {
        if (ValidationUtils.isNullOrEmpty(workloadId)) {
            throw new IllegalArgumentException("Workload ID cannot be null or empty");
        }
        logger.debug("Retrieving workload with ID: {} from remote Agent IDP", workloadId);

        try {
            String url = serviceEndpointResolver.resolveConsumer(
                    "agent-idp", "workload.retrieve");
            if (url == null) {
                logger.error("Failed to resolve endpoint: workload.retrieve for service agent-idp");
                return Optional.empty();
            }

            Map<String, String> requestMap = Map.of("workloadId", workloadId);
            String requestBody = objectMapper.writeValueAsString(requestMap);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            return switch (response.statusCode()) {
                case 200 -> {
                    logger.debug("Successfully retrieved workload: {}", workloadId);
                    WorkloadInfo workloadInfo = objectMapper.readValue(
                            response.body(), WorkloadInfo.class);
                    yield Optional.ofNullable(workloadInfo);
                }
                case 404 -> {
                    logger.debug("Workload not found on remote Agent IDP: {}", workloadId);
                    yield Optional.empty();
                }
                default -> {
                    logger.error("Failed to retrieve workload: HTTP {} - {}",
                            response.statusCode(), response.body());
                    yield Optional.empty();
                }
            };
        } catch (Exception e) {
            logger.error("Failed to retrieve workload from remote Agent IDP", e);
            return Optional.empty();
        }
    }

    @Override
    public void delete(String workloadId) {
        throw new UnsupportedOperationException(
                "Remote workload deletion is not supported. "
                        + "Workloads should be managed on the Agent IDP.");
    }

    @Override
    public boolean exists(String workloadId) {
        return findById(workloadId).isPresent();
    }

    @Override
    public Optional<WorkloadInfo> findByWorkloadUniqueKey(String workloadUniqueKey) {
        logger.warn("Remote workload retrieval by unique key is not yet supported. "
                + "Use findById() instead.");
        return Optional.empty();
    }

    @Override
    public void revoke(String workloadId) {
        throw new UnsupportedOperationException(
                "Remote workload revocation is not supported. "
                        + "Workloads should be managed on the Agent IDP.");
    }

    @Override
    public List<WorkloadInfo> listAll() {
        logger.debug("Listing all workloads from remote Agent IDP");

        try {
            String url = serviceEndpointResolver.resolveConsumer(
                    "agent-idp", "workload.list");
            if (url == null) {
                logger.error("Failed to resolve endpoint: workload.list for service agent-idp");
                return List.of();
            }

            Map<String, Object> requestMap = Map.of("page", 1, "size", 100);
            String requestBody = objectMapper.writeValueAsString(requestMap);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                logger.debug("Successfully retrieved workloads from remote Agent IDP");
                return parseWorkloadListResponse(response.body());
            }

            logger.error("Failed to list workloads: HTTP {} - {}",
                    response.statusCode(), response.body());
            return List.of();
        } catch (Exception e) {
            logger.error("Failed to list workloads from remote Agent IDP", e);
            return List.of();
        }
    }

    /**
     * Parses the workload list response from the Agent IDP.
     * <p>
     * The response is expected to be a PageResponse containing an "items" field
     * with the list of workloads. The items are WorkloadResponse objects from the
     * Agent IDP's WorkloadController, which are mapped back to WorkloadInfo objects.
     * </p>
     *
     * @param responseBody the JSON response body
     * @return the list of workload info objects
     */
    private List<WorkloadInfo> parseWorkloadListResponse(String responseBody) {
        try {
            Map<String, Object> pageResponse = objectMapper.readValue(
                    responseBody, new TypeReference<>() {});
            Object itemsObj = pageResponse.get("items");
            if (itemsObj == null) {
                return List.of();
            }
            String itemsJson = objectMapper.writeValueAsString(itemsObj);
            return objectMapper.readValue(itemsJson, new TypeReference<>() {});
        } catch (Exception e) {
            logger.error("Failed to parse workload list response", e);
            return List.of();
        }
    }
}
