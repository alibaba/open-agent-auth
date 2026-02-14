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
package com.alibaba.openagentauth.core.policy.registry;

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.exception.policy.PolicyRegistrationException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
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
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Remote implementation of PolicyRegistry that communicates with an Authorization Server
 * via REST API.
 * <p>
 * This implementation enables distributed policy management, allowing Resource Servers
 * to query policies from a centralized Authorization Server. All operations are performed
 * through HTTP requests to the PolicyRegistryController endpoints.
 * </p>
 * <p>
 * <b>Architecture:</b></p>
 * <pre>
 * ┌─────────────────┐         HTTP          ┌──────────────────────┐
 * │ Resource Server │ ────────────────────▶ │ Authorization Server │
 * │  (RemotePolicy  │   GET /api/v1/        │   (Local InMemory    │
 * │   Registry)     │   policies/{id}       │    PolicyRegistry)   │
 * └─────────────────┘                       └──────────────────────┘
 * </pre>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe. The underlying RestTemplate is thread-safe,
 * and all operations are stateless.
 * </p>
 *
 * @see PolicyRegistry
 * @since 1.0
 */
public class RemotePolicyRegistry implements PolicyRegistry {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(RemotePolicyRegistry.class);

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
     * Creates a new RemotePolicyRegistry.
     *
     * @param serviceEndpointResolver the service endpoint resolver
     */
    public RemotePolicyRegistry(ServiceEndpointResolver serviceEndpointResolver) {

        // Validate service endpoint resolver
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(serviceEndpointResolver, "Service endpoint resolver");

        // Initialize HTTP client with timeout
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        logger.info("RemotePolicyRegistry initialized with service endpoint resolver");
    }

    @Override
    public PolicyRegistration register(
            String regoPolicy,
            String description,
            String createdBy,
            Instant expirationTime
    ) throws PolicyRegistrationException {
        logger.warn("Remote policy registration is not supported. " +
                "Policies should be registered on the Authorization Server.");
        throw new PolicyRegistrationException("Remote policy registration is not supported. " +
                "Please register policies on the Authorization Server.");
    }

    @Override
    public Policy get(String policyId) throws PolicyNotFoundException {

        // Ensure policy ID is not null or empty
        if (ValidationUtils.isNullOrEmpty(policyId)) {
            throw new IllegalArgumentException("Policy ID cannot be null or empty");
        }
        logger.debug("Retrieving policy with ID: {} from remote server", policyId);

        try {
            // Build the HTTP request
            String urlTemplate = serviceEndpointResolver.resolveConsumer("authorization-server", "policy.get");
            // Replace path parameter {policyId} with actual value
            String url = urlTemplate.replace("{policyId}", policyId);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            logger.debug("Sending GET request to: {}", url);

            // Send the request
            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            // Handle the response
            return switch (response.statusCode()) {
                case 200 -> {
                    logger.debug("Successfully retrieved policy: {}", policyId);
                    yield parsePolicyResponse(response.body());
                }
                case 404 -> {
                    logger.warn("Policy not found on remote server: {}", policyId);
                    throw new PolicyNotFoundException("Policy not found: " + policyId);
                }
                default -> {
                    String errorMsg = String.format(
                            "Failed to retrieve policy: HTTP %d - %s",
                            response.statusCode(), response.body()
                    );
                    logger.error(errorMsg);
                    throw new PolicyNotFoundException(errorMsg);
                }
            };

        } catch (PolicyNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to retrieve policy from remote server", e);
            throw new PolicyNotFoundException("Failed to retrieve policy: " + e.getMessage(), e);
        }
    }

    /**
     * Parses the Policy response from the Authorization Server.
     *
     * @param responseBody the JSON response body
     * @return the Policy object
     * @throws PolicyNotFoundException if parsing fails
     */
    private Policy parsePolicyResponse(String responseBody) throws PolicyNotFoundException {
        try {
            Policy policy = objectMapper.readValue(responseBody, Policy.class);
            logger.debug("Successfully parsed policy: {}", policy.getPolicyId());
            return policy;
        } catch (Exception e) {
            logger.error("Failed to parse policy response", e);
            throw new PolicyNotFoundException("Failed to parse policy response: " + e.getMessage(), e);
        }
    }

    @Override
    public Optional<Policy> get(String policyId, boolean includeExpired) {
        try {
            return Optional.of(get(policyId));
        } catch (PolicyNotFoundException e) {
            return Optional.empty();
        }
    }

    @Override
    public Policy update(String policyId, String regoPolicy, String description) throws PolicyNotFoundException {
        logger.warn("Remote policy update is not supported. Policies should be updated on the Authorization Server.");
        throw new PolicyNotFoundException("Remote policy update is not supported");
    }

    @Override
    public void delete(String policyId) throws PolicyNotFoundException {
        logger.warn("Remote policy deletion is not supported. Policies should be deleted on the Authorization Server.");
        throw new PolicyNotFoundException("Remote policy deletion is not supported");
    }

    @Override
    public boolean exists(String policyId) {
        logger.warn("Remote policy existence check is not supported.");
        return false;
    }

    @Override
    public List<Policy> listAll() {
        logger.warn("Remote policy listing is not supported.");
        return List.of();
    }

    @Override
    public List<Policy> listByCreator(String createdBy) {
        logger.warn("Remote policy listing by creator is not supported.");
        return List.of();
    }

    @Override
    public List<Policy> listExpired() {
        logger.warn("Remote policy listing of expired policies is not supported.");
        return List.of();
    }

    @Override
    public int cleanupExpired() {
        logger.warn("Remote policy cleanup is not supported.");
        return 0;
    }

    @Override
    public int size() {
        logger.warn("Remote policy size is not supported.");
        return 0;
    }
}