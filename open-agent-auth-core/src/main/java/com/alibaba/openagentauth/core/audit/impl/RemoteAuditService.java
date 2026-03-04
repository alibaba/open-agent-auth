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
package com.alibaba.openagentauth.core.audit.impl;

import com.alibaba.openagentauth.core.audit.api.AuditProcessor;
import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
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
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Remote implementation of AuditService that communicates with an Authorization Server
 * via REST API.
 * <p>
 * This implementation enables distributed audit event querying, allowing Agents and
 * Resource Servers to read audit events from a centralized Authorization Server.
 * Write operations (logEvent, logEventAsync) are not supported since audit events
 * should only be created on the Authorization Server.
 * </p>
 * <p>
 * <b>Architecture:</b></p>
 * <pre>
 * ┌─────────────────┐         HTTP          ┌──────────────────────┐
 * │     Agent /      │ ────────────────────▶ │ Authorization Server │
 * │ Resource Server  │   POST /api/v1/       │   (Local InMemory    │
 * │ (RemoteAudit     │   audit/events/list   │    AuditService)     │
 * │  Service)        │                       │                      │
 * └─────────────────┘                       └──────────────────────┘
 * </pre>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe. The underlying HttpClient is thread-safe,
 * and all operations are stateless.
 * </p>
 *
 * @see AuditService
 * @since 1.0
 */
public class RemoteAuditService implements AuditService {

    private static final Logger logger = LoggerFactory.getLogger(RemoteAuditService.class);

    private static final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    private final HttpClient httpClient;
    private final ServiceEndpointResolver serviceEndpointResolver;

    /**
     * Creates a new RemoteAuditService.
     *
     * @param serviceEndpointResolver the service endpoint resolver for resolving
     *                                Authorization Server audit endpoints
     */
    public RemoteAuditService(ServiceEndpointResolver serviceEndpointResolver) {
        this.serviceEndpointResolver = ValidationUtils.validateNotNull(
                serviceEndpointResolver, "Service endpoint resolver");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        logger.info("RemoteAuditService initialized with service endpoint resolver");
    }

    @Override
    public void logEvent(AuditEvent event) throws AuditStorageException {
        throw new UnsupportedOperationException(
                "Remote audit event logging is not supported. "
                        + "Audit events should be created on the Authorization Server.");
    }

    @Override
    public void logEventAsync(AuditEvent event) {
        throw new UnsupportedOperationException(
                "Remote audit event logging is not supported. "
                        + "Audit events should be created on the Authorization Server.");
    }

    @Override
    public AuditEvent getEvent(String eventId) throws AuditStorageException {
        if (ValidationUtils.isNullOrEmpty(eventId)) {
            throw new IllegalArgumentException("Event ID cannot be null or empty");
        }
        logger.debug("Retrieving audit event with ID: {} from remote server", eventId);

        try {
            String url = serviceEndpointResolver.resolveConsumer(
                    "authorization-server", "event.retrieve");
            if (url == null) {
                throw new AuditStorageException(
                        "Failed to resolve endpoint: event.retrieve for service authorization-server");
            }

            Map<String, String> requestMap = Map.of("eventId", eventId);
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
                    logger.debug("Successfully retrieved audit event: {}", eventId);
                    yield objectMapper.readValue(response.body(), AuditEvent.class);
                }
                case 404 -> {
                    logger.debug("Audit event not found on remote server: {}", eventId);
                    yield null;
                }
                default -> {
                    logger.error("Failed to retrieve audit event: HTTP {} - {}",
                            response.statusCode(), response.body());
                    yield null;
                }
            };
        } catch (AuditStorageException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to retrieve audit event from remote server", e);
            throw new AuditStorageException("Failed to retrieve audit event remotely", e);
        }
    }

    @Override
    public List<AuditEvent> getEventsByTimeRange(Instant startTime, Instant endTime)
            throws AuditStorageException {
        logger.debug("Retrieving audit events between {} and {} from remote server",
                startTime, endTime);

        try {
            String url = serviceEndpointResolver.resolveConsumer(
                    "authorization-server", "event.list");
            if (url == null) {
                throw new AuditStorageException(
                        "Failed to resolve endpoint: event.list for service authorization-server");
            }

            Map<String, Object> requestMap = new HashMap<>();
            requestMap.put("startTime", startTime);
            requestMap.put("endTime", endTime);
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
                logger.debug("Successfully retrieved audit events from remote server");
                return parseAuditEventListResponse(response.body());
            }

            logger.error("Failed to retrieve audit events: HTTP {} - {}",
                    response.statusCode(), response.body());
            return List.of();
        } catch (AuditStorageException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to retrieve audit events from remote server", e);
            throw new AuditStorageException("Failed to retrieve audit events remotely", e);
        }
    }

    @Override
    public List<AuditEvent> getEventsByUser(String userId) throws AuditStorageException {
        logger.warn("Remote audit event retrieval by user is not yet supported. "
                + "Use getEventsByTimeRange() instead.");
        return List.of();
    }

    @Override
    public List<AuditEvent> getEventsByAgent(String agentId) throws AuditStorageException {
        logger.warn("Remote audit event retrieval by agent is not yet supported. "
                + "Use getEventsByTimeRange() instead.");
        return List.of();
    }

    @Override
    public List<AuditEvent> getEventsBySession(String sessionId) throws AuditStorageException {
        logger.warn("Remote audit event retrieval by session is not yet supported. "
                + "Use getEventsByTimeRange() instead.");
        return List.of();
    }

    @Override
    public List<AuditEvent> getEventsByType(AuditEventType eventType) throws AuditStorageException {
        logger.warn("Remote audit event retrieval by type is not yet supported. "
                + "Use getEventsByTimeRange() instead.");
        return List.of();
    }

    @Override
    public List<AuditEvent> getEventsBySeverity(AuditSeverity severity) throws AuditStorageException {
        logger.warn("Remote audit event retrieval by severity is not yet supported. "
                + "Use getEventsByTimeRange() instead.");
        return List.of();
    }

    @Override
    public void registerProcessor(AuditProcessor processor) {
        throw new UnsupportedOperationException(
                "Remote audit processor registration is not supported.");
    }

    @Override
    public void unregisterProcessor(AuditProcessor processor) {
        throw new UnsupportedOperationException(
                "Remote audit processor unregistration is not supported.");
    }

    @Override
    public long getEventCount() throws AuditStorageException {
        logger.warn("Remote audit event count is not supported.");
        return 0;
    }

    /**
     * Parses the audit event list response from the Authorization Server.
     * <p>
     * The response is expected to be a PageResponse containing an "items" field
     * with the list of audit events.
     * </p>
     *
     * @param responseBody the JSON response body
     * @return the list of audit events
     */
    private List<AuditEvent> parseAuditEventListResponse(String responseBody) {
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
            logger.error("Failed to parse audit event list response", e);
            return List.of();
        }
    }
}
