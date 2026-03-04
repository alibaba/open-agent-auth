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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.page.PageRequest;
import com.alibaba.openagentauth.core.model.page.PageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * REST API controller for Audit operations.
 * <p>
 * This controller exposes the AuditService functionality via RESTful endpoints,
 * enabling audit event management and testing. It is only enabled when the
 * AuditService bean is configured, allowing for data testing and audit trail
 * verification.
 * </p>
 * <p>
 * <b>Endpoints:</b></p>
 * <ul>
 *   <li>POST /api/v1/audit/events/get - Get an audit event by ID</li>
 *   <li>POST /api/v1/audit/events/list - Get audit events with optional time range filters</li>
 * </ul>
 *
 * @see AuditService
 * @see AuditEvent
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(AuditService.class)
public class AuditController {

    private static final Logger logger = LoggerFactory.getLogger(AuditController.class);

    private final AuditService auditService;

    /**
     * Creates a new AuditController.
     * <p>
     * This controller is only created when AuditService bean is available,
     * ensuring it's only enabled in services that have audit functionality.
     * </p>
     *
     * @param auditService the audit service (optional)
     */
    public AuditController(Optional<AuditService> auditService) {
        this.auditService = auditService.orElse(null);
        if (this.auditService != null) {
            logger.info("AuditController initialized - audit functionality is enabled");
        } else {
            logger.warn("AuditController initialized - audit service is not available");
        }
    }

    /**
     * Retrieves an audit event by its unique identifier.
     *
     * @param request the request containing event ID
     * @return the audit event if found, 404 if not found
     */
    @PostMapping("${open-agent-auth.capabilities.audit.endpoints.event.retrieve:/api/v1/audit/events/get}")
    public ResponseEntity<AuditEvent> getEvent(@RequestBody EventIdRequest request) {
        logger.debug("Getting audit event with ID: {}", request.getEventId());

        try {
            AuditEvent event = auditService.getEvent(request.getEventId());
            if (event != null) {
                return ResponseEntity.ok(event);
            } else {
                logger.warn("Audit event not found: {}", request.getEventId());
                return ResponseEntity.notFound().build();
            }
        } catch (AuditStorageException e) {
            logger.error("Failed to retrieve audit event: {}", request.getEventId(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Retrieves audit events within a specified time range.
     * <p>
     * If only startTime is provided, returns events from that time onwards.
     * If only endTime is provided, returns events up to that time.
     * If both are provided, returns events in the specified range.
     * If neither is provided, returns a bad request.
     * </p>
     *
     * @param request the request containing time range parameters
     * @return a list of audit events in the specified range
     */
    @PostMapping("${open-agent-auth.capabilities.audit.endpoints.event.list:/api/v1/audit/events/list}")
    public ResponseEntity<PageResponse<AuditEvent>> getEventsByTimeRange(@RequestBody TimeRangeRequest request) {
        
        if (request.getStartTime() == null && request.getEndTime() == null) {
            logger.warn("Both startTime and endTime are null, returning bad request");
            return ResponseEntity.badRequest().build();
        }

        // Set default values for null parameters
        Instant actualStartTime = request.getStartTime() != null ? request.getStartTime() : Instant.EPOCH;
        Instant actualEndTime = request.getEndTime() != null ? request.getEndTime() : Instant.now().plusSeconds(86400);

        logger.debug("Getting audit events between {} and {}", actualStartTime, actualEndTime);

        try {
            List<AuditEvent> allEvents = auditService.getEventsByTimeRange(actualStartTime, actualEndTime);
            logger.debug("Retrieved {} audit events total", allEvents.size());

            PageRequest pageRequest = new PageRequest(request.getPage(), request.getSize());
            PageResponse<AuditEvent> pageResponse = PageResponse.of(allEvents, pageRequest);
            logger.debug("Returning page {}/{} with {} events",
                    pageResponse.getPage(), pageResponse.getTotalPages(), pageResponse.getItems().size());
            return ResponseEntity.ok(pageResponse);
        } catch (AuditStorageException e) {
            logger.error("Failed to retrieve audit events by time range", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Request DTO for event ID.
     */
    public static class EventIdRequest {
        private String eventId;

        public String getEventId() {
            return eventId;
        }

        public void setEventId(String eventId) {
            this.eventId = eventId;
        }
    }

    /**
     * Request DTO for time range query with pagination support.
     */
    public static class TimeRangeRequest {
        private Instant startTime;
        private Instant endTime;
        private Integer page;
        private Integer size;

        public Instant getStartTime() {
            return startTime;
        }

        public void setStartTime(Instant startTime) {
            this.startTime = startTime;
        }

        public Instant getEndTime() {
            return endTime;
        }

        public void setEndTime(Instant endTime) {
            this.endTime = endTime;
        }

        public Integer getPage() {
            return page;
        }

        public void setPage(Integer page) {
            this.page = page;
        }

        public Integer getSize() {
            return size;
        }

        public void setSize(Integer size) {
            this.size = size;
        }
    }
}