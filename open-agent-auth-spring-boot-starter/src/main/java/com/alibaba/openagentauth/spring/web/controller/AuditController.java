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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
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
 *   <li>GET /api/v1/audit/events/{eventId} - Get an audit event by ID</li>
 *   <li>GET /api/v1/audit/events - Get audit events with optional time range filters</li>
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
     * @param eventId the unique event identifier
     * @return the audit event if found, 404 if not found
     */
    @GetMapping("${open-agent-auth.capabilities.audit.endpoints.event.get:/api/v1/audit/events/{eventId}}")
    public ResponseEntity<AuditEvent> getEvent(@PathVariable String eventId) {
        logger.debug("Getting audit event with ID: {}", eventId);

        try {
            AuditEvent event = auditService.getEvent(eventId);
            if (event != null) {
                return ResponseEntity.ok(event);
            } else {
                logger.warn("Audit event not found: {}", eventId);
                return ResponseEntity.notFound().build();
            }
        } catch (AuditStorageException e) {
            logger.error("Failed to retrieve audit event: {}", eventId, e);
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
     * @param startTime the start of the time range (inclusive)
     * @param endTime   the end of the time range (inclusive)
     * @return a list of audit events in the specified range
     */
    @GetMapping("${open-agent-auth.capabilities.audit.endpoints.events.list:/api/v1/audit/events}")
    public ResponseEntity<List<AuditEvent>> getEventsByTimeRange(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant startTime,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant endTime) {
        
        if (startTime == null && endTime == null) {
            logger.warn("Both startTime and endTime are null, returning bad request");
            return ResponseEntity.badRequest().build();
        }

        // Set default values for null parameters
        Instant actualStartTime = startTime != null ? startTime : Instant.EPOCH;
        Instant actualEndTime = endTime != null ? endTime : Instant.now().plusSeconds(86400);

        logger.debug("Getting audit events between {} and {}", actualStartTime, actualEndTime);

        try {
            List<AuditEvent> events = auditService.getEventsByTimeRange(actualStartTime, actualEndTime);
            logger.debug("Retrieved {} audit events", events.size());
            if (!events.isEmpty()) {
                logger.debug("Event types: {}", events.stream().map(e -> e.getEventType().toString()).toList());
            }
            return ResponseEntity.ok(events);
        } catch (AuditStorageException e) {
            logger.error("Failed to retrieve audit events by time range", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}