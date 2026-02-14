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
package com.alibaba.openagentauth.core.audit.api;

import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;

import java.time.Instant;
import java.util.List;

/**
 * Service interface for managing audit events.
 * <p>
 * This interface provides the main entry point for creating, storing,
 * and retrieving audit events. It orchestrates the interaction between
 * audit storage, filters, and processors to provide a comprehensive
 * audit logging solution.
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Single Responsibility:</b> This service focuses on audit event
 *       lifecycle management</li>
 *   <li><b>Interface Segregation:</b> Separate interfaces for storage,
 *       filtering, and processing</li>
 *   <li><b>Dependency Inversion:</b> Depends on abstractions (interfaces)
 *       rather than concrete implementations</li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * AuditService auditService = new DefaultAuditService(storage, processors);
 * 
 * AuditEvent event = AuditEvent.builder()
 *     .eventType(AuditEventType.AUTHORIZATION_GRANTED)
 *     .severity(AuditSeverity.INFO)
 *     .message("Authorization granted for user")
 *     .build();
 * 
 * auditService.logEvent(event);
 * }</pre>
 * </p>
 *
 * @see AuditEvent
 * @see AuditStorage
 * @see AuditFilter
 * @see AuditProcessor
 */
public interface AuditService {

    /**
     * Logs an audit event.
     * <p>
     * This method stores the event and applies all registered processors.
     * The event will be stored even if processing fails, ensuring that
     * audit records are not lost due to processing errors.
     * </p>
     *
     * @param event the audit event to log
     * @throws AuditStorageException if the event cannot be stored
     */
    void logEvent(AuditEvent event) throws AuditStorageException;

    /**
     * Logs an audit event asynchronously.
     * <p>
     * This method stores the event and applies all registered processors
     * asynchronously. This is useful for high-throughput scenarios where
     * blocking on audit logging would impact performance.
     * </p>
     *
     * @param event the audit event to log
     */
    void logEventAsync(AuditEvent event);

    /**
     * Retrieves an audit event by its unique identifier.
     *
     * @param eventId the unique event identifier
     * @return the audit event, or null if not found
     * @throws AuditStorageException if retrieval fails
     */
    AuditEvent getEvent(String eventId) throws AuditStorageException;

    /**
     * Retrieves audit events within a specified time range.
     *
     * @param startTime the start of the time range (inclusive)
     * @param endTime   the end of the time range (inclusive)
     * @return a list of audit events in the specified range
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> getEventsByTimeRange(Instant startTime, Instant endTime) throws AuditStorageException;

    /**
     * Retrieves audit events for a specific user.
     *
     * @param userId the user identifier
     * @return a list of audit events for the user
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> getEventsByUser(String userId) throws AuditStorageException;

    /**
     * Retrieves audit events for a specific agent.
     *
     * @param agentId the agent identifier
     * @return a list of audit events for the agent
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> getEventsByAgent(String agentId) throws AuditStorageException;

    /**
     * Retrieves audit events for a specific session.
     *
     * @param sessionId the session identifier
     * @return a list of audit events for the session
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> getEventsBySession(String sessionId) throws AuditStorageException;

    /**
     * Retrieves audit events by type.
     *
     * @param eventType the event type
     * @return a list of audit events of the specified type
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> getEventsByType(AuditEventType eventType) throws AuditStorageException;

    /**
     * Retrieves audit events by severity.
     *
     * @param severity the severity level
     * @return a list of audit events with the specified severity
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> getEventsBySeverity(AuditSeverity severity) throws AuditStorageException;

    /**
     * Registers an audit processor.
     * <p>
     * Processors are executed in order of priority (highest first) after
     * an event is stored.
     * </p>
     *
     * @param processor the processor to register
     */
    void registerProcessor(AuditProcessor processor);

    /**
     * Unregisters an audit processor.
     *
     * @param processor the processor to unregister
     */
    void unregisterProcessor(AuditProcessor processor);

    /**
     * Gets the total count of stored audit events.
     *
     * @return the total count
     * @throws AuditStorageException if retrieval fails
     */
    long getEventCount() throws AuditStorageException;

}
