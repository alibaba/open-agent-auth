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

import java.time.Instant;
import java.util.List;

/**
 * Interface for audit event storage.
 * <p>
 * This interface defines the contract for storing and retrieving audit events.
 * Implementations can provide various storage backends such as in-memory storage,
 * database storage, file-based storage, or distributed storage systems.
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Interface Segregation:</b> This interface provides a focused contract
 *       for audit storage operations</li>
 *   <li><b>Extensibility:</b> Implementations can support various storage mechanisms
 *       and optimization strategies</li>
 *   <li><b>Thread Safety:</b> Implementations must be thread-safe for concurrent access</li>
 * </ul>
 * </p>
 * <p>
 * <b>Implementation Considerations:</b></p>
 * <ul>
 *   <li>Implementations should handle storage failures gracefully</li>
 *   <li>Consider implementing audit log retention and archival policies</li>
 *   <li>Implement audit log encryption for sensitive data</li>
 *   <li>Support efficient querying and filtering capabilities</li>
 * </ul>
 * </p>
 *
 * @see AuditEvent
 * @see AuditService
 */
public interface AuditStorage {

    /**
     * Stores an audit event.
     * <p>
     * This method should handle storage failures gracefully, potentially
     * implementing retry logic or fallback mechanisms.
     * </p>
     *
     * @param event the audit event to store
     * @throws AuditStorageException if the event cannot be stored
     */
    void store(AuditEvent event) throws AuditStorageException;

    /**
     * Retrieves an audit event by its unique identifier.
     *
     * @param eventId the unique event identifier
     * @return the audit event, or null if not found
     * @throws AuditStorageException if retrieval fails
     */
    AuditEvent retrieve(String eventId) throws AuditStorageException;

    /**
     * Retrieves audit events within a specified time range.
     *
     * @param startTime the start of the time range (inclusive)
     * @param endTime   the end of the time range (inclusive)
     * @return a list of audit events in the specified range
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> retrieveByTimeRange(Instant startTime, Instant endTime) throws AuditStorageException;

    /**
     * Retrieves audit events for a specific user.
     *
     * @param userId the user identifier
     * @return a list of audit events for the user
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> retrieveByUser(String userId) throws AuditStorageException;

    /**
     * Retrieves audit events for a specific agent.
     *
     * @param agentId the agent identifier
     * @return a list of audit events for the agent
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> retrieveByAgent(String agentId) throws AuditStorageException;

    /**
     * Retrieves audit events for a specific session.
     *
     * @param sessionId the session identifier
     * @return a list of audit events for the session
     * @throws AuditStorageException if retrieval fails
     */
    List<AuditEvent> retrieveBySession(String sessionId) throws AuditStorageException;

    /**
     * Deletes audit events older than a specified timestamp.
     * <p>
     * This method is useful for implementing retention policies and
     * managing storage space.
     * </p>
     *
     * @param beforeTimestamp the timestamp threshold
     * @return the number of events deleted
     * @throws AuditStorageException if deletion fails
     */
    int deleteOlderThan(Instant beforeTimestamp) throws AuditStorageException;

    /**
     * Gets the total count of stored audit events.
     *
     * @return the total count
     * @throws AuditStorageException if retrieval fails
     */
    long count() throws AuditStorageException;

}
