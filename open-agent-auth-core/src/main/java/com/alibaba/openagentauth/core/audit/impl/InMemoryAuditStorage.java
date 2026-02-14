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

import com.alibaba.openagentauth.core.audit.api.AuditStorage;
import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * In-memory implementation of {@link AuditStorage}.
 * <p>
 * This implementation stores audit events in memory using thread-safe data structures.
 * It is suitable for testing, development, and scenarios where persistence is not required.
 * For production use, consider implementing a custom {@link AuditStorage} with persistent storage.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * <ul>
 *   <li>This implementation is thread-safe and can handle concurrent access</li>
 *   <li>Uses {@link ConcurrentHashMap} and {@link CopyOnWriteArrayList} for thread safety</li>
 *   <li>All operations are atomic and consistent</li>
 * </ul>
 * </p>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Events are lost when the application restarts</li>
 *   <li>Memory usage grows with the number of events</li>
 *   <li>Not suitable for long-term audit retention</li>
 * </ul>
 * </p>
 *
 * @see AuditStorage
 */
public class InMemoryAuditStorage implements AuditStorage {

    private final Map<String, AuditEvent> eventsById;
    private final List<AuditEvent> allEvents;

    /**
     * Creates a new in-memory audit storage.
     */
    public InMemoryAuditStorage() {
        this.eventsById = new ConcurrentHashMap<>();
        this.allEvents = new CopyOnWriteArrayList<>();
    }

    @Override
    public void store(AuditEvent event) throws AuditStorageException {
        if (event == null) {
            throw new AuditStorageException("Audit event cannot be null");
        }
        if (event.getEventId() == null) {
            throw new AuditStorageException("Audit event ID cannot be null");
        }

        eventsById.put(event.getEventId(), event);
        allEvents.add(event);
    }

    @Override
    public AuditEvent retrieve(String eventId) throws AuditStorageException {
        if (eventId == null) {
            throw new AuditStorageException("Event ID cannot be null");
        }
        return eventsById.get(eventId);
    }

    @Override
    public List<AuditEvent> retrieveByTimeRange(Instant startTime, Instant endTime) 
            throws AuditStorageException {
        if (startTime == null || endTime == null) {
            throw new AuditStorageException("Start time and end time cannot be null");
        }
        
        return allEvents.stream()
                .filter(event -> {
                    Instant eventTime = Instant.parse(event.getTimestamp());
                    return !eventTime.isBefore(startTime) && !eventTime.isAfter(endTime);
                })
                .collect(Collectors.toList());
    }

    @Override
    public List<AuditEvent> retrieveByUser(String userId) throws AuditStorageException {
        if (userId == null) {
            throw new AuditStorageException("User ID cannot be null");
        }
        
        return allEvents.stream()
                .filter(event -> event.getContext() != null && 
                                 userId.equals(event.getContext().getUserId()))
                .collect(Collectors.toList());
    }

    @Override
    public List<AuditEvent> retrieveByAgent(String agentId) throws AuditStorageException {
        if (agentId == null) {
            throw new AuditStorageException("Agent ID cannot be null");
        }
        
        return allEvents.stream()
                .filter(event -> event.getContext() != null && 
                                 agentId.equals(event.getContext().getAgentId()))
                .collect(Collectors.toList());
    }

    @Override
    public List<AuditEvent> retrieveBySession(String sessionId) throws AuditStorageException {
        if (sessionId == null) {
            throw new AuditStorageException("Session ID cannot be null");
        }
        
        return allEvents.stream()
                .filter(event -> event.getContext() != null && 
                                 sessionId.equals(event.getContext().getSessionId()))
                .collect(Collectors.toList());
    }

    @Override
    public int deleteOlderThan(Instant beforeTimestamp) throws AuditStorageException {
        if (beforeTimestamp == null) {
            throw new AuditStorageException("Timestamp cannot be null");
        }
        
        List<AuditEvent> toRemove = allEvents.stream()
                .filter(event -> Instant.parse(event.getTimestamp()).isBefore(beforeTimestamp))
                .collect(Collectors.toList());
        
        toRemove.forEach(event -> {
            eventsById.remove(event.getEventId());
            allEvents.remove(event);
        });
        
        return toRemove.size();
    }

    @Override
    public long count() throws AuditStorageException {
        return allEvents.size();
    }

    /**
     * Clears all stored audit events.
     * <p>
     * This method is primarily useful for testing.
     * </p>
     */
    public void clear() {
        eventsById.clear();
        allEvents.clear();
    }

    /**
     * Gets all stored audit events.
     * <p>
     * This method returns a defensive copy of the events list.
     * </p>
     *
     * @return an unmodifiable list of all audit events
     */
    public List<AuditEvent> getAllEvents() {
        return Collections.unmodifiableList(new ArrayList<>(allEvents));
    }
}
