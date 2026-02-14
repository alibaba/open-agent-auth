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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.audit.api.AuditStorage;
import com.alibaba.openagentauth.core.exception.audit.AuditProcessingException;
import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link AuditService}.
 * <p>
 * This implementation provides a comprehensive audit logging solution with support for
 * synchronous and asynchronous event logging, event processors, and flexible querying.
 * </p>
 * <p>
 * <b>Design Patterns:</b></p>
 * <ul>
 *   <li><b>Strategy Pattern:</b> Pluggable storage and processor implementations</li>
 *   <li><b>Chain of Responsibility:</b> Processors are executed in priority order</li>
 *   <li><b>Observer Pattern:</b> Processors observe and react to audit events</li>
 * </ul>
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * <ul>
 *   <li>This implementation is thread-safe</li>
   *   <li>Uses {@link CopyOnWriteArrayList} for processor registry</li>
 *   <li>Uses a dedicated executor for asynchronous logging</li>
 * </ul>
 * </p>
 *
 * @see AuditService
 * @see AuditStorage
 * @see AuditProcessor
 */
public class DefaultAuditService implements AuditService {

    private final AuditStorage storage;
    private final List<AuditProcessor> processors;
    private final ExecutorService asyncExecutor;
    private final boolean shutdownExecutorOnClose;

    /**
     * Creates a new default audit service with the specified storage.
     *
     * @param storage the audit storage implementation
     */
    public DefaultAuditService(AuditStorage storage) {
        this(storage, Executors.newCachedThreadPool(), true);
    }

    /**
     * Creates a new default audit service with the specified storage and executor.
     *
     * @param storage              the audit storage implementation
     * @param asyncExecutor        the executor for asynchronous logging
     * @param shutdownExecutorOnClose whether to shutdown the executor when the service is closed
     */
    public DefaultAuditService(AuditStorage storage, ExecutorService asyncExecutor, 
                              boolean shutdownExecutorOnClose) {
        ValidationUtils.validateNotNull(storage, "Audit storage");
        ValidationUtils.validateNotNull(asyncExecutor, "Async executor");
        
        this.storage = storage;
        this.processors = new CopyOnWriteArrayList<>();
        this.asyncExecutor = asyncExecutor;
        this.shutdownExecutorOnClose = shutdownExecutorOnClose;
    }

    @Override
    public void logEvent(AuditEvent event) throws AuditStorageException {
        ValidationUtils.validateNotNull(event, "Audit event");

        // Store the event first to ensure it's not lost even if processing fails
        storage.store(event);

        // Apply processors in priority order (highest first)
        applyProcessors(event);
    }

    @Override
    public void logEventAsync(AuditEvent event) {
        ValidationUtils.validateNotNull(event, "Audit event");

        asyncExecutor.submit(() -> {
            try {
                logEvent(event);
            } catch (AuditStorageException e) {
                // Log the failure but don't propagate it in async mode
                System.err.println("Failed to log audit event asynchronously: " + e.getMessage());
            }
        });
    }

    @Override
    public AuditEvent getEvent(String eventId) throws AuditStorageException {
        ValidationUtils.validateNotNull(eventId, "Event ID");
        return storage.retrieve(eventId);
    }

    @Override
    public List<AuditEvent> getEventsByTimeRange(Instant startTime, Instant endTime) 
            throws AuditStorageException {
        ValidationUtils.validateNotNull(startTime, "Start time");
        ValidationUtils.validateNotNull(endTime, "End time");
        return storage.retrieveByTimeRange(startTime, endTime);
    }

    @Override
    public List<AuditEvent> getEventsByUser(String userId) throws AuditStorageException {
        ValidationUtils.validateNotNull(userId, "User ID");
        return storage.retrieveByUser(userId);
    }

    @Override
    public List<AuditEvent> getEventsByAgent(String agentId) throws AuditStorageException {
        ValidationUtils.validateNotNull(agentId, "Agent ID");
        return storage.retrieveByAgent(agentId);
    }

    @Override
    public List<AuditEvent> getEventsBySession(String sessionId) throws AuditStorageException {
        ValidationUtils.validateNotNull(sessionId, "Session ID");
        return storage.retrieveBySession(sessionId);
    }

    @Override
    public List<AuditEvent> getEventsByType(AuditEventType eventType) 
            throws AuditStorageException {
        ValidationUtils.validateNotNull(eventType, "Event type");
        
        List<AuditEvent> allEvents = storage.retrieveByTimeRange(
            Instant.EPOCH, Instant.now().plusSeconds(86400));
        
        return allEvents.stream()
                .filter(event -> eventType.equals(event.getEventType()))
                .collect(Collectors.toList());
    }

    @Override
    public List<AuditEvent> getEventsBySeverity(AuditSeverity severity) 
            throws AuditStorageException {
        ValidationUtils.validateNotNull(severity, "Severity");
        
        List<AuditEvent> allEvents = storage.retrieveByTimeRange(
            Instant.EPOCH, Instant.now().plusSeconds(86400));
        
        return allEvents.stream()
                .filter(event -> severity.equals(event.getSeverity()))
                .collect(Collectors.toList());
    }

    @Override
    public void registerProcessor(AuditProcessor processor) {
        ValidationUtils.validateNotNull(processor, "Processor");
        processors.add(processor);
        // Sort by priority (highest first)
        processors.sort(Comparator.comparingInt(AuditProcessor::getPriority).reversed());
    }

    @Override
    public void unregisterProcessor(AuditProcessor processor) {
        ValidationUtils.validateNotNull(processor, "Processor");
        processors.remove(processor);
    }

    @Override
    public long getEventCount() throws AuditStorageException {
        return storage.count();
    }

    /**
     * Applies all registered processors to the audit event.
     * <p>
     * Processors are executed in priority order (highest first). If a processor
     * fails, the error is logged but processing continues with the next processor.
     * </p>
     *
     * @param event the audit event to process
     */
    private void applyProcessors(AuditEvent event) {
        for (AuditProcessor processor : processors) {
            try {
                processor.process(event);
            } catch (AuditProcessingException e) {
                // Log the failure but continue with other processors
                System.err.println("Audit processor failed: " + e.getMessage());
                if (e.getCause() != null) {
                    e.getCause().printStackTrace();
                }
            }
        }
    }

    /**
     * Shuts down the audit service and releases resources.
     * <p>
     * If shutdownExecutorOnClose is true, this method will shutdown the
     * async executor, waiting up to 30 seconds for pending tasks to complete.
     * </p>
     */
    public void shutdown() {
        if (shutdownExecutorOnClose) {
            asyncExecutor.shutdown();
            try {
                if (!asyncExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                    asyncExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                asyncExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Gets the list of registered processors.
     *
     * @return an unmodifiable list of registered processors
     */
    public List<AuditProcessor> getProcessors() {
        return new ArrayList<>(processors);
    }

    /**
     * Gets the audit storage implementation.
     *
     * @return the audit storage
     */
    public AuditStorage getStorage() {
        return storage;
    }
}
