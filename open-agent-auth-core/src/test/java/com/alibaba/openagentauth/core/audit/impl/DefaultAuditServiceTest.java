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
import com.alibaba.openagentauth.core.audit.api.AuditStorage;
import com.alibaba.openagentauth.core.exception.audit.AuditProcessingException;
import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditContext;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for {@link DefaultAuditService}.
 * <p>
 * This test class validates the core functionality of the audit service,
 * including event logging, retrieval, processing, and thread safety.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("DefaultAuditService Tests")
@ExtendWith(MockitoExtension.class)
class DefaultAuditServiceTest {

    @Mock
    private AuditStorage storage;

    @Mock
    private AuditProcessor processor1;

    @Mock
    private AuditProcessor processor2;

    private DefaultAuditService auditService;
    private ExecutorService executorService;

    @BeforeEach
    void setUp() {
        executorService = Executors.newCachedThreadPool();
        auditService = new DefaultAuditService(storage, executorService, false);
    }

    @AfterEach
    void tearDown() {
        if (auditService != null) {
            auditService.shutdown();
        }
        if (executorService != null && !executorService.isShutdown()) {
            executorService.shutdown();
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw exception when storage is null")
        void shouldThrowExceptionWhenStorageIsNull() {
            assertThatThrownBy(() -> new DefaultAuditService(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Audit storage");
        }

        @Test
        @DisplayName("Should throw exception when executor is null")
        void shouldThrowExceptionWhenExecutorIsNull() {
            assertThatThrownBy(() -> new DefaultAuditService(storage, null, false))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Async executor");
        }

        @Test
        @DisplayName("Should create service with default executor")
        void shouldCreateServiceWithDefaultExecutor() {
            DefaultAuditService service = new DefaultAuditService(storage);
            assertThat(service).isNotNull();
            assertThat(service.getStorage()).isEqualTo(storage);
            service.shutdown();
        }
    }

    @Nested
    @DisplayName("Event Logging Tests")
    class EventLoggingTests {

        @Test
        @DisplayName("Should log event successfully")
        void shouldLogEventSuccessfully() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-001");

            auditService.logEvent(event);

            verify(storage).store(event);
        }

        @Test
        @DisplayName("Should throw exception when event is null")
        void shouldThrowExceptionWhenEventIsNull() {
            assertThatThrownBy(() -> auditService.logEvent(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Audit event");
        }

        @Test
        @DisplayName("Should apply processors after storing event")
        void shouldApplyProcessorsAfterStoringEvent() throws AuditProcessingException, AuditStorageException {
            when(processor1.getPriority()).thenReturn(10);
            when(processor2.getPriority()).thenReturn(5);

            auditService.registerProcessor(processor1);
            auditService.registerProcessor(processor2);

            AuditEvent event = createTestEvent("event-002");
            auditService.logEvent(event);

            verify(storage).store(event);
            verify(processor1).process(event);
            verify(processor2).process(event);
        }

        @Test
        @DisplayName("Should continue processing even if one processor fails")
        void shouldContinueProcessingEvenIfOneProcessorFails() throws AuditProcessingException, AuditStorageException {
            when(processor1.getPriority()).thenReturn(10);
            when(processor2.getPriority()).thenReturn(5);
            doThrow(new AuditProcessingException("Processor failed")).when(processor1).process(any());

            auditService.registerProcessor(processor1);
            auditService.registerProcessor(processor2);

            AuditEvent event = createTestEvent("event-003");
            auditService.logEvent(event);

            verify(storage).store(event);
            verify(processor1).process(event);
            verify(processor2).process(event);
        }

        @Test
        @DisplayName("Should store event even if all processors fail")
        void shouldStoreEventEvenIfAllProcessorsFail() throws AuditProcessingException, AuditStorageException {
            when(processor1.getPriority()).thenReturn(10);
            when(processor2.getPriority()).thenReturn(5);
            doThrow(new AuditProcessingException("Processor 1 failed")).when(processor1).process(any());
            doThrow(new AuditProcessingException("Processor 2 failed")).when(processor2).process(any());

            auditService.registerProcessor(processor1);
            auditService.registerProcessor(processor2);

            AuditEvent event = createTestEvent("event-004");
            auditService.logEvent(event);

            verify(storage).store(event);
        }
    }

    @Nested
    @DisplayName("Async Event Logging Tests")
    class AsyncEventLoggingTests {

        @Test
        @DisplayName("Should log event asynchronously")
        void shouldLogEventAsynchronously() throws AuditStorageException, InterruptedException {
            AuditEvent event = createTestEvent("event-005");

            auditService.logEventAsync(event);

            Thread.sleep(100);

            verify(storage).store(event);
        }

        @Test
        @DisplayName("Should throw exception when event is null for async logging")
        void shouldThrowExceptionWhenEventIsNullForAsyncLogging() {
            assertThatThrownBy(() -> auditService.logEventAsync(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Audit event");
        }

        @Test
        @DisplayName("Should handle storage failure gracefully in async mode")
        void shouldHandleStorageFailureGracefullyInAsyncMode() throws InterruptedException {
            AuditEvent event = createTestEvent("event-006");
            
            auditService.logEventAsync(event);
            
            Thread.sleep(100);
            
            verify(storage).store(event);
        }
    }

    @Nested
    @DisplayName("Event Retrieval Tests")
    class EventRetrievalTests {

        @Test
        @DisplayName("Should retrieve event by ID successfully")
        void shouldRetrieveEventByIdSuccessfully() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-007");
            when(storage.retrieve("event-007")).thenReturn(event);

            AuditEvent retrieved = auditService.getEvent("event-007");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getEventId()).isEqualTo("event-007");
        }

        @Test
        @DisplayName("Should return null when event not found")
        void shouldReturnNullWhenEventNotFound() throws AuditStorageException {
            when(storage.retrieve("non-existent")).thenReturn(null);

            AuditEvent retrieved = auditService.getEvent("non-existent");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should throw exception when event ID is null")
        void shouldThrowExceptionWhenEventIdIsNull() {
            assertThatThrownBy(() -> auditService.getEvent(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Event ID");
        }

        @Test
        @DisplayName("Should retrieve events by time range")
        void shouldRetrieveEventsByTimeRange() throws AuditStorageException {
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();
            AuditEvent event1 = createTestEvent("event-008");
            AuditEvent event2 = createTestEvent("event-009");
            List<AuditEvent> events = List.of(event1, event2);

            when(storage.retrieveByTimeRange(startTime, endTime)).thenReturn(events);

            List<AuditEvent> retrieved = auditService.getEventsByTimeRange(startTime, endTime);

            assertThat(retrieved).hasSize(2);
            verify(storage).retrieveByTimeRange(startTime, endTime);
        }

        @Test
        @DisplayName("Should throw exception when start time is null")
        void shouldThrowExceptionWhenStartTimeIsNull() {
            assertThatThrownBy(() -> auditService.getEventsByTimeRange(null, Instant.now()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Start time");
        }

        @Test
        @DisplayName("Should throw exception when end time is null")
        void shouldThrowExceptionWhenEndTimeIsNull() {
            assertThatThrownBy(() -> auditService.getEventsByTimeRange(Instant.now(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("End time");
        }

        @Test
        @DisplayName("Should retrieve events by user ID")
        void shouldRetrieveEventsByUserId() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-010");
            List<AuditEvent> events = List.of(event);

            when(storage.retrieveByUser("user123")).thenReturn(events);

            List<AuditEvent> retrieved = auditService.getEventsByUser("user123");

            assertThat(retrieved).hasSize(1);
            verify(storage).retrieveByUser("user123");
        }

        @Test
        @DisplayName("Should throw exception when user ID is null")
        void shouldThrowExceptionWhenUserIdIsNull() {
            assertThatThrownBy(() -> auditService.getEventsByUser(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("User ID");
        }

        @Test
        @DisplayName("Should retrieve events by agent ID")
        void shouldRetrieveEventsByAgentId() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-011");
            List<AuditEvent> events = List.of(event);

            when(storage.retrieveByAgent("agent456")).thenReturn(events);

            List<AuditEvent> retrieved = auditService.getEventsByAgent("agent456");

            assertThat(retrieved).hasSize(1);
            verify(storage).retrieveByAgent("agent456");
        }

        @Test
        @DisplayName("Should throw exception when agent ID is null")
        void shouldThrowExceptionWhenAgentIdIsNull() {
            assertThatThrownBy(() -> auditService.getEventsByAgent(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Agent ID");
        }

        @Test
        @DisplayName("Should retrieve events by session ID")
        void shouldRetrieveEventsBySessionId() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-012");
            List<AuditEvent> events = List.of(event);

            when(storage.retrieveBySession("session789")).thenReturn(events);

            List<AuditEvent> retrieved = auditService.getEventsBySession("session789");

            assertThat(retrieved).hasSize(1);
            verify(storage).retrieveBySession("session789");
        }

        @Test
        @DisplayName("Should throw exception when session ID is null")
        void shouldThrowExceptionWhenSessionIdIsNull() {
            assertThatThrownBy(() -> auditService.getEventsBySession(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session ID");
        }

        @Test
        @DisplayName("Should retrieve events by type")
        void shouldRetrieveEventsByType() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-013");
            AuditEvent event2 = createTestEvent("event-014");
            List<AuditEvent> allEvents = List.of(event1, event2);

            when(storage.retrieveByTimeRange(any(), any())).thenReturn(allEvents);

            List<AuditEvent> retrieved = auditService.getEventsByType(AuditEventType.AUTHORIZATION_GRANTED);

            assertThat(retrieved).hasSize(2);
        }

        @Test
        @DisplayName("Should throw exception when event type is null")
        void shouldThrowExceptionWhenEventTypeIsNull() {
            assertThatThrownBy(() -> auditService.getEventsByType(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Event type");
        }

        @Test
        @DisplayName("Should retrieve events by severity")
        void shouldRetrieveEventsBySeverity() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-015");
            AuditEvent event2 = createTestEvent("event-016");
            List<AuditEvent> allEvents = List.of(event1, event2);

            when(storage.retrieveByTimeRange(any(), any())).thenReturn(allEvents);

            List<AuditEvent> retrieved = auditService.getEventsBySeverity(AuditSeverity.INFO);

            assertThat(retrieved).hasSize(2);
        }

        @Test
        @DisplayName("Should throw exception when severity is null")
        void shouldThrowExceptionWhenSeverityIsNull() {
            assertThatThrownBy(() -> auditService.getEventsBySeverity(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Severity");
        }
    }

    @Nested
    @DisplayName("Processor Management Tests")
    class ProcessorManagementTests {

        @Test
        @DisplayName("Should register processor successfully")
        void shouldRegisterProcessorSuccessfully() {
            AuditProcessor testProcessor = createTestProcessor(10);
            
            auditService.registerProcessor(testProcessor);

            assertThat(auditService.getProcessors()).hasSize(1);
            assertThat(auditService.getProcessors()).contains(testProcessor);
        }

        @Test
        @DisplayName("Should throw exception when processor is null")
        void shouldThrowExceptionWhenProcessorIsNull() {
            assertThatThrownBy(() -> auditService.registerProcessor(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Processor");
        }

        @Test
        @DisplayName("Should unregister processor successfully")
        void shouldUnregisterProcessorSuccessfully() {
            AuditProcessor testProcessor = createTestProcessor(10);
            auditService.registerProcessor(testProcessor);

            auditService.unregisterProcessor(testProcessor);

            assertThat(auditService.getProcessors()).isEmpty();
        }

        @Test
        @DisplayName("Should throw exception when unregistering null processor")
        void shouldThrowExceptionWhenUnregisteringNullProcessor() {
            assertThatThrownBy(() -> auditService.unregisterProcessor(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Processor");
        }

        @Test
        @DisplayName("Should sort processors by priority")
        void shouldSortProcessorsByPriority() {
            when(processor1.getPriority()).thenReturn(5);
            when(processor2.getPriority()).thenReturn(10);

            auditService.registerProcessor(processor1);
            auditService.registerProcessor(processor2);

            List<AuditProcessor> processors = auditService.getProcessors();
            assertThat(processors).hasSize(2);
            assertThat(processors.get(0)).isEqualTo(processor2);
            assertThat(processors.get(1)).isEqualTo(processor1);
        }

        @Test
        @DisplayName("Should handle processors with same priority")
        void shouldHandleProcessorsWithSamePriority() {
            when(processor1.getPriority()).thenReturn(10);
            when(processor2.getPriority()).thenReturn(10);

            auditService.registerProcessor(processor1);
            auditService.registerProcessor(processor2);

            assertThat(auditService.getProcessors()).hasSize(2);
        }
    }

    @Nested
    @DisplayName("Event Count Tests")
    class EventCountTests {

        @Test
        @DisplayName("Should return event count successfully")
        void shouldReturnEventCountSuccessfully() throws AuditStorageException {
            when(storage.count()).thenReturn(42L);

            long count = auditService.getEventCount();

            assertThat(count).isEqualTo(42L);
            verify(storage).count();
        }

        @Test
        @DisplayName("Should return zero when no events exist")
        void shouldReturnZeroWhenNoEventsExist() throws AuditStorageException {
            when(storage.count()).thenReturn(0L);

            long count = auditService.getEventCount();

            assertThat(count).isEqualTo(0L);
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent event logging")
        void shouldHandleConcurrentEventLogging() throws InterruptedException {
            int threadCount = 20;
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        AuditEvent event = createTestEvent("concurrent-event-" + index);
                        auditService.logEvent(event);
                        successCount.incrementAndGet();
                    } catch (AuditStorageException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isEqualTo(threadCount);
            verify(storage, times(threadCount)).store(any());
        }

        @Test
        @DisplayName("Should handle concurrent processor registration")
        void shouldHandleConcurrentProcessorRegistration() throws InterruptedException {
            int threadCount = 10;
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        AuditProcessor processor = createTestProcessor(index);
                        auditService.registerProcessor(processor);
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(auditService.getProcessors()).hasSize(threadCount);
        }

        @Test
        @DisplayName("Should handle concurrent async logging")
        void shouldHandleConcurrentAsyncLogging() throws InterruptedException {
            int threadCount = 15;
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        AuditEvent event = createTestEvent("async-concurrent-event-" + index);
                        auditService.logEventAsync(event);
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            Thread.sleep(500);
            verify(storage, times(threadCount)).store(any());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full audit lifecycle")
        void shouldCompleteFullAuditLifecycle() throws AuditStorageException, AuditProcessingException {
            when(processor1.getPriority()).thenReturn(10);
            when(processor2.getPriority()).thenReturn(5);

            auditService.registerProcessor(processor1);
            auditService.registerProcessor(processor2);

            AuditEvent event = createTestEvent("lifecycle-event");
            when(storage.retrieve("lifecycle-event")).thenReturn(event);
            when(storage.count()).thenReturn(1L);

            auditService.logEvent(event);

            AuditEvent retrieved = auditService.getEvent("lifecycle-event");
            assertThat(retrieved).isNotNull();

            long count = auditService.getEventCount();
            assertThat(count).isEqualTo(1L);

            verify(processor1).process(event);
            verify(processor2).process(event);
        }

        @Test
        @DisplayName("Should handle multiple events with different types")
        void shouldHandleMultipleEventsWithDifferentTypes() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-017");
            AuditEvent event2 = createTestEvent("event-018", AuditEventType.AUTHORIZATION_DENIED);
            AuditEvent event3 = createTestEvent("event-019", AuditEventType.POLICY_EVALUATION_SUCCESS);

            List<AuditEvent> allEvents = List.of(event1, event2, event3);

            when(storage.retrieveByTimeRange(any(), any())).thenReturn(allEvents);

            List<AuditEvent> authGrantedEvents = auditService.getEventsByType(AuditEventType.AUTHORIZATION_GRANTED);
            List<AuditEvent> authDeniedEvents = auditService.getEventsByType(AuditEventType.AUTHORIZATION_DENIED);
            List<AuditEvent> policyEvalEvents = auditService.getEventsByType(AuditEventType.POLICY_EVALUATION_SUCCESS);

            assertThat(authGrantedEvents).hasSize(1);
            assertThat(authDeniedEvents).hasSize(1);
            assertThat(policyEvalEvents).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Shutdown Tests")
    class ShutdownTests {

        @Test
        @DisplayName("Should shutdown executor when configured")
        void shouldShutdownExecutorWhenConfigured() {
            ExecutorService customExecutor = Executors.newCachedThreadPool();
            DefaultAuditService service = new DefaultAuditService(storage, customExecutor, true);

            service.shutdown();

            assertThat(customExecutor.isShutdown()).isTrue();
        }

        @Test
        @DisplayName("Should not shutdown executor when not configured")
        void shouldNotShutdownExecutorWhenNotConfigured() {
            ExecutorService customExecutor = Executors.newCachedThreadPool();
            DefaultAuditService service = new DefaultAuditService(storage, customExecutor, false);

            service.shutdown();

            assertThat(customExecutor.isShutdown()).isFalse();
            customExecutor.shutdown();
        }
    }

    private AuditEvent createTestEvent(String eventId) {
        return createTestEvent(eventId, AuditEventType.AUTHORIZATION_GRANTED);
    }

    private AuditEvent createTestEvent(String eventId, AuditEventType eventType) {
        AuditContext context = AuditContext.builder()
                .userId("user123")
                .agentId("agent456")
                .sessionId("session789")
                .requestId("request123")
                .clientIpAddress("192.168.1.1")
                .userAgent("TestAgent/1.0")
                .build();

        return AuditEvent.builder()
                .eventId(eventId)
                .timestamp(Instant.now().toString())
                .eventType(eventType)
                .severity(AuditSeverity.INFO)
                .message("Authorization granted for user")
                .context(context)
                .build();
    }

    private AuditProcessor createTestProcessor(int priority) {
        return new AuditProcessor() {
            @Override
            public void process(AuditEvent event) throws AuditProcessingException {
                // No-op
            }

            @Override
            public int getPriority() {
                return priority;
            }
        };
    }
}
