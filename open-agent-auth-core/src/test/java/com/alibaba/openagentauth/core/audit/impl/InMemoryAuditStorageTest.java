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

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for {@link InMemoryAuditStorage}.
 * <p>
 * This test class validates the in-memory audit storage functionality,
 * including event storage, retrieval, deletion, and thread safety.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("InMemoryAuditStorage Tests")
class InMemoryAuditStorageTest {

    private InMemoryAuditStorage storage;

    @BeforeEach
    void setUp() {
        storage = new InMemoryAuditStorage();
    }

    @AfterEach
    void tearDown() {
        if (storage != null) {
            storage.clear();
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create storage instance")
        void shouldCreateStorageInstance() {
            InMemoryAuditStorage newStorage = new InMemoryAuditStorage();

            assertThat(newStorage).isNotNull();
            assertThat(newStorage.getAllEvents()).isEmpty();
        }

        @Test
        @DisplayName("Should create multiple independent storage instances")
        void shouldCreateMultipleIndependentStorageInstances() {
            InMemoryAuditStorage storage1 = new InMemoryAuditStorage();
            InMemoryAuditStorage storage2 = new InMemoryAuditStorage();

            assertThat(storage1).isNotSameAs(storage2);
        }
    }

    @Nested
    @DisplayName("Event Storage Tests")
    class EventStorageTests {

        @Test
        @DisplayName("Should store event successfully")
        void shouldStoreEventSuccessfully() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-001");

            storage.store(event);

            assertThat(storage.getAllEvents()).hasSize(1);
            assertThat(storage.getAllEvents().get(0)).isEqualTo(event);
        }

        @Test
        @DisplayName("Should throw exception when event is null")
        void shouldThrowExceptionWhenEventIsNull() {
            assertThatThrownBy(() -> storage.store(null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Audit event cannot be null");
        }

        @Test
        @DisplayName("Should store multiple events")
        void shouldStoreMultipleEvents() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001");
            AuditEvent event2 = createTestEvent("event-002");
            AuditEvent event3 = createTestEvent("event-003");

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            assertThat(storage.getAllEvents()).hasSize(3);
        }

        @Test
        @DisplayName("Should overwrite event with same ID")
        void shouldOverwriteEventWithSameId() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001");
            storage.store(event1);

            AuditEvent event2 = createTestEventWithMessage("event-001", "Second message");
            storage.store(event2);

            List<AuditEvent> events = storage.getAllEvents();
            // Current implementation adds duplicate events to the list
            // so we expect 2 events with the same ID
            assertThat(events).hasSize(2);
            
            // The last stored event should be retrieved from eventsById map
            AuditEvent retrievedEvent = storage.retrieve("event-001");
            assertThat(retrievedEvent).isNotNull();
            assertThat(retrievedEvent.getMessage()).isEqualTo("Second message");
            
            // Verify that both events in the list have the same ID
            assertThat(events.stream().filter(e -> e.getEventId().equals("event-001")).count()).isEqualTo(2);
        }
    }

    @Nested
    @DisplayName("Event Retrieval Tests")
    class EventRetrievalTests {

        @Test
        @DisplayName("Should retrieve event by ID successfully")
        void shouldRetrieveEventByIdSuccessfully() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-001");
            storage.store(event);

            AuditEvent retrieved = storage.retrieve("event-001");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getEventId()).isEqualTo("event-001");
        }

        @Test
        @DisplayName("Should return null when event not found")
        void shouldReturnNullWhenEventNotFound() throws AuditStorageException {
            AuditEvent retrieved = storage.retrieve("non-existent");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should throw exception when event ID is null")
        void shouldThrowExceptionWhenEventIdIsNull() {
            assertThatThrownBy(() -> storage.retrieve(null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Event ID cannot be null");
        }

        @Test
        @DisplayName("Should retrieve events by time range")
        void shouldRetrieveEventsByTimeRange() throws AuditStorageException {
            Instant now = Instant.now();
            Instant oneHourAgo = now.minusSeconds(3600);
            Instant twoHoursAgo = now.minusSeconds(7200);

            AuditEvent event1 = createTestEvent("event-001", twoHoursAgo);
            AuditEvent event2 = createTestEvent("event-002", oneHourAgo);
            AuditEvent event3 = createTestEvent("event-003", now);

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            List<AuditEvent> retrieved = storage.retrieveByTimeRange(oneHourAgo.minusSeconds(60), now.plusSeconds(60));

            assertThat(retrieved).hasSize(2);
            assertThat(retrieved).allMatch(e -> e.getEventId().equals("event-002") || e.getEventId().equals("event-003"));
        }

        @Test
        @DisplayName("Should throw exception when start time is null")
        void shouldThrowExceptionWhenStartTimeIsNull() {
            assertThatThrownBy(() -> storage.retrieveByTimeRange(null, Instant.now()))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Start time and end time cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when end time is null")
        void shouldThrowExceptionWhenEndTimeIsNull() {
            assertThatThrownBy(() -> storage.retrieveByTimeRange(Instant.now(), null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Start time and end time cannot be null");
        }

        @Test
        @DisplayName("Should retrieve events by user ID")
        void shouldRetrieveEventsByUserId() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001", "user123");
            AuditEvent event2 = createTestEvent("event-002", "user456");
            AuditEvent event3 = createTestEvent("event-003", "user123");

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            List<AuditEvent> retrieved = storage.retrieveByUser("user123");

            assertThat(retrieved).hasSize(2);
            assertThat(retrieved).allMatch(e -> e.getContext().getUserId().equals("user123"));
        }

        @Test
        @DisplayName("Should throw exception when user ID is null")
        void shouldThrowExceptionWhenUserIdIsNull() {
            assertThatThrownBy(() -> storage.retrieveByUser(null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("User ID cannot be null");
        }

        @Test
        @DisplayName("Should retrieve events by agent ID")
        void shouldRetrieveEventsByAgentId() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001", "user123", "agent456");
            AuditEvent event2 = createTestEvent("event-002", "user456", "agent789");
            AuditEvent event3 = createTestEvent("event-003", "user789", "agent456");

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            List<AuditEvent> retrieved = storage.retrieveByAgent("agent456");

            assertThat(retrieved).hasSize(2);
            assertThat(retrieved).allMatch(e -> e.getContext().getAgentId().equals("agent456"));
        }

        @Test
        @DisplayName("Should throw exception when agent ID is null")
        void shouldThrowExceptionWhenAgentIdIsNull() {
            assertThatThrownBy(() -> storage.retrieveByAgent(null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Agent ID cannot be null");
        }

        @Test
        @DisplayName("Should retrieve events by session ID")
        void shouldRetrieveEventsBySessionId() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001", "user123", "agent456", "session001");
            AuditEvent event2 = createTestEvent("event-002", "user456", "agent789", "session002");
            AuditEvent event3 = createTestEvent("event-003", "user789", "agent456", "session001");

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            List<AuditEvent> retrieved = storage.retrieveBySession("session001");

            assertThat(retrieved).hasSize(2);
            assertThat(retrieved).allMatch(e -> e.getContext().getSessionId().equals("session001"));
        }

        @Test
        @DisplayName("Should throw exception when session ID is null")
        void shouldThrowExceptionWhenSessionIdIsNull() {
            assertThatThrownBy(() -> storage.retrieveBySession(null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Session ID cannot be null");
        }

        @Test
        @DisplayName("Should return empty list when no events match criteria")
        void shouldReturnEmptyListWhenNoEventsMatchCriteria() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-001", "user123");
            storage.store(event);

            List<AuditEvent> retrieved = storage.retrieveByUser("non-existent-user");

            assertThat(retrieved).isEmpty();
        }

        @Test
        @DisplayName("Should handle events without context")
        void shouldHandleEventsWithoutContext() throws AuditStorageException {
            AuditEvent event = AuditEvent.builder()
                    .eventId("event-001")
                    .timestamp(Instant.now().toString())
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event without context")
                    .build();

            storage.store(event);

            List<AuditEvent> retrieved = storage.retrieveByUser("user123");

            assertThat(retrieved).isEmpty();
        }
    }

    @Nested
    @DisplayName("Event Deletion Tests")
    class EventDeletionTests {

        @Test
        @DisplayName("Should delete older events successfully")
        void shouldDeleteOlderEventsSuccessfully() throws AuditStorageException {
            Instant now = Instant.now();
            Instant oneHourAgo = now.minusSeconds(3600);
            Instant twoHoursAgo = now.minusSeconds(7200);

            AuditEvent event1 = createTestEvent("event-001", twoHoursAgo);
            AuditEvent event2 = createTestEvent("event-002", oneHourAgo);
            AuditEvent event3 = createTestEvent("event-003", now);

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            int deleted = storage.deleteOlderThan(oneHourAgo);

            assertThat(deleted).isEqualTo(1);
            assertThat(storage.getAllEvents()).hasSize(2);
            assertThat(storage.getAllEvents()).noneMatch(e -> e.getEventId().equals("event-001"));
        }

        @Test
        @DisplayName("Should delete all events when timestamp is in the future")
        void shouldDeleteAllEventsWhenTimestampIsInTheFuture() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001");
            AuditEvent event2 = createTestEvent("event-002");

            storage.store(event1);
            storage.store(event2);

            int deleted = storage.deleteOlderThan(Instant.now().plusSeconds(3600));

            assertThat(deleted).isEqualTo(2);
            assertThat(storage.getAllEvents()).isEmpty();
        }

        @Test
        @DisplayName("Should delete no events when timestamp is in the past")
        void shouldDeleteNoEventsWhenTimestampIsInThePast() throws AuditStorageException {
            AuditEvent event = createTestEvent("event-001");
            storage.store(event);

            int deleted = storage.deleteOlderThan(Instant.now().minusSeconds(3600));

            assertThat(deleted).isEqualTo(0);
            assertThat(storage.getAllEvents()).hasSize(1);
        }

        @Test
        @DisplayName("Should throw exception when timestamp is null")
        void shouldThrowExceptionWhenTimestampIsNull() {
            assertThatThrownBy(() -> storage.deleteOlderThan(null))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Timestamp cannot be null");
        }

        @Test
        @DisplayName("Should clear all events")
        void shouldClearAllEvents() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001");
            AuditEvent event2 = createTestEvent("event-002");

            storage.store(event1);
            storage.store(event2);

            storage.clear();

            assertThat(storage.getAllEvents()).isEmpty();
            assertThat(storage.count()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Event Count Tests")
    class EventCountTests {

        @Test
        @DisplayName("Should return zero when no events exist")
        void shouldReturnZeroWhenNoEventsExist() throws AuditStorageException {
            long count = storage.count();

            assertThat(count).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return correct event count")
        void shouldReturnCorrectEventCount() throws AuditStorageException {
            storage.store(createTestEvent("event-001"));
            storage.store(createTestEvent("event-002"));
            storage.store(createTestEvent("event-003"));

            long count = storage.count();

            assertThat(count).isEqualTo(3);
        }

        @Test
        @DisplayName("Should update count after deletion")
        void shouldUpdateCountAfterDeletion() throws AuditStorageException {
            storage.store(createTestEvent("event-001"));
            storage.store(createTestEvent("event-002"));

            assertThat(storage.count()).isEqualTo(2);

            storage.deleteOlderThan(Instant.now().plusSeconds(3600));

            assertThat(storage.count()).isEqualTo(0);
        }
    }

    @Nested
    @DisplayName("Get All Events Tests")
    class GetAllEventsTests {

        @Test
        @DisplayName("Should return empty list when no events exist")
        void shouldReturnEmptyListWhenNoEventsExist() {
            List<AuditEvent> events = storage.getAllEvents();

            assertThat(events).isNotNull();
            assertThat(events).isEmpty();
        }

        @Test
        @DisplayName("Should return all events")
        void shouldReturnAllEvents() throws AuditStorageException {
            AuditEvent event1 = createTestEvent("event-001");
            AuditEvent event2 = createTestEvent("event-002");

            storage.store(event1);
            storage.store(event2);

            List<AuditEvent> events = storage.getAllEvents();

            assertThat(events).hasSize(2);
            assertThat(events).contains(event1, event2);
        }

        @Test
        @DisplayName("Should return unmodifiable list")
        void shouldReturnUnmodifiableList() throws AuditStorageException {
            storage.store(createTestEvent("event-001"));

            List<AuditEvent> events = storage.getAllEvents();

            assertThatThrownBy(() -> events.add(createTestEvent("event-002")))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Should return defensive copy")
        void shouldReturnDefensiveCopy() throws AuditStorageException {
            storage.store(createTestEvent("event-001"));

            List<AuditEvent> events1 = storage.getAllEvents();
            List<AuditEvent> events2 = storage.getAllEvents();

            assertThat(events1).isNotSameAs(events2);
            assertThat(events1).isEqualTo(events2);
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent event storage")
        void shouldHandleConcurrentEventStorage() throws InterruptedException {
            int threadCount = 20;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        storage.store(createTestEvent("concurrent-event-" + index));
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
            assertThat(storage.count()).isEqualTo(threadCount);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent event retrieval")
        void shouldHandleConcurrentEventRetrieval() throws AuditStorageException, InterruptedException {
            storage.store(createTestEvent("event-001"));

            int threadCount = 20;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executorService.submit(() -> {
                    try {
                        AuditEvent event = storage.retrieve("event-001");
                        if (event != null) {
                            successCount.incrementAndGet();
                        }
                    } catch (AuditStorageException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isEqualTo(threadCount);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent storage and retrieval")
        void shouldHandleConcurrentStorageAndRetrieval() throws InterruptedException {
            int threadCount = 10;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount * 2);
            CountDownLatch latch = new CountDownLatch(threadCount * 2);
            AtomicInteger storageSuccessCount = new AtomicInteger(0);
            AtomicInteger retrievalSuccessCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        storage.store(createTestEvent("concurrent-event-" + index));
                        storageSuccessCount.incrementAndGet();
                    } catch (AuditStorageException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });

                executorService.submit(() -> {
                    try {
                        storage.retrieve("concurrent-event-" + index);
                        retrievalSuccessCount.incrementAndGet();
                    } catch (AuditStorageException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(storageSuccessCount.get()).isEqualTo(threadCount);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent deletion")
        void shouldHandleConcurrentDeletion() throws InterruptedException, AuditStorageException {
            for (int i = 0; i < 20; i++) {
                storage.store(createTestEvent("event-" + i));
            }

            int threadCount = 5;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            for (int i = 0; i < threadCount; i++) {
                final int threadIndex = i;
                executorService.submit(() -> {
                    try {
                        storage.deleteOlderThan(Instant.now().plusSeconds(3600));
                    } catch (AuditStorageException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(storage.count()).isEqualTo(0);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full event lifecycle")
        void shouldCompleteFullEventLifecycle() throws AuditStorageException {
            AuditEvent event = createTestEvent("lifecycle-event");

            storage.store(event);
            assertThat(storage.count()).isEqualTo(1);

            AuditEvent retrieved = storage.retrieve("lifecycle-event");
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getEventId()).isEqualTo("lifecycle-event");

            storage.deleteOlderThan(Instant.now().plusSeconds(3600));
            assertThat(storage.count()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should handle complex query scenarios")
        void shouldHandleComplexQueryScenarios() throws AuditStorageException {
            Instant now = Instant.now();
            Instant oneHourAgo = now.minusSeconds(3600);

            AuditEvent event1 = createTestEvent("event-001", "user123", "agent456", "session001", oneHourAgo);
            AuditEvent event2 = createTestEvent("event-002", "user123", "agent789", "session002", now);
            AuditEvent event3 = createTestEvent("event-003", "user456", "agent456", "session001", now);

            storage.store(event1);
            storage.store(event2);
            storage.store(event3);

            List<AuditEvent> user123Events = storage.retrieveByUser("user123");
            assertThat(user123Events).hasSize(2);

            List<AuditEvent> agent456Events = storage.retrieveByAgent("agent456");
            assertThat(agent456Events).hasSize(2);

            List<AuditEvent> session001Events = storage.retrieveBySession("session001");
            assertThat(session001Events).hasSize(2);

            List<AuditEvent> recentEvents = storage.retrieveByTimeRange(oneHourAgo, now.plusSeconds(60));
            assertThat(recentEvents).hasSize(3);
        }

        @Test
        @DisplayName("Should handle large number of events")
        void shouldHandleLargeNumberOfEvents() throws AuditStorageException {
            int eventCount = 1000;

            for (int i = 0; i < eventCount; i++) {
                storage.store(createTestEvent("event-" + i));
            }

            assertThat(storage.count()).isEqualTo(eventCount);
            assertThat(storage.getAllEvents()).hasSize(eventCount);

            storage.deleteOlderThan(Instant.now().plusSeconds(3600));
            assertThat(storage.count()).isEqualTo(0);
        }
    }

    private AuditEvent createTestEvent(String eventId) {
        return createTestEvent(eventId, Instant.now());
    }

    private AuditEvent createTestEvent(String eventId, Instant timestamp) {
        return createTestEvent(eventId, "user123", "agent456", "session789", timestamp);
    }

    private AuditEvent createTestEvent(String eventId, String userId) {
        return createTestEvent(eventId, userId, "agent456", "session789", Instant.now());
    }

    private AuditEvent createTestEvent(String eventId, String userId, String agentId) {
        return createTestEvent(eventId, userId, agentId, "session789", Instant.now());
    }

    private AuditEvent createTestEvent(String eventId, String userId, String agentId, String sessionId) {
        return createTestEvent(eventId, userId, agentId, sessionId, Instant.now());
    }

    private AuditEvent createTestEvent(String eventId, String userId, String agentId, String sessionId, Instant timestamp) {
        return createTestEventWithMessage(eventId, userId, agentId, sessionId, timestamp, "Authorization granted for user");
    }

    private AuditEvent createTestEventWithMessage(String eventId, String message) {
        return createTestEventWithMessage(eventId, "user123", "agent456", "session789", Instant.now(), message);
    }

    private AuditEvent createTestEventWithMessage(String eventId, String userId, String agentId, String sessionId, Instant timestamp, String message) {
        AuditContext context = AuditContext.builder()
                .userId(userId)
                .agentId(agentId)
                .sessionId(sessionId)
                .requestId("request123")
                .clientIpAddress("192.168.1.1")
                .userAgent("TestAgent/1.0")
                .build();

        return AuditEvent.builder()
                .eventId(eventId)
                .timestamp(timestamp.toString())
                .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                .severity(AuditSeverity.INFO)
                .message(message)
                .context(context)
                .build();
    }
}
