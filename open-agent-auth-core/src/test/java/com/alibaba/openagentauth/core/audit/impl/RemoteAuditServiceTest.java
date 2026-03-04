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
import com.alibaba.openagentauth.core.exception.audit.AuditStorageException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RemoteAuditService}.
 * <p>
 * Tests verify the remote audit service implementation that communicates
 * with an Authorization Server via REST API.
 * </p>
 * <p>
 * <b>Note:</b> HTTP request tests are skipped in unit tests because
 * {@code java.net.http.HttpClient} is a final class and cannot be mocked by Mockito.
 * Integration tests should be created to test actual HTTP communication.
 * </p>
 */
@DisplayName("RemoteAuditService Tests")
class RemoteAuditServiceTest {

    private RemoteAuditService auditService;
    private static final String BASE_URL = "http://localhost:8085";
    private static final String EVENT_ID = "event-123";
    private static final String USER_ID = "user-123";
    private static final String AGENT_ID = "agent-123";
    private static final String SESSION_ID = "session-123";

    private ServiceEndpointResolver mockServiceEndpointResolver;

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create service with valid service endpoint resolver")
        void shouldCreateServiceWithValidServiceEndpointResolver() {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);

            // Act
            RemoteAuditService service = new RemoteAuditService(mockServiceEndpointResolver);

            // Assert
            assertThat(service).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new RemoteAuditService(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Service endpoint resolver");
        }
    }

    @Nested
    @DisplayName("logEvent() - Unsupported Operation")
    class LogEventTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw UnsupportedOperationException for logEvent()")
        void shouldThrowUnsupportedOperationExceptionForLogEvent() throws AuditStorageException {
            // Arrange
            AuditEvent event = AuditEvent.builder()
                    .eventId(EVENT_ID)
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> auditService.logEvent(event))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote audit event logging is not supported");
        }

        @Test
        @DisplayName("Should throw UnsupportedOperationException for logEventAsync()")
        void shouldThrowUnsupportedOperationExceptionForLogEventAsync() {
            // Arrange
            AuditEvent event = AuditEvent.builder()
                    .eventId(EVENT_ID)
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> auditService.logEventAsync(event))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote audit event logging is not supported");
        }
    }

    @Nested
    @DisplayName("getEvent() - Parameter Validation")
    class GetEventParameterValidationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw exception when event ID is null")
        void shouldThrowExceptionWhenEventIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Event ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when event ID is empty")
        void shouldThrowExceptionWhenEventIdIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Event ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when event ID is whitespace")
        void shouldThrowExceptionWhenEventIdIsWhitespace() {
            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Event ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("getEvent() - HTTP Communication")
    class GetEventHttpCommunicationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/audit/events/retrieve");
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw AuditStorageException when endpoint resolution fails")
        void shouldThrowAuditStorageExceptionWhenEndpointResolutionFails() {
            // Arrange
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent(EVENT_ID))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Failed to resolve endpoint");
        }
    }

    @Nested
    @DisplayName("getEventsByTimeRange() - HTTP Communication")
    class GetEventsByTimeRangeHttpCommunicationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/audit/events/list");
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw AuditStorageException when endpoint resolution fails")
        void shouldThrowAuditStorageExceptionWhenEndpointResolutionFails() {
            // Arrange
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(null);

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEventsByTimeRange(startTime, endTime))
                    .isInstanceOf(AuditStorageException.class)
                    .hasMessageContaining("Failed to resolve endpoint");
        }
    }

    @Nested
    @DisplayName("getEventsByUser() - Not Supported")
    class GetEventsByUserTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty list for getEventsByUser()")
        void shouldReturnEmptyListForGetEventsByUser() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByUser(USER_ID);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsByUser() with null user ID")
        void shouldReturnEmptyListForGetEventsByUserWithNullUserId() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByUser(null);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsByUser() with empty user ID")
        void shouldReturnEmptyListForGetEventsByUserWithEmptyUserId() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByUser("");

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getEventsByAgent() - Not Supported")
    class GetEventsByAgentTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty list for getEventsByAgent()")
        void shouldReturnEmptyListForGetEventsByAgent() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByAgent(AGENT_ID);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsByAgent() with null agent ID")
        void shouldReturnEmptyListForGetEventsByAgentWithNullAgentId() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByAgent(null);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsByAgent() with empty agent ID")
        void shouldReturnEmptyListForGetEventsByAgentWithEmptyAgentId() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByAgent("");

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getEventsBySession() - Not Supported")
    class GetEventsBySessionTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty list for getEventsBySession()")
        void shouldReturnEmptyListForGetEventsBySession() throws AuditStorageException {
            // Act
            var result = auditService.getEventsBySession(SESSION_ID);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsBySession() with null session ID")
        void shouldReturnEmptyListForGetEventsBySessionWithNullSessionId() throws AuditStorageException {
            // Act
            var result = auditService.getEventsBySession(null);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsBySession() with empty session ID")
        void shouldReturnEmptyListForGetEventsBySessionWithEmptySessionId() throws AuditStorageException {
            // Act
            var result = auditService.getEventsBySession("");

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getEventsByType() - Not Supported")
    class GetEventsByTypeTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty list for getEventsByType()")
        void shouldReturnEmptyListForGetEventsByType() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByType(AuditEventType.AUTHORIZATION_GRANTED);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsByType() with null type")
        void shouldReturnEmptyListForGetEventsByTypeWithNullType() throws AuditStorageException {
            // Act
            var result = auditService.getEventsByType(null);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("getEventsBySeverity() - Not Supported")
    class GetEventsBySeverityTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return empty list for getEventsBySeverity()")
        void shouldReturnEmptyListForGetEventsBySeverity() throws AuditStorageException {
            // Act
            var result = auditService.getEventsBySeverity(AuditSeverity.INFO);

            // Assert
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list for getEventsBySeverity() with null severity")
        void shouldReturnEmptyListForGetEventsBySeverityWithNullSeverity() throws AuditStorageException {
            // Act
            var result = auditService.getEventsBySeverity(null);

            // Assert
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("Processor Registration - Unsupported Operation")
    class ProcessorRegistrationTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should throw exception for registerProcessor()")
        void shouldThrowExceptionForRegisterProcessor() {
            // Arrange
            AuditProcessor processor = mock(AuditProcessor.class);

            // Act & Assert
            assertThatThrownBy(() -> auditService.registerProcessor(processor))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote audit processor registration is not supported");
        }

        @Test
        @DisplayName("Should throw exception for registerProcessor() with null processor")
        void shouldThrowExceptionForRegisterProcessorWithNullProcessor() {
            // Act & Assert
            assertThatThrownBy(() -> auditService.registerProcessor(null))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        @DisplayName("Should throw exception for unregisterProcessor()")
        void shouldThrowExceptionForUnregisterProcessor() {
            // Arrange
            AuditProcessor processor = mock(AuditProcessor.class);

            // Act & Assert
            assertThatThrownBy(() -> auditService.unregisterProcessor(processor))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("Remote audit processor unregistration is not supported");
        }

        @Test
        @DisplayName("Should throw exception for unregisterProcessor() with null processor")
        void shouldThrowExceptionForUnregisterProcessorWithNullProcessor() {
            // Act & Assert
            assertThatThrownBy(() -> auditService.unregisterProcessor(null))
                    .isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Nested
    @DisplayName("getEventCount() - Not Supported")
    class GetEventCountTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should return 0 for getEventCount()")
        void shouldReturnZeroForGetEventCount() throws AuditStorageException {
            // Act
            long result = auditService.getEventCount();

            // Assert
            assertThat(result).isZero();
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Conditions")
    class EdgeCasesAndBoundaryConditionsTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/audit/events/retrieve");
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should handle very long event ID")
        void shouldHandleVeryLongEventId() {
            // Arrange
            String longEventId = "event-" + "a".repeat(1000);

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent(longEventId))
                    .isInstanceOf(AuditStorageException.class);
        }

        @Test
        @DisplayName("Should handle special characters in event ID")
        void shouldHandleSpecialCharactersInEventId() {
            // Arrange
            String specialEventId = "event-123_@#$%";

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent(specialEventId))
                    .isInstanceOf(AuditStorageException.class);
        }

        @Test
        @DisplayName("Should handle time range with same start and end time")
        void shouldHandleTimeRangeWithSameStartAndEndTime() {
            // Arrange
            Instant now = Instant.now();

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEventsByTimeRange(now, now))
                    .isInstanceOf(AuditStorageException.class);
        }

        @Test
        @DisplayName("Should handle time range with end before start")
        void shouldHandleTimeRangeWithEndBeforeStart() {
            // Arrange
            Instant startTime = Instant.now();
            Instant endTime = Instant.now().minusSeconds(3600);

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEventsByTimeRange(startTime, endTime))
                    .isInstanceOf(AuditStorageException.class);
        }
    }

    @Nested
    @DisplayName("Thread Safety")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should allow concurrent creation of services")
        void shouldAllowConcurrentCreationOfServices() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/audit/events/retrieve");
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            RemoteAuditService[] services = new RemoteAuditService[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    services[index] = new RemoteAuditService(mockServiceEndpointResolver);
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert
            for (RemoteAuditService service : services) {
                assertThat(service).isNotNull();
            }
        }

        @Test
        @DisplayName("Should allow concurrent getEvent() calls")
        void shouldAllowConcurrentGetEventCalls() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/audit/events/retrieve");
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            Exception[] exceptions = new Exception[threadCount];

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    try {
                        auditService.getEvent(EVENT_ID);
                    } catch (Exception e) {
                        exceptions[index] = e;
                    }
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert - All should throw AuditStorageException (not concurrent modification)
            for (Exception e : exceptions) {
                assertThat(e).isInstanceOf(AuditStorageException.class);
            }
        }

        @Test
        @DisplayName("Should allow concurrent getEventsByTimeRange() calls")
        void shouldAllowConcurrentGetEventsByTimeRangeCalls() throws InterruptedException {
            // Arrange
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            when(mockServiceEndpointResolver.resolveConsumer(anyString(), anyString()))
                    .thenReturn(BASE_URL + "/api/v1/audit/events/list");
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            Exception[] exceptions = new Exception[threadCount];
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();

            // Act
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    try {
                        auditService.getEventsByTimeRange(startTime, endTime);
                    } catch (Exception e) {
                        exceptions[index] = e;
                    }
                });
                threads[i].start();
            }

            for (Thread thread : threads) {
                thread.join();
            }

            // Assert - All should throw AuditStorageException (not concurrent modification)
            for (Exception e : exceptions) {
                assertThat(e).isInstanceOf(AuditStorageException.class);
            }
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationScenariosTests {

        @BeforeEach
        void setUp() {
            mockServiceEndpointResolver = mock(ServiceEndpointResolver.class);
            auditService = new RemoteAuditService(mockServiceEndpointResolver);
        }

        @Test
        @DisplayName("Should handle multiple sequential getEvent() calls")
        void shouldHandleMultipleSequentialGetEventCalls() {
            // Act & Assert
            for (int i = 0; i < 5; i++) {
                final int eventIndex = i;
                assertThatThrownBy(() -> auditService.getEvent("event-" + eventIndex))
                        .isInstanceOf(AuditStorageException.class);
            }
        }

        @Test
        @DisplayName("Should handle alternating between getEvent() and getEventsByTimeRange()")
        void shouldHandleAlternatingBetweenGetEventAndGetEventsByTimeRange() {
            // Arrange
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();

            // Act & Assert
            assertThatThrownBy(() -> auditService.getEvent(EVENT_ID))
                    .isInstanceOf(AuditStorageException.class);

            assertThatThrownBy(() -> auditService.getEventsByTimeRange(startTime, endTime))
                    .isInstanceOf(AuditStorageException.class);

            assertThatThrownBy(() -> auditService.getEvent(EVENT_ID))
                    .isInstanceOf(AuditStorageException.class);
        }

        @Test
        @DisplayName("Should handle calling all unsupported operations in sequence")
        void shouldHandleCallingAllUnsupportedOperationsInSequence() {
            // Arrange
            AuditEvent event = AuditEvent.builder()
                    .eventId(EVENT_ID)
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .build();
            AuditProcessor processor = mock(AuditProcessor.class);

            // Act & Assert
            assertThatThrownBy(() -> auditService.logEvent(event))
                    .isInstanceOf(UnsupportedOperationException.class);

            assertThatThrownBy(() -> auditService.logEventAsync(event))
                    .isInstanceOf(UnsupportedOperationException.class);

            assertThatThrownBy(() -> auditService.registerProcessor(processor))
                    .isInstanceOf(UnsupportedOperationException.class);

            assertThatThrownBy(() -> auditService.unregisterProcessor(processor))
                    .isInstanceOf(UnsupportedOperationException.class);

            assertThat(auditService.getEventsByUser(USER_ID)).isEmpty();
            assertThat(auditService.getEventsByAgent(AGENT_ID)).isEmpty();
            assertThat(auditService.getEventsBySession(SESSION_ID)).isEmpty();
            assertThat(auditService.getEventsByType(AuditEventType.AUTHORIZATION_GRANTED)).isEmpty();
            assertThat(auditService.getEventsBySeverity(AuditSeverity.INFO)).isEmpty();
        }
    }
}
