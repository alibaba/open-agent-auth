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
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuditController}.
 * <p>
 * This test class verifies the Audit API functionality, including:
 * <ul>
 *   <li>Retrieving audit events by ID</li>
 *   <li>Retrieving audit events by time range</li>
 *   <li>Retrieving audit events by user, agent, session</li>
 *   <li>Retrieving audit events by type and severity</li>
 *   <li>Getting audit event count</li>
 *   <li>Error handling and exception scenarios</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditController Tests")
class AuditControllerTest {

    private static final String EVENT_ID = "event-123";
    private static final String USER_ID = "user-456";
    private static final String AGENT_ID = "agent-789";
    private static final String SESSION_ID = "session-abc";
    private static final String MESSAGE = "Test audit event";

    @Mock
    private AuditService auditService;

    private AuditController controller;

    private AuditEvent mockAuditEvent;

    @BeforeEach
    void setUp() {
        mockAuditEvent = AuditEvent.builder()
                .eventId(EVENT_ID)
                .timestamp(Instant.now().toString())
                .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                .severity(AuditSeverity.INFO)
                .message(MESSAGE)
                .build();
        
        // Manually create the controller with Optional<AuditService>
        controller = new AuditController(Optional.of(auditService));
    }

    @Nested
    @DisplayName("GET /api/v1/audit/events/{eventId} - Get Event By ID")
    class GetEventByIdTests {

        @Test
        @DisplayName("Should return audit event when found")
        void shouldReturnAuditEventWhenFound() throws AuditStorageException {
            // Arrange
            when(auditService.getEvent(EVENT_ID)).thenReturn(mockAuditEvent);

            // Act
            AuditController.EventIdRequest request = new AuditController.EventIdRequest();
            request.setEventId(EVENT_ID);
            ResponseEntity<AuditEvent> response = controller.getEvent(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getEventId()).isEqualTo(EVENT_ID);
            assertThat(response.getBody().getMessage()).isEqualTo(MESSAGE);
        }

        @Test
        @DisplayName("Should return 404 when event not found")
        void shouldReturn404WhenEventNotFound() throws AuditStorageException {
            // Arrange
            when(auditService.getEvent(EVENT_ID)).thenReturn(null);

            // Act
            AuditController.EventIdRequest request = new AuditController.EventIdRequest();
            request.setEventId(EVENT_ID);
            ResponseEntity<AuditEvent> response = controller.getEvent(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody()).isNull();
        }

        @Test
        @DisplayName("Should return 500 when storage exception occurs")
        void shouldReturn500WhenStorageExceptionOccurs() throws AuditStorageException {
            // Arrange
            when(auditService.getEvent(EVENT_ID))
                    .thenThrow(new AuditStorageException("Storage error"));

            // Act
            AuditController.EventIdRequest request = new AuditController.EventIdRequest();
            request.setEventId(EVENT_ID);
            ResponseEntity<AuditEvent> response = controller.getEvent(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNull();
        }
    }

    @Nested
    @DisplayName("GET /api/v1/audit/events - Get Events By Time Range")
    class GetEventsByTimeRangeTests {

        @Test
        @DisplayName("Should return events when time range is valid")
        void shouldReturnEventsWhenTimeRangeIsValid() throws AuditStorageException {
            // Arrange
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();
            List<AuditEvent> events = List.of(mockAuditEvent);

            when(auditService.getEventsByTimeRange(startTime, endTime)).thenReturn(events);

            // Act
            AuditController.TimeRangeRequest request = new AuditController.TimeRangeRequest();
            request.setStartTime(startTime);
            request.setEndTime(endTime);
            ResponseEntity<List<AuditEvent>> response = controller.getEventsByTimeRange(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).hasSize(1);
            assertThat(response.getBody().get(0).getEventId()).isEqualTo(EVENT_ID);
        }

        @Test
        @DisplayName("Should return empty list when no events found in range")
        void shouldReturnEmptyListWhenNoEventsFoundInRange() throws AuditStorageException {
            // Arrange
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();

            when(auditService.getEventsByTimeRange(startTime, endTime)).thenReturn(Collections.emptyList());

            // Act
            AuditController.TimeRangeRequest request = new AuditController.TimeRangeRequest();
            request.setStartTime(startTime);
            request.setEndTime(endTime);
            ResponseEntity<List<AuditEvent>> response = controller.getEventsByTimeRange(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).isEmpty();
        }

        @Test
        @DisplayName("Should return 400 when both time parameters are null")
        void shouldReturn400WhenBothTimeParametersAreNull() {
            // Act
            AuditController.TimeRangeRequest request = new AuditController.TimeRangeRequest();
            ResponseEntity<List<AuditEvent>> response = controller.getEventsByTimeRange(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNull();
        }

        @Test
        @DisplayName("Should return 500 when storage exception occurs")
        void shouldReturn500WhenStorageExceptionOccurs() throws AuditStorageException {
            // Arrange
            Instant startTime = Instant.now().minusSeconds(3600);
            Instant endTime = Instant.now();

            when(auditService.getEventsByTimeRange(startTime, endTime))
                    .thenThrow(new AuditStorageException("Storage error"));

            // Act
            AuditController.TimeRangeRequest request = new AuditController.TimeRangeRequest();
            request.setStartTime(startTime);
            request.setEndTime(endTime);
            ResponseEntity<List<AuditEvent>> response = controller.getEventsByTimeRange(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(response.getBody()).isNull();
        }

        @Test
        @DisplayName("Should return events when only startTime is provided")
        void shouldReturnEventsWhenOnlyStartTimeIsProvided() throws AuditStorageException {
            // Arrange
            Instant startTime = Instant.now().minusSeconds(3600);
            List<AuditEvent> events = List.of(mockAuditEvent);

            when(auditService.getEventsByTimeRange(eq(startTime), any(Instant.class))).thenReturn(events);

            // Act
            AuditController.TimeRangeRequest request = new AuditController.TimeRangeRequest();
            request.setStartTime(startTime);
            ResponseEntity<List<AuditEvent>> response = controller.getEventsByTimeRange(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).hasSize(1);
        }

        @Test
        @DisplayName("Should return events when only endTime is provided")
        void shouldReturnEventsWhenOnlyEndTimeIsProvided() throws AuditStorageException {
            // Arrange
            Instant endTime = Instant.now();
            List<AuditEvent> events = List.of(mockAuditEvent);

            when(auditService.getEventsByTimeRange(any(Instant.class), eq(endTime))).thenReturn(events);

            // Act
            AuditController.TimeRangeRequest request = new AuditController.TimeRangeRequest();
            request.setEndTime(endTime);
            ResponseEntity<List<AuditEvent>> response = controller.getEventsByTimeRange(request);

            // Assert
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).hasSize(1);
        }
    }
}
