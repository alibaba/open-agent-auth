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
package com.alibaba.openagentauth.core.audit.builder;

import com.alibaba.openagentauth.core.audit.api.AuditFilter;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import com.alibaba.openagentauth.core.model.audit.AuditContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AuditFilterBuilder Tests")
class AuditFilterBuilderTest {

    @Nested
    @DisplayName("Create Tests")
    class CreateTests {

        @Test
        @DisplayName("Should create new builder instance")
        void shouldCreateNewBuilderInstance() {
            // Act
            AuditFilterBuilder builder = AuditFilterBuilder.create();

            // Assert
            assertThat(builder).isNotNull();
        }
    }

    @Nested
    @DisplayName("EventType Tests")
    class EventTypeTests {

        @Test
        @DisplayName("Should filter by event type")
        void shouldFilterByEventType() {
            // Arrange
            AuditEvent matchingEvent = createTestEvent(AuditEventType.AUTHORIZATION_GRANTED);
            AuditEvent nonMatchingEvent = createTestEvent(AuditEventType.AUTHORIZATION_DENIED);

            AuditFilter filter = AuditFilterBuilder.create()
                .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when event type is null")
        void shouldNotFilterWhenEventTypeIsNull() {
            // Arrange
            AuditEvent event = createTestEvent(AuditEventType.AUTHORIZATION_GRANTED);

            AuditFilter filter = AuditFilterBuilder.create()
                .eventType(null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    @Nested
    @DisplayName("Severity Tests")
    class SeverityTests {

        @Test
        @DisplayName("Should filter by severity")
        void shouldFilterBySeverity() {
            // Arrange
            AuditEvent matchingEvent = createTestEvent(AuditSeverity.HIGH);
            AuditEvent nonMatchingEvent = createTestEvent(AuditSeverity.LOW);

            AuditFilter filter = AuditFilterBuilder.create()
                .severity(AuditSeverity.HIGH)
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when severity is null")
        void shouldNotFilterWhenSeverityIsNull() {
            // Arrange
            AuditEvent event = createTestEvent(AuditSeverity.HIGH);

            AuditFilter filter = AuditFilterBuilder.create()
                .severity(null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    @Nested
    @DisplayName("UserId Tests")
    class UserIdTests {

        @Test
        @DisplayName("Should filter by user ID")
        void shouldFilterByUserId() {
            // Arrange
            AuditEvent matchingEvent = createTestEventWithUserId("user123");
            AuditEvent nonMatchingEvent = createTestEventWithUserId("user456");

            AuditFilter filter = AuditFilterBuilder.create()
                .userId("user123")
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when user ID is null")
        void shouldNotFilterWhenUserIdIsNull() {
            // Arrange
            AuditEvent event = createTestEventWithUserId("user123");

            AuditFilter filter = AuditFilterBuilder.create()
                .userId(null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }

        @Test
        @DisplayName("Should not filter when context is null")
        void shouldNotFilterWhenContextIsNull() {
            // Arrange
            AuditEvent event = AuditEvent.builder()
                .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                .severity(AuditSeverity.INFO)
                .build();

            AuditFilter filter = AuditFilterBuilder.create()
                .userId("user123")
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isFalse();
        }
    }

    @Nested
    @DisplayName("AgentId Tests")
    class AgentIdTests {

        @Test
        @DisplayName("Should filter by agent ID")
        void shouldFilterByAgentId() {
            // Arrange
            AuditEvent matchingEvent = createTestEventWithAgentId("agent123");
            AuditEvent nonMatchingEvent = createTestEventWithAgentId("agent456");

            AuditFilter filter = AuditFilterBuilder.create()
                .agentId("agent123")
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when agent ID is null")
        void shouldNotFilterWhenAgentIdIsNull() {
            // Arrange
            AuditEvent event = createTestEventWithAgentId("agent123");

            AuditFilter filter = AuditFilterBuilder.create()
                .agentId(null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    @Nested
    @DisplayName("SessionId Tests")
    class SessionIdTests {

        @Test
        @DisplayName("Should filter by session ID")
        void shouldFilterBySessionId() {
            // Arrange
            AuditEvent matchingEvent = createTestEventWithSessionId("session123");
            AuditEvent nonMatchingEvent = createTestEventWithSessionId("session456");

            AuditFilter filter = AuditFilterBuilder.create()
                .sessionId("session123")
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when session ID is null")
        void shouldNotFilterWhenSessionIdIsNull() {
            // Arrange
            AuditEvent event = createTestEventWithSessionId("session123");

            AuditFilter filter = AuditFilterBuilder.create()
                .sessionId(null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    @Nested
    @DisplayName("TimeRange Tests")
    class TimeRangeTests {

        @Test
        @DisplayName("Should filter by time range")
        void shouldFilterByTimeRange() {
            // Arrange
            Instant startTime = Instant.parse("2024-01-01T00:00:00Z");
            Instant endTime = Instant.parse("2024-01-01T23:59:59Z");
            
            AuditEvent matchingEvent = createTestEvent(Instant.parse("2024-01-01T12:00:00Z"));
            AuditEvent beforeEvent = createTestEvent(Instant.parse("2023-12-31T23:59:59Z"));
            AuditEvent afterEvent = createTestEvent(Instant.parse("2024-01-02T00:00:00Z"));

            AuditFilter filter = AuditFilterBuilder.create()
                .timeRange(startTime, endTime)
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(beforeEvent)).isFalse();
            assertThat(filter.matches(afterEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when time range is null")
        void shouldNotFilterWhenTimeRangeIsNull() {
            // Arrange
            AuditEvent event = createTestEvent(Instant.now());

            AuditFilter filter = AuditFilterBuilder.create()
                .timeRange(null, null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    @Nested
    @DisplayName("Custom Tests")
    class CustomTests {

        @Test
        @DisplayName("Should filter by custom predicate")
        void shouldFilterByCustomPredicate() {
            // Arrange
            AuditEvent matchingEvent = createTestEventWithMessage("test message");
            AuditEvent nonMatchingEvent = createTestEventWithMessage("other message");

            AuditFilter filter = AuditFilterBuilder.create()
                .custom(event -> "test message".equals(event.getMessage()))
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent)).isFalse();
        }

        @Test
        @DisplayName("Should not filter when custom predicate is null")
        void shouldNotFilterWhenCustomPredicateIsNull() {
            // Arrange
            AuditEvent event = createTestEvent();

            AuditFilter filter = AuditFilterBuilder.create()
                .custom(null)
                .build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    @Nested
    @DisplayName("RequiresImmediateAttention Tests")
    class RequiresImmediateAttentionTests {

        @Test
        @DisplayName("Should filter events requiring immediate attention")
        void shouldFilterEventsRequiringImmediateAttention() {
            // Arrange
            AuditEvent highEvent = createTestEvent(AuditSeverity.HIGH);
            AuditEvent criticalEvent = createTestEvent(AuditSeverity.CRITICAL);
            AuditEvent lowEvent = createTestEvent(AuditSeverity.LOW);

            AuditFilter filter = AuditFilterBuilder.create()
                .requiresImmediateAttention()
                .build();

            // Act & Assert
            assertThat(filter.matches(highEvent)).isTrue();
            assertThat(filter.matches(criticalEvent)).isTrue();
            assertThat(filter.matches(lowEvent)).isFalse();
        }
    }

    @Nested
    @DisplayName("Chaining Tests")
    class ChainingTests {

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            // Arrange
            AuditEvent matchingEvent = createTestEventWithUserIdAndSeverity("user123", AuditSeverity.HIGH);
            AuditEvent nonMatchingEvent1 = createTestEventWithUserIdAndSeverity("user456", AuditSeverity.HIGH);
            AuditEvent nonMatchingEvent2 = createTestEventWithUserIdAndSeverity("user123", AuditSeverity.LOW);

            AuditFilter filter = AuditFilterBuilder.create()
                .userId("user123")
                .severity(AuditSeverity.HIGH)
                .eventType(AuditEventType.SECURITY_VIOLATION)
                .build();

            // Act & Assert
            assertThat(filter.matches(matchingEvent)).isTrue();
            assertThat(filter.matches(nonMatchingEvent1)).isFalse();
            assertThat(filter.matches(nonMatchingEvent2)).isFalse();
        }
    }

    @Nested
    @DisplayName("Build Tests")
    class BuildTests {

        @Test
        @DisplayName("Should build filter that accepts all events when no criteria specified")
        void shouldBuildFilterThatAcceptsAllEventsWhenNoCriteriaSpecified() {
            // Arrange
            AuditEvent event = createTestEvent();

            AuditFilter filter = AuditFilterBuilder.create().build();

            // Act & Assert
            assertThat(filter.matches(event)).isTrue();
        }
    }

    // Helper methods
    private AuditEvent createTestEvent() {
        return createTestEvent(Instant.now());
    }

    private AuditEvent createTestEvent(AuditEventType eventType) {
        return AuditEvent.builder()
            .eventType(eventType)
            .severity(AuditSeverity.INFO)
            .timestamp(Instant.now().toString())
            .build();
    }

    private AuditEvent createTestEvent(AuditSeverity severity) {
        return AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
            .severity(severity)
            .timestamp(Instant.now().toString())
            .build();
    }

    private AuditEvent createTestEvent(Instant timestamp) {
        return AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
            .severity(AuditSeverity.INFO)
            .timestamp(timestamp.toString())
            .build();
    }

    private AuditEvent createTestEventWithUserId(String userId) {
        AuditContext context = AuditContext.builder()
            .userId(userId)
            .build();
        return AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
            .severity(AuditSeverity.INFO)
            .context(context)
            .build();
    }

    private AuditEvent createTestEventWithAgentId(String agentId) {
        AuditContext context = AuditContext.builder()
            .agentId(agentId)
            .build();
        return AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
            .severity(AuditSeverity.INFO)
            .context(context)
            .build();
    }

    private AuditEvent createTestEventWithSessionId(String sessionId) {
        AuditContext context = AuditContext.builder()
            .sessionId(sessionId)
            .build();
        return AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
            .severity(AuditSeverity.INFO)
            .context(context)
            .build();
    }

    private AuditEvent createTestEventWithMessage(String message) {
        return AuditEvent.builder()
            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
            .severity(AuditSeverity.INFO)
            .message(message)
            .build();
    }

    private AuditEvent createTestEventWithUserIdAndSeverity(String userId, AuditSeverity severity) {
        AuditContext context = AuditContext.builder()
            .userId(userId)
            .build();
        return AuditEvent.builder()
            .eventType(AuditEventType.SECURITY_VIOLATION)
            .severity(severity)
            .context(context)
            .build();
    }
}