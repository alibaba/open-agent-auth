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

import com.alibaba.openagentauth.core.model.audit.AuditEvent;
import com.alibaba.openagentauth.core.model.audit.AuditEventType;
import com.alibaba.openagentauth.core.model.audit.AuditSeverity;
import com.alibaba.openagentauth.core.model.audit.AuditTrail;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for {@link AuditEventBuilder}.
 * <p>
 * This test class validates the fluent API for building audit events,
 * including all field setters, method chaining, and edge cases.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuditEventBuilder Tests")
class AuditEventBuilderTest {

    @Nested
    @DisplayName("Builder Creation Tests")
    class BuilderCreationTests {

        @Test
        @DisplayName("Should create new builder instance")
        void shouldCreateNewBuilderInstance() {
            AuditEventBuilder builder = AuditEventBuilder.create();

            assertThat(builder).isNotNull();
        }

        @Test
        @DisplayName("Should create multiple independent builder instances")
        void shouldCreateMultipleIndependentBuilderInstances() {
            AuditEventBuilder builder1 = AuditEventBuilder.create();
            AuditEventBuilder builder2 = AuditEventBuilder.create();

            assertThat(builder1).isNotSameAs(builder2);
        }
    }

    @Nested
    @DisplayName("Event Field Tests")
    class EventFieldTests {

        @Test
        @DisplayName("Should build event with event ID")
        void shouldBuildEventWithEventId() {
            AuditEvent event = AuditEventBuilder.create()
                    .eventId("event-001")
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .build();

            assertThat(event.getEventId()).isEqualTo("event-001");
        }

        @Test
        @DisplayName("Should build event with timestamp string")
        void shouldBuildEventWithTimestampString() {
            String timestamp = "2024-01-01T00:00:00Z";
            AuditEvent event = AuditEventBuilder.create()
                    .timestamp(timestamp)
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .build();

            assertThat(event.getTimestamp()).isEqualTo(timestamp);
        }

        @Test
        @DisplayName("Should build event with timestamp instant")
        void shouldBuildEventWithTimestampInstant() {
            Instant instant = Instant.now();
            AuditEvent event = AuditEventBuilder.create()
                    .timestamp(instant)
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .build();

            assertThat(event.getTimestamp()).isEqualTo(instant.toString());
        }

        @Test
        @DisplayName("Should build event with event type")
        void shouldBuildEventWithEventType() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_DENIED)
                    .severity(AuditSeverity.MEDIUM)
                    .message("Test event")
                    .build();

            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_DENIED);
        }

        @Test
        @DisplayName("Should build event with severity")
        void shouldBuildEventWithSeverity() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Test event")
                    .build();

            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.HIGH);
        }

        @Test
        @DisplayName("Should build event with message")
        void shouldBuildEventWithMessage() {
            String message = "Authorization granted for user";
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message(message)
                    .build();

            assertThat(event.getMessage()).isEqualTo(message);
        }

        @Test
        @DisplayName("Should build event with audit trail")
        void shouldBuildEventWithAuditTrail() {
            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Buy something cheap")
                    .renderedOperationText("Purchase under $50")
                    .build();
            
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .trail(trail)
                    .build();

            assertThat(event.getTrail()).isNotNull();
            assertThat(event.getTrail().getOriginalPromptText()).isEqualTo("Buy something cheap");
        }
    }

    @Nested
    @DisplayName("Context Field Tests")
    class ContextFieldTests {

        @Test
        @DisplayName("Should build event with user ID")
        void shouldBuildEventWithUserId() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .userId("user123")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getUserId()).isEqualTo("user123");
        }

        @Test
        @DisplayName("Should build event with agent ID")
        void shouldBuildEventWithAgentId() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .agentId("agent456")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getAgentId()).isEqualTo("agent456");
        }

        @Test
        @DisplayName("Should build event with session ID")
        void shouldBuildEventWithSessionId() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .sessionId("session789")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getSessionId()).isEqualTo("session789");
        }

        @Test
        @DisplayName("Should build event with request ID")
        void shouldBuildEventWithRequestId() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .requestId("request123")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getRequestId()).isEqualTo("request123");
        }

        @Test
        @DisplayName("Should build event with client IP address")
        void shouldBuildEventWithClientIpAddress() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .clientIpAddress("192.168.1.1")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getClientIpAddress()).isEqualTo("192.168.1.1");
        }

        @Test
        @DisplayName("Should build event with user agent")
        void shouldBuildEventWithUserAgent() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .userAgent("TestAgent/1.0")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getUserAgent()).isEqualTo("TestAgent/1.0");
        }

        @Test
        @DisplayName("Should build event with context metadata")
        void shouldBuildEventWithContextMetadata() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .addContextMetadata("key1", "value1")
                    .addContextMetadata("key2", "value2")
                    .build();

            assertThat(event.getContext()).isNotNull();
            assertThat(event.getContext().getMetadata()).hasSize(2);
            assertThat(event.getContext().getMetadata()).containsEntry("key1", "value1");
            assertThat(event.getContext().getMetadata()).containsEntry("key2", "value2");
        }
    }

    @Nested
    @DisplayName("Data Field Tests")
    class DataFieldTests {

        @Test
        @DisplayName("Should build event with single data entry")
        void shouldBuildEventWithSingleDataEntry() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .addData("resource", "/api/orders")
                    .build();

            assertThat(event.getData()).isNotNull();
            assertThat(event.getData()).hasSize(1);
            assertThat(event.getData()).containsEntry("resource", "/api/orders");
        }

        @Test
        @DisplayName("Should build event with multiple data entries")
        void shouldBuildEventWithMultipleDataEntries() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .addData("resource", "/api/orders")
                    .addData("method", "POST")
                    .addData("status", "200")
                    .build();

            assertThat(event.getData()).isNotNull();
            assertThat(event.getData()).hasSize(3);
            assertThat(event.getData()).containsEntry("resource", "/api/orders");
            assertThat(event.getData()).containsEntry("method", "POST");
            assertThat(event.getData()).containsEntry("status", "200");
        }

        @Test
        @DisplayName("Should build event with data map")
        void shouldBuildEventWithDataMap() {
            Map<String, Object> data = new HashMap<>();
            data.put("resource", "/api/orders");
            data.put("method", "POST");

            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .data(data)
                    .build();

            assertThat(event.getData()).isNotNull();
            assertThat(event.getData()).hasSize(2);
            assertThat(event.getData()).containsEntry("resource", "/api/orders");
            assertThat(event.getData()).containsEntry("method", "POST");
        }

        @Test
        @DisplayName("Should overwrite data when using data map")
        void shouldOverwriteDataWhenUsingDataMap() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .addData("key1", "value1")
                    .addData("key2", "value2")
                    .data(Map.of("key3", "value3", "key4", "value4"))
                    .build();

            assertThat(event.getData()).isNotNull();
            assertThat(event.getData()).hasSize(2);
            assertThat(event.getData()).containsEntry("key3", "value3");
            assertThat(event.getData()).containsEntry("key4", "value4");
            assertThat(event.getData()).doesNotContainKey("key1");
            assertThat(event.getData()).doesNotContainKey("key2");
        }

        @Test
        @DisplayName("Should build event without data when not set")
        void shouldBuildEventWithoutDataWhenNotSet() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .build();

            assertThat(event.getData()).isNull();
        }

        @Test
        @DisplayName("Should build event with empty data map")
        void shouldBuildEventWithEmptyDataMap() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .data(new HashMap<>())
                    .build();

            assertThat(event.getData()).isNull();
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            AuditEventBuilder builder = AuditEventBuilder.create();
            AuditEventBuilder result = builder
                    .eventId("event-001")
                    .timestamp(Instant.now())
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .userId("user123")
                    .agentId("agent456");

            assertThat(result).isSameAs(builder);
        }

        @Test
        @DisplayName("Should build complete event with chaining")
        void shouldBuildCompleteEventWithChaining() {
            AuditEvent event = AuditEventBuilder.create()
                    .eventId("event-001")
                    .timestamp(Instant.now())
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Authorization granted")
                    .userId("user123")
                    .agentId("agent456")
                    .sessionId("session789")
                    .requestId("request123")
                    .clientIpAddress("192.168.1.1")
                    .userAgent("TestAgent/1.0")
                    .addData("resource", "/api/orders")
                    .addContextMetadata("metadata1", "value1")
                    .build();

            assertThat(event.getEventId()).isEqualTo("event-001");
            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event.getMessage()).isEqualTo("Authorization granted");
            assertThat(event.getContext().getUserId()).isEqualTo("user123");
            assertThat(event.getContext().getAgentId()).isEqualTo("agent456");
            assertThat(event.getContext().getSessionId()).isEqualTo("session789");
            assertThat(event.getContext().getRequestId()).isEqualTo("request123");
            assertThat(event.getContext().getClientIpAddress()).isEqualTo("192.168.1.1");
            assertThat(event.getContext().getUserAgent()).isEqualTo("TestAgent/1.0");
            assertThat(event.getData()).containsEntry("resource", "/api/orders");
            assertThat(event.getContext().getMetadata()).containsEntry("metadata1", "value1");
        }
    }

    @Nested
    @DisplayName("Configure Method Tests")
    class ConfigureMethodTests {

        @Test
        @DisplayName("Should apply consumer function")
        void shouldApplyConsumerFunction() {
            AuditEvent event = AuditEventBuilder.create()
                    .configure(builder -> {
                        builder.type(AuditEventType.AUTHORIZATION_GRANTED)
                                .severity(AuditSeverity.INFO)
                                .message("Configured event")
                                .userId("configured-user");
                    })
                    .build();

            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event.getMessage()).isEqualTo("Configured event");
            assertThat(event.getContext().getUserId()).isEqualTo("configured-user");
        }

        @Test
        @DisplayName("Should support multiple configure calls")
        void shouldSupportMultipleConfigureCalls() {
            AuditEvent event = AuditEventBuilder.create()
                    .configure(builder -> {
                        builder.type(AuditEventType.AUTHORIZATION_GRANTED)
                                .severity(AuditSeverity.INFO);
                    })
                    .configure(builder -> {
                        builder.message("Multi-configured event")
                                .userId("user123");
                    })
                    .build();

            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event.getMessage()).isEqualTo("Multi-configured event");
            assertThat(event.getContext().getUserId()).isEqualTo("user123");
        }

        @Test
        @DisplayName("Should throw exception when consumer is null")
        void shouldThrowExceptionWhenConsumerIsNull() {
            assertThatThrownBy(() -> AuditEventBuilder.create().configure(null))
                    .isInstanceOf(NullPointerException.class);
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should build event with empty string fields")
        void shouldBuildEventWithEmptyStringFields() {
            AuditEvent event = AuditEventBuilder.create()
                    .eventId("")
                    .userId("")
                    .agentId("")
                    .sessionId("")
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("")
                    .build();

            assertThat(event.getEventId()).isEmpty();
            assertThat(event.getContext().getUserId()).isEmpty();
            assertThat(event.getContext().getAgentId()).isEmpty();
            assertThat(event.getContext().getSessionId()).isEmpty();
            assertThat(event.getMessage()).isEmpty();
        }

        @Test
        @DisplayName("Should build event with null values in data")
        void shouldBuildEventWithNullValuesInData() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .addData("key1", null)
                    .addData("key2", "value2")
                    .build();

            assertThat(event.getData()).hasSize(2);
            assertThat(event.getData()).containsEntry("key1", null);
            assertThat(event.getData()).containsEntry("key2", "value2");
        }

        @Test
        @DisplayName("Should build event without context fields")
        void shouldBuildEventWithoutContextFields() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Test event")
                    .build();

            assertThat(event.getContext()).isNotNull();
        }

        @Test
        @DisplayName("Should build event with different event types")
        void shouldBuildEventWithDifferentEventTypes() {
            AuditEvent event1 = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Granted")
                    .build();

            AuditEvent event2 = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_DENIED)
                    .severity(AuditSeverity.MEDIUM)
                    .message("Denied")
                    .build();

            AuditEvent event3 = AuditEventBuilder.create()
                    .type(AuditEventType.POLICY_EVALUATION_SUCCESS)
                    .severity(AuditSeverity.INFO)
                    .message("Issued")
                    .build();

            assertThat(event1.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event2.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_DENIED);
            assertThat(event3.getEventType()).isEqualTo(AuditEventType.POLICY_EVALUATION_SUCCESS);
        }

        @Test
        @DisplayName("Should build event with different severity levels")
        void shouldBuildEventWithDifferentSeverityLevels() {
            AuditEvent event1 = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Info")
                    .build();

            AuditEvent event2 = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_DENIED)
                    .severity(AuditSeverity.MEDIUM)
                    .message("Warning")
                    .build();

            AuditEvent event3 = AuditEventBuilder.create()
                    .type(AuditEventType.EVALUATION_ERROR)
                    .severity(AuditSeverity.HIGH)
                    .message("Error")
                    .build();

            assertThat(event1.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event2.getSeverity()).isEqualTo(AuditSeverity.MEDIUM);
            assertThat(event3.getSeverity()).isEqualTo(AuditSeverity.HIGH);
        }
    }

    @Nested
    @DisplayName("Immutability Tests")
    class ImmutabilityTests {

        @Test
        @DisplayName("Should create independent events from same builder")
        void shouldCreateIndependentEventsFromSameBuilder() {
            AuditEventBuilder builder = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO);

            AuditEvent event1 = builder.message("Event 1").build();
            AuditEvent event2 = builder.message("Event 2").build();

            assertThat(event1.getMessage()).isEqualTo("Event 1");
            assertThat(event2.getMessage()).isEqualTo("Event 2");
            assertThat(event1).isNotSameAs(event2);
        }

        @Test
        @DisplayName("Should not modify built event after building")
        void shouldNotModifyBuiltEventAfterBuilding() {
            AuditEventBuilder builder = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Original message");

            AuditEvent event1 = builder.build();
            builder.message("Modified message");
            AuditEvent event2 = builder.build();

            assertThat(event1.getMessage()).isEqualTo("Original message");
            assertThat(event2.getMessage()).isEqualTo("Modified message");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should build complete audit event for authorization granted")
        void shouldBuildCompleteAuditEventForAuthorizationGranted() {
            AuditEvent event = AuditEventBuilder.create()
                    .eventId("auth-granted-001")
                    .timestamp(Instant.now())
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Authorization granted for user user123")
                    .userId("user123")
                    .agentId("agent456")
                    .sessionId("session789")
                    .requestId("request123")
                    .clientIpAddress("192.168.1.100")
                    .userAgent("Mozilla/5.0")
                    .addData("resource", "/api/orders")
                    .addData("action", "read")
                    .addData("decision", "allow")
                    .addContextMetadata("authMethod", "oauth2")
                    .addContextMetadata("scope", "read:orders")
                    .build();

            assertThat(event.getEventId()).isEqualTo("auth-granted-001");
            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event.getMessage()).isEqualTo("Authorization granted for user user123");
            assertThat(event.getContext().getUserId()).isEqualTo("user123");
            assertThat(event.getContext().getAgentId()).isEqualTo("agent456");
            assertThat(event.getContext().getSessionId()).isEqualTo("session789");
            assertThat(event.getContext().getRequestId()).isEqualTo("request123");
            assertThat(event.getContext().getClientIpAddress()).isEqualTo("192.168.1.100");
            assertThat(event.getContext().getUserAgent()).isEqualTo("Mozilla/5.0");
            assertThat(event.getData()).hasSize(3);
            assertThat(event.getContext().getMetadata()).hasSize(2);
        }

        @Test
        @DisplayName("Should build complete audit event for authorization denied")
        void shouldBuildCompleteAuditEventForAuthorizationDenied() {
            AuditEvent event = AuditEventBuilder.create()
                    .eventId("auth-denied-001")
                    .timestamp(Instant.now())
                    .type(AuditEventType.AUTHORIZATION_DENIED)
                    .severity(AuditSeverity.MEDIUM)
                    .message("Authorization denied for user user456")
                    .userId("user456")
                    .agentId("agent789")
                    .addData("resource", "/api/admin")
                    .addData("action", "delete")
                    .addData("reason", "insufficient permissions")
                    .build();

            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_DENIED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.MEDIUM);
            assertThat(event.getData()).hasSize(3);
            assertThat(event.getData()).containsEntry("reason", "insufficient permissions");
        }

        @Test
        @DisplayName("Should build minimal audit event")
        void shouldBuildMinimalAuditEvent() {
            AuditEvent event = AuditEventBuilder.create()
                    .type(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.INFO)
                    .message("Minimal event")
                    .build();

            assertThat(event.getEventType()).isEqualTo(AuditEventType.AUTHORIZATION_GRANTED);
            assertThat(event.getSeverity()).isEqualTo(AuditSeverity.INFO);
            assertThat(event.getMessage()).isEqualTo("Minimal event");
            assertThat(event.getContext()).isNotNull();
        }
    }
}
