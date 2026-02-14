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
package com.alibaba.openagentauth.core.model.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AuditEvent Tests")
class AuditEventTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build AuditEvent with required fields")
        void shouldBuildAuditEventWithRequiredFields() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotNull(event);
            assertNotNull(event.getEventId());
            assertNotNull(event.getTimestamp());
            assertEquals(AuditEventType.AUTHORIZATION_GRANTED, event.getEventType());
            assertEquals(AuditSeverity.HIGH, event.getSeverity());
        }

        @Test
        @DisplayName("Should build AuditEvent with all fields")
        void shouldBuildAuditEventWithAllFields() {
            AuditContext context = AuditContext.builder()
                    .userId("user123")
                    .agentId("agent456")
                    .build();

            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Buy something cheap")
                    .renderedOperationText("Purchase under $50")
                    .build();

            Map<String, Object> data = new HashMap<>();
            data.put("resourceId", "res789");
            data.put("operation", "read");

            AuditEvent event = AuditEvent.builder()
                    .eventId("evt-001")
                    .timestamp("2025-11-11T10:30:00Z")
                    .eventType(AuditEventType.RESOURCE_ACCESS_GRANTED)
                    .severity(AuditSeverity.MEDIUM)
                    .message("Resource access granted")
                    .context(context)
                    .trail(trail)
                    .data(data)
                    .build();

            assertEquals("evt-001", event.getEventId());
            assertEquals("2025-11-11T10:30:00Z", event.getTimestamp());
            assertEquals(AuditEventType.RESOURCE_ACCESS_GRANTED, event.getEventType());
            assertEquals(AuditSeverity.MEDIUM, event.getSeverity());
            assertEquals("Resource access granted", event.getMessage());
            assertEquals(context, event.getContext());
            assertEquals(trail, event.getTrail());
            assertEquals(data, event.getData());
        }

        @Test
        @DisplayName("Should generate random eventId when not specified")
        void shouldGenerateRandomEventIdWhenNotSpecified() {
            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotNull(event1.getEventId());
            assertNotNull(event2.getEventId());
            assertNotEquals(event1.getEventId(), event2.getEventId());
        }

        @Test
        @DisplayName("Should generate current timestamp when not specified")
        void shouldGenerateCurrentTimestampWhenNotSpecified() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotNull(event.getTimestamp());
            assertTrue(event.getTimestamp().matches("\\d{4}-\\d{2}-\\d{2}T.*Z"));
        }

        @Test
        @DisplayName("Should throw exception when eventType is not set")
        void shouldThrowExceptionWhenEventTypeIsNotSet() {
            IllegalStateException exception = assertThrows(
                    IllegalStateException.class,
                    () -> AuditEvent.builder()
                            .severity(AuditSeverity.HIGH)
                            .build()
            );

            assertEquals("eventType is required", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception when severity is not set")
        void shouldThrowExceptionWhenSeverityIsNotSet() {
            IllegalStateException exception = assertThrows(
                    IllegalStateException.class,
                    () -> AuditEvent.builder()
                            .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                            .build()
            );

            assertEquals("severity is required", exception.getMessage());
        }

        @Test
        @DisplayName("Should add data using addData method")
        void shouldAddDataUsingAddDataMethod() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .addData("key1", "value1")
                    .addData("key2", 123)
                    .build();

            assertNotNull(event.getData());
            assertEquals(2, event.getData().size());
            assertEquals("value1", event.getData().get("key1"));
            assertEquals(123, event.getData().get("key2"));
        }

        @Test
        @DisplayName("Should set all data using data method")
        void shouldSetAllDataUsingDataMethod() {
            Map<String, Object> data = new HashMap<>();
            data.put("key1", "value1");
            data.put("key2", 123);

            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .data(data)
                    .build();

            assertEquals(data, event.getData());
        }

        @Test
        @DisplayName("Should support fluent builder pattern")
        void shouldSupportFluentBuilderPattern() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .message("Authorization granted")
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertEquals("Authorization granted", event.getMessage());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return null for optional fields not set")
        void shouldReturnNullForOptionalFieldsNotSet() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNull(event.getMessage());
            assertNull(event.getContext());
            assertNull(event.getTrail());
            assertNull(event.getData());
        }

        @Test
        @DisplayName("Should return copy of data map")
        void shouldReturnCopyOfDataMap() {
            Map<String, Object> originalData = new HashMap<>();
            originalData.put("key", "value");

            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .data(originalData)
                    .build();

            Map<String, Object> retrievedData = event.getData();
            
            // Verify that we get a copy (not the same reference)
            assertNotSame(originalData, retrievedData);
            
            // Verify the contents are the same
            assertEquals(originalData, retrievedData);
            
            // Verify that modifying the returned map doesn't affect the original
            retrievedData.put("newKey", "newValue");
            assertEquals(1, originalData.size());
            assertFalse(originalData.containsKey("newKey"));
            
            // Verify that the event's data remains unchanged
            Map<String, Object> eventData = event.getData();
            assertEquals(1, eventData.size());
            assertFalse(eventData.containsKey("newKey"));
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            AuditEvent event1 = AuditEvent.builder()
                    .eventId("evt-001")
                    .timestamp("2025-11-11T10:30:00Z")
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Test message")
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventId("evt-001")
                    .timestamp("2025-11-11T10:30:00Z")
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Test message")
                    .build();

            assertEquals(event1, event2);
            assertEquals(event1.hashCode(), event2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when eventId differs")
        void shouldNotBeEqualWhenEventIdDiffers() {
            AuditEvent event1 = AuditEvent.builder()
                    .eventId("evt-001")
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventId("evt-002")
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should not be equal when eventType differs")
        void shouldNotBeEqualWhenEventTypeDiffers() {
            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_DENIED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should not be equal when severity differs")
        void shouldNotBeEqualWhenSeverityDiffers() {
            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.LOW)
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should not be equal when message differs")
        void shouldNotBeEqualWhenMessageDiffers() {
            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Message 1")
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Message 2")
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should not be equal when context differs")
        void shouldNotBeEqualWhenContextDiffers() {
            AuditContext context1 = AuditContext.builder().userId("user1").build();
            AuditContext context2 = AuditContext.builder().userId("user2").build();

            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .context(context1)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .context(context2)
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should not be equal when trail differs")
        void shouldNotBeEqualWhenTrailDiffers() {
            AuditTrail trail1 = AuditTrail.builder()
                    .originalPromptText("Prompt 1")
                    .build();

            AuditTrail trail2 = AuditTrail.builder()
                    .originalPromptText("Prompt 2")
                    .build();

            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .trail(trail1)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .trail(trail2)
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should not be equal when data differs")
        void shouldNotBeEqualWhenDataDiffers() {
            Map<String, Object> data1 = new HashMap<>();
            data1.put("key", "value1");

            Map<String, Object> data2 = new HashMap<>();
            data2.put("key", "value2");

            AuditEvent event1 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .data(data1)
                    .build();

            AuditEvent event2 = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .data(data2)
                    .build();

            assertNotEquals(event1, event2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertEquals(event, event);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotEquals(event, null);
        }

        @Test
        @DisplayName("Should not be equal to different class")
        void shouldNotBeEqualToDifferentClass() {
            AuditEvent event = AuditEvent.builder()
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .build();

            assertNotEquals(event, "string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            AuditEvent event = AuditEvent.builder()
                    .eventId("evt-001")
                    .timestamp("2025-11-11T10:30:00Z")
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Test message")
                    .build();

            String toString = event.toString();

            assertTrue(toString.contains("evt-001"));
            assertTrue(toString.contains("2025-11-11T10:30:00Z"));
            assertTrue(toString.contains("AUTHORIZATION_GRANTED"));
            assertTrue(toString.contains("HIGH"));
            assertTrue(toString.contains("Test message"));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should create complete audit event with context and trail")
        void shouldCreateCompleteAuditEventWithContextAndTrail() {
            AuditContext context = AuditContext.builder()
                    .userId("user123")
                    .agentId("agent456")
                    .sessionId("session789")
                    .requestId("req001")
                    .clientIpAddress("192.168.1.1")
                    .userAgent("Mozilla/5.0")
                    .addMetadata("customKey", "customValue")
                    .build();

            AuditTrail trail = AuditTrail.builder()
                    .originalPromptText("Buy winter clothes")
                    .renderedOperationText("Purchase items under $100")
                    .semanticExpansionLevel("low")
                    .userAcknowledgeTimestamp("2025-11-11T10:33:00Z")
                    .consentInterfaceVersion("1.0")
                    .build();

            AuditEvent event = AuditEvent.builder()
                    .eventId("evt-complete")
                    .timestamp("2025-11-11T10:30:00Z")
                    .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                    .severity(AuditSeverity.HIGH)
                    .message("Authorization granted for shopping operation")
                    .context(context)
                    .trail(trail)
                    .addData("operation", "purchase")
                    .addData("limit", 100)
                    .build();

            assertNotNull(event);
            assertEquals("evt-complete", event.getEventId());
            assertEquals(AuditEventType.AUTHORIZATION_GRANTED, event.getEventType());
            assertEquals(AuditSeverity.HIGH, event.getSeverity());
            assertEquals("Authorization granted for shopping operation", event.getMessage());
            assertNotNull(event.getContext());
            assertNotNull(event.getTrail());
            assertNotNull(event.getData());
            assertEquals(2, event.getData().size());
        }

        @Test
        @DisplayName("Should handle all event types")
        void shouldHandleAllEventTypes() {
            AuditEventType[] eventTypes = AuditEventType.values();

            for (AuditEventType eventType : eventTypes) {
                AuditEvent event = AuditEvent.builder()
                        .eventType(eventType)
                        .severity(AuditSeverity.INFO)
                        .build();

                assertEquals(eventType, event.getEventType());
            }
        }

        @Test
        @DisplayName("Should handle all severity levels")
        void shouldHandleAllSeverityLevels() {
            AuditSeverity[] severities = AuditSeverity.values();

            for (AuditSeverity severity : severities) {
                AuditEvent event = AuditEvent.builder()
                        .eventType(AuditEventType.AUTHORIZATION_GRANTED)
                        .severity(severity)
                        .build();

                assertEquals(severity, event.getSeverity());
            }
        }
    }
}
