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
package com.alibaba.openagentauth.framework.model.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuditLogEntry}.
 */
@DisplayName("AuditLogEntry Tests")
class AuditLogEntryTest {

    private static final Instant TIMESTAMP = Instant.now();
    private static final String USER_ID = "user-123";
    private static final String WORKLOAD_ID = "workload-456";
    private static final String OPERATION_TYPE = "query";
    private static final String RESOURCE_ID = "resource-789";
    private static final String DECISION = "allow";
    private static final String REASON = "Policy allows access";
    private static final String IP_ADDRESS = "192.168.1.1";
    private static final String USER_AGENT = "Mozilla/5.0";

    @Nested
    @DisplayName("Constructor")
    class Constructor {

        @Test
        @DisplayName("Should create audit log entry with all parameters")
        void shouldCreateAuditLogEntryWithAllParameters() {
            // Act
            AuditLogEntry entry = new AuditLogEntry(
                    TIMESTAMP, USER_ID, WORKLOAD_ID, OPERATION_TYPE,
                    RESOURCE_ID, DECISION, REASON, IP_ADDRESS, USER_AGENT
            );

            // Assert
            assertThat(entry).isNotNull();
            assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
            assertThat(entry.getUserId()).isEqualTo(USER_ID);
            assertThat(entry.getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(entry.getOperationType()).isEqualTo(OPERATION_TYPE);
            assertThat(entry.getResourceId()).isEqualTo(RESOURCE_ID);
            assertThat(entry.getDecision()).isEqualTo(DECISION);
            assertThat(entry.getReason()).isEqualTo(REASON);
            assertThat(entry.getIpAddress()).isEqualTo(IP_ADDRESS);
            assertThat(entry.getUserAgent()).isEqualTo(USER_AGENT);
        }

        @Test
        @DisplayName("Should create audit log entry with null optional parameters")
        void shouldCreateAuditLogEntryWithNullOptionalParameters() {
            // Act
            AuditLogEntry entry = new AuditLogEntry(
                    TIMESTAMP, USER_ID, WORKLOAD_ID, OPERATION_TYPE,
                    RESOURCE_ID, DECISION, null, null, null
            );

            // Assert
            assertThat(entry).isNotNull();
            assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
            assertThat(entry.getUserId()).isEqualTo(USER_ID);
            assertThat(entry.getReason()).isNull();
            assertThat(entry.getIpAddress()).isNull();
            assertThat(entry.getUserAgent()).isNull();
        }
    }

    @Nested
    @DisplayName("Builder")
    class Builder {

        @Test
        @DisplayName("Should build audit log entry with all fields")
        void shouldBuildAuditLogEntryWithAllFields() {
            // Act
            AuditLogEntry entry = AuditLogEntry.builder()
                    .timestamp(TIMESTAMP)
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .operationType(OPERATION_TYPE)
                    .resourceId(RESOURCE_ID)
                    .decision(DECISION)
                    .reason(REASON)
                    .ipAddress(IP_ADDRESS)
                    .userAgent(USER_AGENT)
                    .build();

            // Assert
            assertThat(entry).isNotNull();
            assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
            assertThat(entry.getUserId()).isEqualTo(USER_ID);
            assertThat(entry.getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(entry.getOperationType()).isEqualTo(OPERATION_TYPE);
            assertThat(entry.getResourceId()).isEqualTo(RESOURCE_ID);
            assertThat(entry.getDecision()).isEqualTo(DECISION);
            assertThat(entry.getReason()).isEqualTo(REASON);
            assertThat(entry.getIpAddress()).isEqualTo(IP_ADDRESS);
            assertThat(entry.getUserAgent()).isEqualTo(USER_AGENT);
        }

        @Test
        @DisplayName("Should build audit log entry with required fields only")
        void shouldBuildAuditLogEntryWithRequiredFieldsOnly() {
            // Act
            AuditLogEntry entry = AuditLogEntry.builder()
                    .timestamp(TIMESTAMP)
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .operationType(OPERATION_TYPE)
                    .resourceId(RESOURCE_ID)
                    .decision(DECISION)
                    .build();

            // Assert
            assertThat(entry).isNotNull();
            assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
            assertThat(entry.getUserId()).isEqualTo(USER_ID);
            assertThat(entry.getWorkloadId()).isEqualTo(WORKLOAD_ID);
            assertThat(entry.getOperationType()).isEqualTo(OPERATION_TYPE);
            assertThat(entry.getResourceId()).isEqualTo(RESOURCE_ID);
            assertThat(entry.getDecision()).isEqualTo(DECISION);
            assertThat(entry.getReason()).isNull();
            assertThat(entry.getIpAddress()).isNull();
            assertThat(entry.getUserAgent()).isNull();
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            // Act
            AuditLogEntry.Builder builder = AuditLogEntry.builder()
                    .timestamp(TIMESTAMP)
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID);

            assertThat(builder).isNotNull();

            AuditLogEntry entry = builder
                    .operationType(OPERATION_TYPE)
                    .resourceId(RESOURCE_ID)
                    .decision(DECISION)
                    .build();

            // Assert
            assertThat(entry).isNotNull();
            assertThat(entry.getOperationType()).isEqualTo(OPERATION_TYPE);
            assertThat(entry.getResourceId()).isEqualTo(RESOURCE_ID);
            assertThat(entry.getDecision()).isEqualTo(DECISION);
        }

        @Test
        @DisplayName("Should allow overwriting builder values")
        void shouldAllowOverwritingBuilderValues() {
            // Act
            AuditLogEntry entry = AuditLogEntry.builder()
                    .userId(USER_ID)
                    .userId("new-user-id")
                    .build();

            // Assert
            assertThat(entry.getUserId()).isEqualTo("new-user-id");
        }
    }

    @Nested
    @DisplayName("Getters")
    class Getters {

        @Test
        @DisplayName("Should return timestamp")
        void shouldReturnTimestamp() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .timestamp(TIMESTAMP)
                    .build();

            // Act & Assert
            assertThat(entry.getTimestamp()).isEqualTo(TIMESTAMP);
        }

        @Test
        @DisplayName("Should return userId")
        void shouldReturnUserId() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .userId(USER_ID)
                    .build();

            // Act & Assert
            assertThat(entry.getUserId()).isEqualTo(USER_ID);
        }

        @Test
        @DisplayName("Should return workloadId")
        void shouldReturnWorkloadId() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .workloadId(WORKLOAD_ID)
                    .build();

            // Act & Assert
            assertThat(entry.getWorkloadId()).isEqualTo(WORKLOAD_ID);
        }

        @Test
        @DisplayName("Should return operationType")
        void shouldReturnOperationType() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .operationType(OPERATION_TYPE)
                    .build();

            // Act & Assert
            assertThat(entry.getOperationType()).isEqualTo(OPERATION_TYPE);
        }

        @Test
        @DisplayName("Should return resourceId")
        void shouldReturnResourceId() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .resourceId(RESOURCE_ID)
                    .build();

            // Act & Assert
            assertThat(entry.getResourceId()).isEqualTo(RESOURCE_ID);
        }

        @Test
        @DisplayName("Should return decision")
        void shouldReturnDecision() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .decision(DECISION)
                    .build();

            // Act & Assert
            assertThat(entry.getDecision()).isEqualTo(DECISION);
        }

        @Test
        @DisplayName("Should return reason")
        void shouldReturnReason() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .reason(REASON)
                    .build();

            // Act & Assert
            assertThat(entry.getReason()).isEqualTo(REASON);
        }

        @Test
        @DisplayName("Should return ipAddress")
        void shouldReturnIpAddress() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .ipAddress(IP_ADDRESS)
                    .build();

            // Act & Assert
            assertThat(entry.getIpAddress()).isEqualTo(IP_ADDRESS);
        }

        @Test
        @DisplayName("Should return userAgent")
        void shouldReturnUserAgent() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .userAgent(USER_AGENT)
                    .build();

            // Act & Assert
            assertThat(entry.getUserAgent()).isEqualTo(USER_AGENT);
        }
    }

    @Nested
    @DisplayName("equals() and hashCode()")
    class EqualsAndHashCode {

        @Test
        @DisplayName("Should be equal when all fields match using usingRecursiveComparison")
        void shouldBeEqualWhenAllFieldsMatch() {
            // Arrange
            AuditLogEntry entry1 = AuditLogEntry.builder()
                    .timestamp(TIMESTAMP)
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .operationType(OPERATION_TYPE)
                    .resourceId(RESOURCE_ID)
                    .decision(DECISION)
                    .build();

            AuditLogEntry entry2 = AuditLogEntry.builder()
                    .timestamp(TIMESTAMP)
                    .userId(USER_ID)
                    .workloadId(WORKLOAD_ID)
                    .operationType(OPERATION_TYPE)
                    .resourceId(RESOURCE_ID)
                    .decision(DECISION)
                    .build();

            // Act & Assert
            assertThat(entry1).usingRecursiveComparison().isEqualTo(entry2);
        }

        @Test
        @DisplayName("Should not be equal when userId differs")
        void shouldNotBeEqualWhenUserIdDiffers() {
            // Arrange
            AuditLogEntry entry1 = AuditLogEntry.builder()
                    .userId(USER_ID)
                    .build();

            AuditLogEntry entry2 = AuditLogEntry.builder()
                    .userId("different-user")
                    .build();

            // Act & Assert
            assertThat(entry1).usingRecursiveComparison().isNotEqualTo(entry2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .userId(USER_ID)
                    .build();

            // Act & Assert
            assertThat(entry).isEqualTo(entry);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .userId(USER_ID)
                    .build();

            // Act & Assert
            assertThat(entry).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Arrange
            AuditLogEntry entry = AuditLogEntry.builder()
                    .userId(USER_ID)
                    .build();

            // Act & Assert
            assertThat(entry).isNotEqualTo("string");
        }
    }
}
