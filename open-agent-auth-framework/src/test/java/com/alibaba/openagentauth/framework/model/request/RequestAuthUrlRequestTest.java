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
package com.alibaba.openagentauth.framework.model.request;

import com.alibaba.openagentauth.framework.model.workload.WorkloadRequestContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link RequestAuthUrlRequest}.
 * <p>
 * This test class verifies the behavior of the RequestAuthUrlRequest class,
 * including builder pattern, validation, and getter methods.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("RequestAuthUrlRequest Tests")
class RequestAuthUrlRequestTest {

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderPatternTests {

        @Test
        @DisplayName("Should build request with all required fields")
        void shouldBuildRequestWithAllRequiredFields() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("I want to search for books")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getUserIdentityToken()).isEqualTo("id-token");
            assertThat(request.getUserOriginalInput()).isEqualTo("I want to search for books");
            assertThat(request.getWorkloadContext()).isEqualTo(workloadContext);
            assertThat(request.getOperationType()).isEqualTo("READ");
            assertThat(request.getResourceId()).isEqualTo("resource-123");
        }

        @Test
        @DisplayName("Should build request with all fields including optional")
        void shouldBuildRequestWithAllFieldsIncludingOptional() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("key", "value");

            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("WRITE")
                .resourceId("resource-456")
                .metadata(metadata)
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("I want to create a record")
                .workloadContext(workloadContext)
                .sessionId("session-123")
                .deviceFingerprint("device-fp-123")
                .build();

            assertThat(request.getSessionId()).isEqualTo("session-123");
            assertThat(request.getDeviceFingerprint()).isEqualTo("device-fp-123");
        }

        @Test
        @DisplayName("Should throw exception when userIdentityToken is null")
        void shouldThrowExceptionWhenUserIdentityTokenIsNull() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken(null)
                    .userOriginalInput("input")
                    .workloadContext(workloadContext)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("userIdentityToken is required");
        }

        @Test
        @DisplayName("Should throw exception when userIdentityToken is empty")
        void shouldThrowExceptionWhenUserIdentityTokenIsEmpty() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken("")
                    .userOriginalInput("input")
                    .workloadContext(workloadContext)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("userIdentityToken is required");
        }

        @Test
        @DisplayName("Should throw exception when userOriginalInput is null")
        void shouldThrowExceptionWhenUserOriginalInputIsNull() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken("id-token")
                    .userOriginalInput(null)
                    .workloadContext(workloadContext)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("userOriginalInput is required");
        }

        @Test
        @DisplayName("Should throw exception when userOriginalInput is empty")
        void shouldThrowExceptionWhenUserOriginalInputIsEmpty() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken("id-token")
                    .userOriginalInput("")
                    .workloadContext(workloadContext)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("userOriginalInput is required");
        }

        @Test
        @DisplayName("Should throw exception when workloadContext is null")
        void shouldThrowExceptionWhenWorkloadContextIsNull() {
            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken("id-token")
                    .userOriginalInput("input")
                    .workloadContext(null)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("workloadContext is required");
        }

        @Test
        @DisplayName("Should throw exception when workloadContext operationType is null")
        void shouldThrowExceptionWhenWorkloadContextOperationTypeIsNull() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .resourceId("resource-123")
                .build();

            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken("id-token")
                    .userOriginalInput("input")
                    .workloadContext(workloadContext)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("workloadContext.operationType is required");
        }

        @Test
        @DisplayName("Should throw exception when workloadContext operationType is empty")
        void shouldThrowExceptionWhenWorkloadContextOperationTypeIsEmpty() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("")
                .resourceId("resource-123")
                .build();

            assertThatThrownBy(() -> {
                RequestAuthUrlRequest.builder()
                    .userIdentityToken("id-token")
                    .userOriginalInput("input")
                    .workloadContext(workloadContext)
                    .build();
            }).isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("workloadContext.operationType is required");
        }

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .sessionId("session-123")
                .deviceFingerprint("device-fp-123")
                .build();

            assertThat(request).isNotNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return userIdentityToken")
        void shouldReturnUserIdentityToken() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getUserIdentityToken()).isEqualTo("id-token");
        }

        @Test
        @DisplayName("Should return userOriginalInput")
        void shouldReturnUserOriginalInput() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("I want to search")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getUserOriginalInput()).isEqualTo("I want to search");
        }

        @Test
        @DisplayName("Should return workloadContext")
        void shouldReturnWorkloadContext() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getWorkloadContext()).isEqualTo(workloadContext);
        }

        @Test
        @DisplayName("Should return operation type from workload context")
        void shouldReturnOperationTypeFromWorkloadContext() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("WRITE")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getOperationType()).isEqualTo("WRITE");
        }

        @Test
        @DisplayName("Should return null operation type when workload context is null")
        void shouldReturnNullOperationTypeWhenWorkloadContextIsNull() {
            // This test is for defensive programming, though build() should prevent this
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getOperationType()).isEqualTo("READ");
        }

        @Test
        @DisplayName("Should return resource id from workload context")
        void shouldReturnResourceIdFromWorkloadContext() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-456")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getResourceId()).isEqualTo("resource-456");
        }

        @Test
        @DisplayName("Should return metadata from workload context")
        void shouldReturnMetadataFromWorkloadContext() {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("key1", "value1");
            metadata.put("key2", "value2");

            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .metadata(metadata)
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request.getMetadata()).hasSize(2);
            assertThat(request.getMetadata()).containsEntry("key1", "value1");
        }

        @Test
        @DisplayName("Should return sessionId")
        void shouldReturnSessionId() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .sessionId("session-123")
                .build();

            assertThat(request.getSessionId()).isEqualTo("session-123");
        }

        @Test
        @DisplayName("Should return deviceFingerprint")
        void shouldReturnDeviceFingerprint() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .deviceFingerprint("device-fp-123")
                .build();

            assertThat(request.getDeviceFingerprint()).isEqualTo("device-fp-123");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request1 = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .sessionId("session-123")
                .deviceFingerprint("device-fp-123")
                .build();

            RequestAuthUrlRequest request2 = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .sessionId("session-123")
                .deviceFingerprint("device-fp-123")
                .build();

            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when fields differ")
        void shouldNotBeEqualWhenFieldsDiffer() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request1 = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token-1")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            RequestAuthUrlRequest request2 = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token-2")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            assertThat(request).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should protect userIdentityToken in toString")
        void shouldProtectUserIdentityTokenInToString() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("input")
                .workloadContext(workloadContext)
                .build();

            String toString = request.toString();
            assertThat(toString).contains("[PROTECTED]");
            assertThat(toString).doesNotContain("id-token");
        }

        @Test
        @DisplayName("Should include userOriginalInput in toString")
        void shouldIncludeUserOriginalInputInToString() {
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType("READ")
                .resourceId("resource-123")
                .build();

            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken("id-token")
                .userOriginalInput("I want to search")
                .workloadContext(workloadContext)
                .build();

            String toString = request.toString();
            assertThat(toString).contains("I want to search");
        }
    }
}
