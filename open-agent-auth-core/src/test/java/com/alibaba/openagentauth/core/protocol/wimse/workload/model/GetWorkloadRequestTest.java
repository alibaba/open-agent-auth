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
package com.alibaba.openagentauth.core.protocol.wimse.workload.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("GetWorkloadRequest Tests")
class GetWorkloadRequestTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build GetWorkloadRequest with workloadId")
        void shouldBuildGetWorkloadRequestWithWorkloadId() {
            // Act
            GetWorkloadRequest request = GetWorkloadRequest.builder()
                    .workloadId("workload123")
                    .build();

            // Assert
            assertThat(request).isNotNull();
            assertThat(request.getWorkloadId()).isEqualTo("workload123");
        }

        @Test
        @DisplayName("Should throw exception when workloadId is null")
        void shouldThrowExceptionWhenWorkloadIdIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> GetWorkloadRequest.builder().build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID is required");
        }

        @Test
        @DisplayName("Should throw exception when workloadId is empty")
        void shouldThrowExceptionWhenWorkloadIdIsEmpty() {
            // Act & Assert
            assertThatThrownBy(() -> GetWorkloadRequest.builder()
                    .workloadId("")
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Workload ID is required");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with JsonCreator constructor")
        void shouldCreateRequestWithJsonCreatorConstructor() {
            // Act
            GetWorkloadRequest request = new GetWorkloadRequest("workload-456");

            // Assert
            assertThat(request.getWorkloadId()).isEqualTo("workload-456");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when same workloadId")
        void shouldBeEqualWhenSameWorkloadId() {
            // Arrange
            GetWorkloadRequest request1 = new GetWorkloadRequest("workload-123");
            GetWorkloadRequest request2 = new GetWorkloadRequest("workload-123");

            // Assert
            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when different workloadId")
        void shouldNotBeEqualWhenDifferentWorkloadId() {
            // Arrange
            GetWorkloadRequest request1 = new GetWorkloadRequest("workload-123");
            GetWorkloadRequest request2 = new GetWorkloadRequest("workload-456");

            // Assert
            assertThat(request1).isNotEqualTo(request2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should return string representation")
        void shouldReturnStringRepresentation() {
            // Arrange
            GetWorkloadRequest request = new GetWorkloadRequest("workload-123");

            // Act
            String result = request.toString();

            // Assert
            assertThat(result).contains("GetWorkloadRequest");
            assertThat(result).contains("workload-123");
        }
    }
}
