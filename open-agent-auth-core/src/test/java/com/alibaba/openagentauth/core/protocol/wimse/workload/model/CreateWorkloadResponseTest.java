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

@DisplayName("CreateWorkloadResponse Tests")
class CreateWorkloadResponseTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build CreateWorkloadResponse with all fields")
        void shouldBuildCreateWorkloadResponseWithAllFields() {
            // Act
            CreateWorkloadResponse response = CreateWorkloadResponse.builder()
                    .workloadId("workload123")
                    .status("ACTIVE")
                    .userId("user-123")
                    .publicKey("pk-123")
                    .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getWorkloadId()).isEqualTo("workload123");
            assertThat(response.getStatus()).isEqualTo("ACTIVE");
            assertThat(response.getUserId()).isEqualTo("user-123");
            assertThat(response.getPublicKey()).isEqualTo("pk-123");
        }

        @Test
        @DisplayName("Should build CreateWorkloadResponse with minimal fields")
        void shouldBuildCreateWorkloadResponseWithMinimalFields() {
            // Act
            CreateWorkloadResponse response = CreateWorkloadResponse.builder()
                .workloadId("workload123")
                .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getWorkloadId()).isEqualTo("workload123");
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterAndSetterTests {

        @Test
        @DisplayName("Should set and get workloadId")
        void shouldSetAndGetWorkloadId() {
            // Arrange
            CreateWorkloadResponse response = new CreateWorkloadResponse();

            // Act
            response.setWorkloadId("workload456");

            // Assert
            assertThat(response.getWorkloadId()).isEqualTo("workload456");
        }

        @Test
        @DisplayName("Should set and get status")
        void shouldSetAndGetStatus() {
            // Arrange
            CreateWorkloadResponse response = new CreateWorkloadResponse();

            // Act
            response.setStatus("PENDING");

            // Assert
            assertThat(response.getStatus()).isEqualTo("PENDING");
        }

        @Test
        @DisplayName("Should set and get error")
        void shouldSetAndGetError() {
            // Arrange
            CreateWorkloadResponse response = new CreateWorkloadResponse();

            // Act
            response.setError("Something went wrong");

            // Assert
            assertThat(response.getError()).isEqualTo("Something went wrong");
        }
    }
}
