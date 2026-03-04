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

@DisplayName("CreateWorkloadRequest Tests")
class CreateWorkloadRequestTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build CreateWorkloadRequest with all fields")
        void shouldBuildCreateWorkloadRequestWithAllFields() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .resourceId("resource-123")
                    .prompt("test prompt")
                    .publicKey("test-public-key")
                    .clientId("client-123")
                    .build();

            // Act
            CreateWorkloadRequest request = CreateWorkloadRequest.builder()
                    .idToken("test-id-token")
                    .context(context)
                    .build();

            // Assert
            assertThat(request).isNotNull();
            assertThat(request.getIdToken()).isEqualTo("test-id-token");
            assertThat(request.getContext()).isEqualTo(context);
        }

        @Test
        @DisplayName("Should throw exception when idToken is null")
        void shouldThrowExceptionWhenIdTokenIsNull() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> CreateWorkloadRequest.builder()
                    .context(context)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("idToken is required");
        }

        @Test
        @DisplayName("Should throw exception when idToken is empty")
        void shouldThrowExceptionWhenIdTokenIsEmpty() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> CreateWorkloadRequest.builder()
                    .idToken("")
                    .context(context)
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("idToken is required");
        }

        @Test
        @DisplayName("Should throw exception when context is null")
        void shouldThrowExceptionWhenContextIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> CreateWorkloadRequest.builder()
                    .idToken("test-id-token")
                    .build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("context is required");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with JsonCreator constructor")
        void shouldCreateRequestWithJsonCreatorConstructor() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .resourceId("resource-123")
                    .build();

            // Act
            CreateWorkloadRequest request = new CreateWorkloadRequest("test-id-token", context);

            // Assert
            assertThat(request.getIdToken()).isEqualTo("test-id-token");
            assertThat(request.getContext()).isEqualTo(context);
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when same values")
        void shouldBeEqualWhenSameValues() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .build();

            CreateWorkloadRequest request1 = new CreateWorkloadRequest("token", context);
            CreateWorkloadRequest request2 = new CreateWorkloadRequest("token", context);

            // Assert
            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when different values")
        void shouldNotBeEqualWhenDifferentValues() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .build();

            CreateWorkloadRequest request1 = new CreateWorkloadRequest("token1", context);
            CreateWorkloadRequest request2 = new CreateWorkloadRequest("token2", context);

            // Assert
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Arrange
            CreateWorkloadRequest request = new CreateWorkloadRequest("token", null);

            // Assert
            assertThat(request).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Arrange
            CreateWorkloadRequest request = new CreateWorkloadRequest("token", null);

            // Assert
            assertThat(request).isEqualTo(request);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should return string representation")
        void shouldReturnStringRepresentation() {
            // Arrange
            CreateWorkloadRequest request = new CreateWorkloadRequest("test-token", null);

            // Act
            String result = request.toString();

            // Assert
            assertThat(result).contains("CreateWorkloadRequest");
            assertThat(result).contains("test-token");
        }
    }
}
