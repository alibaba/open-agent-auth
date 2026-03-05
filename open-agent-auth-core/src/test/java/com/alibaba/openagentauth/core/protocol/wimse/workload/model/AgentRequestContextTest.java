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

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AgentRequestContext Tests")
class AgentRequestContextTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build AgentRequestContext with all fields")
        void shouldBuildAgentRequestContextWithAllFields() {
            // Arrange
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("key1", "value1");

            // Act
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .resourceId("resource-123")
                    .metadata(metadata)
                    .prompt("test prompt")
                    .publicKey("test-public-key")
                    .clientId("client-123")
                    .build();

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getOperationType()).isEqualTo("query");
            assertThat(context.getResourceId()).isEqualTo("resource-123");
            assertThat(context.getMetadata()).isNotNull();
            assertThat(context.getMetadata()).containsKey("key1");
            assertThat(context.getPrompt()).isEqualTo("test prompt");
            assertThat(context.getPublicKey()).isEqualTo("test-public-key");
            assertThat(context.getClientId()).isEqualTo("client-123");
        }

        @Test
        @DisplayName("Should build AgentRequestContext with minimal fields")
        void shouldBuildAgentRequestContextWithMinimalFields() {
            // Act
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("query")
                    .build();

            // Assert
            assertThat(context).isNotNull();
            assertThat(context.getOperationType()).isEqualTo("query");
            assertThat(context.getResourceId()).isNull();
            assertThat(context.getMetadata()).isNull();
            assertThat(context.getPrompt()).isNull();
            assertThat(context.getPublicKey()).isNull();
            assertThat(context.getClientId()).isNull();
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create context with JsonCreator constructor")
        void shouldCreateContextWithJsonCreatorConstructor() {
            // Arrange
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("key", "value");

            // Act
            AgentRequestContext context = new AgentRequestContext(
                    "query", "resource-123", metadata, "prompt", "publicKey", "clientId"
            );

            // Assert
            assertThat(context.getOperationType()).isEqualTo("query");
            assertThat(context.getResourceId()).isEqualTo("resource-123");
            assertThat(context.getMetadata()).containsKey("key");
            assertThat(context.getPrompt()).isEqualTo("prompt");
            assertThat(context.getPublicKey()).isEqualTo("publicKey");
            assertThat(context.getClientId()).isEqualTo("clientId");
        }

        @Test
        @DisplayName("Should create context with null values")
        void shouldCreateContextWithNullValues() {
            // Act
            AgentRequestContext context = new AgentRequestContext(null, null, null, null, null, null);

            // Assert
            assertThat(context.getOperationType()).isNull();
            assertThat(context.getResourceId()).isNull();
            assertThat(context.getMetadata()).isNull();
            assertThat(context.getPrompt()).isNull();
            assertThat(context.getPublicKey()).isNull();
            assertThat(context.getClientId()).isNull();
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct operationType")
        void shouldReturnCorrectOperationType() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .operationType("mutation")
                    .build();

            // Assert
            assertThat(context.getOperationType()).isEqualTo("mutation");
        }

        @Test
        @DisplayName("Should return correct resourceId")
        void shouldReturnCorrectResourceId() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .resourceId("res-456")
                    .build();

            // Assert
            assertThat(context.getResourceId()).isEqualTo("res-456");
        }

        @Test
        @DisplayName("Should return correct metadata")
        void shouldReturnCorrectMetadata() {
            // Arrange
            Map<String, Object> metadata = Map.of("env", "prod");
            AgentRequestContext context = AgentRequestContext.builder()
                    .metadata(metadata)
                    .build();

            // Assert
            assertThat(context.getMetadata()).containsEntry("env", "prod");
        }

        @Test
        @DisplayName("Should return correct prompt")
        void shouldReturnCorrectPrompt() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .prompt("test prompt")
                    .build();

            // Assert
            assertThat(context.getPrompt()).isEqualTo("test prompt");
        }

        @Test
        @DisplayName("Should return correct publicKey")
        void shouldReturnCorrectPublicKey() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .publicKey("pk-123")
                    .build();

            // Assert
            assertThat(context.getPublicKey()).isEqualTo("pk-123");
        }

        @Test
        @DisplayName("Should return correct clientId")
        void shouldReturnCorrectClientId() {
            // Arrange
            AgentRequestContext context = AgentRequestContext.builder()
                    .clientId("client-789")
                    .build();

            // Assert
            assertThat(context.getClientId()).isEqualTo("client-789");
        }
    }
}
