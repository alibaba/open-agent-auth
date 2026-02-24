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
package com.alibaba.openagentauth.core.crypto.key.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link KeyDefinition}.
 */
@DisplayName("KeyDefinition Tests")
class KeyDefinitionTest {

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build KeyDefinition with all fields")
        void shouldBuildKeyDefinitionWithAllFields() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("test-key-001")
                    .algorithm(KeyAlgorithm.ES256)
                    .provider("local")
                    .jwksConsumer("agent-idp")
                    .build();

            assertThat(definition.getKeyId()).isEqualTo("test-key-001");
            assertThat(definition.getAlgorithm()).isEqualTo(KeyAlgorithm.ES256);
            assertThat(definition.getProvider()).isEqualTo("local");
            assertThat(definition.getJwksConsumer()).isEqualTo("agent-idp");
        }

        @Test
        @DisplayName("Should build KeyDefinition with only required fields")
        void shouldBuildKeyDefinitionWithOnlyRequiredFields() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("minimal-key")
                    .build();

            assertThat(definition.getKeyId()).isEqualTo("minimal-key");
            assertThat(definition.getAlgorithm()).isNull();
            assertThat(definition.getProvider()).isNull();
            assertThat(definition.getJwksConsumer()).isNull();
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is null")
        void shouldThrowExceptionWhenKeyIdIsNull() {
            assertThatThrownBy(() -> KeyDefinition.builder().build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("keyId cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is empty")
        void shouldThrowExceptionWhenKeyIdIsEmpty() {
            assertThatThrownBy(() -> KeyDefinition.builder().keyId("").build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("keyId cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is blank")
        void shouldThrowExceptionWhenKeyIdIsBlank() {
            assertThatThrownBy(() -> KeyDefinition.builder().keyId("   ").build())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("keyId cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Remote/Local Key Tests")
    class RemoteLocalKeyTests {

        @Test
        @DisplayName("Should be remote key when jwksConsumer is set")
        void shouldBeRemoteKeyWhenJwksConsumerIsSet() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("remote-key")
                    .jwksConsumer("agent-idp")
                    .build();

            assertThat(definition.isRemoteKey()).isTrue();
            assertThat(definition.isLocalKey()).isFalse();
        }

        @Test
        @DisplayName("Should be local key when jwksConsumer is null")
        void shouldBeLocalKeyWhenJwksConsumerIsNull() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("local-key")
                    .provider("local")
                    .build();

            assertThat(definition.isLocalKey()).isTrue();
            assertThat(definition.isRemoteKey()).isFalse();
        }

        @Test
        @DisplayName("Should be local key when jwksConsumer is blank")
        void shouldBeLocalKeyWhenJwksConsumerIsBlank() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("local-key")
                    .jwksConsumer("   ")
                    .build();

            assertThat(definition.isLocalKey()).isTrue();
            assertThat(definition.isRemoteKey()).isFalse();
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsHashCodeTests {

        @Test
        @DisplayName("Should be equal when all properties are the same")
        void shouldBeEqualWhenAllPropertiesAreTheSame() {
            KeyDefinition definition1 = KeyDefinition.builder()
                    .keyId("key-1")
                    .algorithm(KeyAlgorithm.RS256)
                    .provider("local")
                    .jwksConsumer("consumer-1")
                    .build();

            KeyDefinition definition2 = KeyDefinition.builder()
                    .keyId("key-1")
                    .algorithm(KeyAlgorithm.RS256)
                    .provider("local")
                    .jwksConsumer("consumer-1")
                    .build();

            assertThat(definition1).isEqualTo(definition2);
            assertThat(definition1.hashCode()).isEqualTo(definition2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when keyId differs")
        void shouldNotBeEqualWhenKeyIdDiffers() {
            KeyDefinition definition1 = KeyDefinition.builder()
                    .keyId("key-1")
                    .algorithm(KeyAlgorithm.RS256)
                    .build();

            KeyDefinition definition2 = KeyDefinition.builder()
                    .keyId("key-2")
                    .algorithm(KeyAlgorithm.RS256)
                    .build();

            assertThat(definition1).isNotEqualTo(definition2);
        }

        @Test
        @DisplayName("Should not be equal when algorithm differs")
        void shouldNotBeEqualWhenAlgorithmDiffers() {
            KeyDefinition definition1 = KeyDefinition.builder()
                    .keyId("key-1")
                    .algorithm(KeyAlgorithm.RS256)
                    .build();

            KeyDefinition definition2 = KeyDefinition.builder()
                    .keyId("key-1")
                    .algorithm(KeyAlgorithm.ES256)
                    .build();

            assertThat(definition1).isNotEqualTo(definition2);
        }

        @Test
        @DisplayName("Should not be equal when provider differs")
        void shouldNotBeEqualWhenProviderDiffers() {
            KeyDefinition definition1 = KeyDefinition.builder()
                    .keyId("key-1")
                    .provider("local")
                    .build();

            KeyDefinition definition2 = KeyDefinition.builder()
                    .keyId("key-1")
                    .provider("file")
                    .build();

            assertThat(definition1).isNotEqualTo(definition2);
        }

        @Test
        @DisplayName("Should not be equal when jwksConsumer differs")
        void shouldNotBeEqualWhenJwksConsumerDiffers() {
            KeyDefinition definition1 = KeyDefinition.builder()
                    .keyId("key-1")
                    .jwksConsumer("consumer-1")
                    .build();

            KeyDefinition definition2 = KeyDefinition.builder()
                    .keyId("key-1")
                    .jwksConsumer("consumer-2")
                    .build();

            assertThat(definition1).isNotEqualTo(definition2);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("key-1")
                    .build();

            assertThat(definition).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("key-1")
                    .build();

            assertThat(definition).isEqualTo(definition);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should contain all fields in toString output")
        void shouldContainAllFieldsInToStringOutput() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("test-key")
                    .algorithm(KeyAlgorithm.ES256)
                    .provider("local")
                    .jwksConsumer("agent-idp")
                    .build();

            String result = definition.toString();

            assertThat(result).contains("test-key");
            assertThat(result).contains("ES256");
            assertThat(result).contains("local");
            assertThat(result).contains("agent-idp");
        }

        @Test
        @DisplayName("Should handle null fields in toString output")
        void shouldHandleNullFieldsInToStringOutput() {
            KeyDefinition definition = KeyDefinition.builder()
                    .keyId("minimal-key")
                    .build();

            String result = definition.toString();

            assertThat(result).contains("minimal-key");
            assertThat(result).contains("keyId");
        }
    }
}
