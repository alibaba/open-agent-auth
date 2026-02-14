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
package com.alibaba.openagentauth.core.model.evidence;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link UserInputEvidence.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * UserInputEvidence, including normal construction, method chaining,
 * optional field settings, and build() method behavior.
 * </p>
 */
@DisplayName("UserInputEvidence.Builder Tests")
class UserInputEvidenceTest {

    private static final String TYPE = "UserInputEvidence";
    private static final String PROMPT = "What is the weather today?";
    private static final String TIMESTAMP = "2024-01-01T00:00:00Z";
    private static final String CHANNEL = "web";
    private static final String DEVICE_FINGERPRINT = "device_123";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build evidence with all required fields")
        void shouldBuildEvidenceWithAllRequiredFields() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getType()).isEqualTo(TYPE);
            assertThat(evidence.getPrompt()).isEqualTo(PROMPT);
            assertThat(evidence.getTimestamp()).isEqualTo(TIMESTAMP);
        }

        @Test
        @DisplayName("Should build evidence with all fields")
        void shouldBuildEvidenceWithAllFields() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .type(TYPE)
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .channel(CHANNEL)
                    .deviceFingerprint(DEVICE_FINGERPRINT)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getType()).isEqualTo(TYPE);
            assertThat(evidence.getPrompt()).isEqualTo(PROMPT);
            assertThat(evidence.getTimestamp()).isEqualTo(TIMESTAMP);
            assertThat(evidence.getChannel()).isEqualTo(CHANNEL);
            assertThat(evidence.getDeviceFingerprint()).isEqualTo(DEVICE_FINGERPRINT);
        }

        @Test
        @DisplayName("Should build evidence with timestamp from Instant")
        void shouldBuildEvidenceWithTimestampFromInstant() {
            // Given
            Instant instant = Instant.parse(TIMESTAMP);

            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(instant)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getTimestamp()).isEqualTo(TIMESTAMP);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining for all setters")
        void shouldSupportMethodChainingForAllSetters() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .type(TYPE)
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .channel(CHANNEL)
                    .deviceFingerprint(DEVICE_FINGERPRINT)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getType()).isEqualTo(TYPE);
            assertThat(evidence.getPrompt()).isEqualTo(PROMPT);
            assertThat(evidence.getChannel()).isEqualTo(CHANNEL);
            assertThat(evidence.getDeviceFingerprint()).isEqualTo(DEVICE_FINGERPRINT);
        }
    }

    @Nested
    @DisplayName("Optional Field Tests")
    class OptionalFieldTests {

        @Test
        @DisplayName("Should use default type when not set")
        void shouldUseDefaultTypeWhenNotSet() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence.getType()).isEqualTo(TYPE);
        }

        @Test
        @DisplayName("Should use default channel when not set")
        void shouldUseDefaultChannelWhenNotSet() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence.getChannel()).isEqualTo("web");
        }

        @Test
        @DisplayName("Should allow null optional fields")
        void shouldAllowNullOptionalFields() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getDeviceFingerprint()).isNull();
        }

        @Test
        @DisplayName("Should set optional channel field")
        void shouldSetOptionalChannelField() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .channel("mobile")
                    .build();

            // Then
            assertThat(evidence.getChannel()).isEqualTo("mobile");
        }

        @Test
        @DisplayName("Should set optional deviceFingerprint field")
        void shouldSetOptionalDeviceFingerprintField() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .deviceFingerprint(DEVICE_FINGERPRINT)
                    .build();

            // Then
            assertThat(evidence.getDeviceFingerprint()).isEqualTo(DEVICE_FINGERPRINT);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence).isInstanceOf(UserInputEvidence.class);
            assertThat(evidence.getPrompt()).isEqualTo(PROMPT);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            UserInputEvidence.Builder builder = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP);

            // When
            UserInputEvidence evidence1 = builder.build();
            builder.prompt("different_prompt");
            UserInputEvidence evidence2 = builder.build();

            // Then
            assertThat(evidence1.getPrompt()).isEqualTo(PROMPT);
            assertThat(evidence2.getPrompt()).isEqualTo("different_prompt");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all fields match")
        void shouldBeEqualWhenAllFieldsMatch() {
            // When
            UserInputEvidence evidence1 = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            UserInputEvidence evidence2 = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence1).isEqualTo(evidence2);
            assertThat(evidence1.hashCode()).isEqualTo(evidence2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when prompts differ")
        void shouldNotBeEqualWhenPromptsDiffer() {
            // When
            UserInputEvidence evidence1 = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .build();

            UserInputEvidence evidence2 = UserInputEvidence.builder()
                    .prompt("different_prompt")
                    .timestamp(TIMESTAMP)
                    .build();

            // Then
            assertThat(evidence1).isNotEqualTo(evidence2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include all fields in toString")
        void shouldIncludeAllFieldsInToString() {
            // When
            UserInputEvidence evidence = UserInputEvidence.builder()
                    .prompt(PROMPT)
                    .timestamp(TIMESTAMP)
                    .channel(CHANNEL)
                    .deviceFingerprint(DEVICE_FINGERPRINT)
                    .build();

            // Then
            String toString = evidence.toString();
            assertThat(toString).contains("UserInputEvidence");
            assertThat(toString).contains(PROMPT);
            assertThat(toString).contains(TIMESTAMP);
            assertThat(toString).contains(CHANNEL);
            assertThat(toString).contains(DEVICE_FINGERPRINT);
        }
    }
}
