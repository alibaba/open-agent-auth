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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link Evidence.Builder}.
 * <p>
 * This test class validates the Builder pattern implementation for
 * Evidence, including normal construction, method chaining, and build() method behavior.
 * </p>
 */
@DisplayName("Evidence.Builder Tests")
class EvidenceTest {

    private static final String SOURCE_PROMPT_CREDENTIAL = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";

    @Nested
    @DisplayName("Normal Construction Tests")
    class NormalConstructionTests {

        @Test
        @DisplayName("Should build evidence with sourcePromptCredential")
        void shouldBuildEvidenceWithSourcePromptCredential() {
            // When
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getSourcePromptCredential()).isEqualTo(SOURCE_PROMPT_CREDENTIAL);
        }
    }

    @Nested
    @DisplayName("Method Chaining Tests")
    class MethodChainingTests {

        @Test
        @DisplayName("Should support method chaining")
        void shouldSupportMethodChaining() {
            // When
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            // Then
            assertThat(evidence).isNotNull();
            assertThat(evidence.getSourcePromptCredential()).isEqualTo(SOURCE_PROMPT_CREDENTIAL);
        }
    }

    @Nested
    @DisplayName("Build Method Tests")
    class BuildMethodTests {

        @Test
        @DisplayName("Should return correct instance when build is called")
        void shouldReturnCorrectInstanceWhenBuildIsCalled() {
            // When
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            // Then
            assertThat(evidence).isInstanceOf(Evidence.class);
            assertThat(evidence.getSourcePromptCredential()).isEqualTo(SOURCE_PROMPT_CREDENTIAL);
        }

        @Test
        @DisplayName("Should create independent instances from same builder")
        void shouldCreateIndependentInstancesFromSameBuilder() {
            // Given
            Evidence.Builder builder = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL);

            // When
            Evidence evidence1 = builder.build();
            builder.sourcePromptCredential("different_credential");
            Evidence evidence2 = builder.build();

            // Then
            assertThat(evidence1.getSourcePromptCredential()).isEqualTo(SOURCE_PROMPT_CREDENTIAL);
            assertThat(evidence2.getSourcePromptCredential()).isEqualTo("different_credential");
        }
    }

    @Nested
    @DisplayName("Equals and HashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when sourcePromptCredential matches")
        void shouldBeEqualWhenSourcePromptCredentialMatches() {
            // When
            Evidence evidence1 = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            Evidence evidence2 = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            // Then
            assertThat(evidence1).isEqualTo(evidence2);
            assertThat(evidence1.hashCode()).isEqualTo(evidence2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when sourcePromptCredential differs")
        void shouldNotBeEqualWhenSourcePromptCredentialDiffers() {
            // When
            Evidence evidence1 = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            Evidence evidence2 = Evidence.builder()
                    .sourcePromptCredential("different_credential")
                    .build();

            // Then
            assertThat(evidence1).isNotEqualTo(evidence2);
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should include sourcePromptCredential in toString")
        void shouldIncludeSourcePromptCredentialInToString() {
            // When
            Evidence evidence = Evidence.builder()
                    .sourcePromptCredential(SOURCE_PROMPT_CREDENTIAL)
                    .build();

            // Then
            String toString = evidence.toString();
            assertThat(toString).contains("Evidence");
            assertThat(toString).contains(SOURCE_PROMPT_CREDENTIAL);
        }
    }
}
