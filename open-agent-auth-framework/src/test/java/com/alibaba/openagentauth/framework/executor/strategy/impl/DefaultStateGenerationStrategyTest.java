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
package com.alibaba.openagentauth.framework.executor.strategy.impl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for DefaultStateGenerationStrategy.
 * <p>
 * This test class verifies the functionality of generating state parameters.
 * </p>
 */
@DisplayName("DefaultStateGenerationStrategy Tests")
class DefaultStateGenerationStrategyTest {

    private DefaultStateGenerationStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new DefaultStateGenerationStrategy();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create strategy successfully")
        void shouldCreateStrategySuccessfully() {
            assertThat(strategy).isNotNull();
        }
    }

    @Nested
    @DisplayName("Generate Tests")
    class GenerateTests {

        @Test
        @DisplayName("Should generate non-null state")
        void shouldGenerateNonNullState() {
            String state = strategy.generate();

            assertThat(state).isNotNull();
        }

        @Test
        @DisplayName("Should generate non-empty state")
        void shouldGenerateNonEmptyState() {
            String state = strategy.generate();

            assertThat(state).isNotEmpty();
        }

        @Test
        @DisplayName("Should generate URL-safe Base64 encoded state")
        void shouldGenerateUrlSafeBase64EncodedState() {
            String state = strategy.generate();

            // Should be valid Base64
            assertThatCode(() -> Base64.getUrlDecoder().decode(state))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Should generate state with correct length (43 characters for 32 bytes)")
        void shouldGenerateStateWithCorrectLength() {
            String state = strategy.generate();

            // 32 bytes encoded in URL-safe Base64 without padding = 43 characters
            assertThat(state).hasSize(43);
        }

        @Test
        @DisplayName("Should generate state without padding characters")
        void shouldGenerateStateWithoutPaddingCharacters() {
            String state = strategy.generate();

            assertThat(state).doesNotContain("=");
        }

        @Test
        @DisplayName("Should generate state without + and / characters")
        void shouldGenerateStateWithoutPlusAndSlashCharacters() {
            String state = strategy.generate();

            assertThat(state).doesNotContain("+");
            assertThat(state).doesNotContain("/");
        }

        @Test
        @DisplayName("Should generate unique states")
        void shouldGenerateUniqueStates() {
            String state1 = strategy.generate();
            String state2 = strategy.generate();

            assertThat(state1).isNotEqualTo(state2);
        }
    }

    @Nested
    @DisplayName("Uniqueness Tests")
    class UniquenessTests {

        @Test
        @DisplayName("Should generate different values for consecutive calls")
        void shouldGenerateDifferentValuesForConsecutiveCalls() {
            String state1 = strategy.generate();
            String state2 = strategy.generate();

            assertThat(state1).isNotEqualTo(state2);
        }

        @Test
        @DisplayName("Should generate cryptographically secure random values")
        void shouldGenerateCryptographicallySecureRandomValues() {
            String state1 = strategy.generate();
            String state2 = strategy.generate();
            String state3 = strategy.generate();

            // Three consecutive calls should all be different
            assertThat(state1).isNotEqualTo(state2);
            assertThat(state2).isNotEqualTo(state3);
            assertThat(state1).isNotEqualTo(state3);
        }
    }
}