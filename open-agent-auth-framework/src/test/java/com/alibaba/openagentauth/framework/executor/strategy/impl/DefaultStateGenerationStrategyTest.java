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

import java.util.UUID;

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
        @DisplayName("Should generate state with session ID")
        void shouldGenerateStateWithSessionId() {
            String sessionId = "session-123";
            String state = strategy.generate(sessionId);

            assertThat(state).isNotNull();
            assertThat(state).startsWith("agent:");
            assertThat(state).endsWith(sessionId);
            assertThat(state).contains(":");
        }

        @Test
        @DisplayName("Should generate state without session ID")
        void shouldGenerateStateWithoutSessionId() {
            String state = strategy.generate(null);

            assertThat(state).isNotNull();
            assertThat(state).startsWith("agent:");
            assertThat(state).doesNotContain(":.:");
        }

        @Test
        @DisplayName("Should generate state with empty session ID")
        void shouldGenerateStateWithEmptySessionId() {
            String state = strategy.generate("");

            assertThat(state).isNotNull();
            assertThat(state).startsWith("agent:");
            assertThat(state).doesNotEndWith(":");
        }

        @Test
        @DisplayName("Should generate unique states")
        void shouldGenerateUniqueStates() {
            String state1 = strategy.generate("session-1");
            String state2 = strategy.generate("session-1");

            assertThat(state1).isNotEqualTo(state2);
        }
    }

    @Nested
    @DisplayName("Format Tests")
    class FormatTests {

        @Test
        @DisplayName("Should follow format \"agent:UUID:sessionId\" with session ID")
        void shouldFollowFormatWithSessionId() {
            String sessionId = "session-123";
            String state = strategy.generate(sessionId);

            String[] parts = state.split(":");
            assertThat(parts).hasSize(3);
            assertThat(parts[0]).isEqualTo("agent");
            assertThat(parts[2]).isEqualTo(sessionId);
        }

        @Test
        @DisplayName("Should follow format \"agent:UUID\" without session ID")
        void shouldFollowFormatWithoutSessionId() {
            String state = strategy.generate(null);

            String[] parts = state.split(":");
            assertThat(parts).hasSize(2);
            assertThat(parts[0]).isEqualTo("agent");
        }

        @Test
        @DisplayName("Should generate valid UUID")
        void shouldGenerateValidUuid() {
            String state = strategy.generate(null);
            String[] parts = state.split(":");
            String uuidPart = parts[1];

            assertThatCode(() -> UUID.fromString(uuidPart))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle special characters in session ID")
        void shouldHandleSpecialCharactersInSessionId() {
            String sessionId = "session-123_abc@def#456";
            String state = strategy.generate(sessionId);

            assertThat(state).endsWith(sessionId);
            assertThat(state.split(":")).hasSize(3);
        }

        @Test
        @DisplayName("Should handle long session ID")
        void shouldHandleLongSessionId() {
            String sessionId = "a".repeat(1000);
            String state = strategy.generate(sessionId);

            assertThat(state).endsWith(sessionId);
            assertThat(state.split(":")).hasSize(3);
        }

        @Test
        @DisplayName("Should handle whitespace session ID")
        void shouldHandleWhitespaceSessionId() {
            String sessionId = "session 123 with spaces";
            String state = strategy.generate(sessionId);

            assertThat(state).endsWith(sessionId);
            assertThat(state.split(":")).hasSize(3);
        }

        @Test
        @DisplayName("Should handle session ID with colons")
        void shouldHandleSessionIdWithColons() {
            String sessionId = "session:123:456";
            String state = strategy.generate(sessionId);

            assertThat(state).endsWith(sessionId);
            assertThat(state.split(":")).hasSizeGreaterThanOrEqualTo(4);
        }

        @Test
        @DisplayName("Should handle numeric session ID")
        void shouldHandleNumericSessionId() {
            String sessionId = "12345";
            String state = strategy.generate(sessionId);

            assertThat(state).endsWith(sessionId);
            assertThat(state.split(":")).hasSize(3);
        }

        @Test
        @DisplayName("Should handle Unicode session ID")
        void shouldHandleUnicodeSessionId() {
            String sessionId = "session中文测试";
            String state = strategy.generate(sessionId);

            assertThat(state).endsWith(sessionId);
            assertThat(state.split(":")).hasSize(3);
        }
    }

    @Nested
    @DisplayName("Uniqueness Tests")
    class UniquenessTests {

        @Test
        @DisplayName("Should generate different UUIDs for consecutive calls")
        void shouldGenerateDifferentUuidsForConsecutiveCalls() {
            String state1 = strategy.generate("session");
            String state2 = strategy.generate("session");

            String[] parts1 = state1.split(":");
            String[] parts2 = state2.split(":");

            assertThat(parts1[1]).isNotEqualTo(parts2[1]);
        }

        @Test
        @DisplayName("Should generate different UUIDs for different session IDs")
        void shouldGenerateDifferentUuidsForDifferentSessionIds() {
            String state1 = strategy.generate("session-1");
            String state2 = strategy.generate("session-2");

            String[] parts1 = state1.split(":");
            String[] parts2 = state2.split(":");

            assertThat(parts1[1]).isNotEqualTo(parts2[1]);
        }
    }
}
