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

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for DefaultDeviceFingerprintStrategy.
 * <p>
 * This test class verifies the functionality of generating device fingerprints.
 * </p>
 */
@DisplayName("DefaultDeviceFingerprintStrategy Tests")
class DefaultDeviceFingerprintStrategyTest {

    private DefaultDeviceFingerprintStrategy defaultStrategy;
    private DefaultDeviceFingerprintStrategy customStrategy;

    @BeforeEach
    void setUp() {
        defaultStrategy = new DefaultDeviceFingerprintStrategy();
        customStrategy = new DefaultDeviceFingerprintStrategy("custom_");
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create strategy with default prefix")
        void shouldCreateStrategyWithDefaultPrefix() {
            assertThat(defaultStrategy).isNotNull();
        }

        @Test
        @DisplayName("Should create strategy with custom prefix")
        void shouldCreateStrategyWithCustomPrefix() {
            assertThat(customStrategy).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when prefix is null")
        void shouldThrowExceptionWhenPrefixIsNull() {
            assertThatThrownBy(() -> new DefaultDeviceFingerprintStrategy(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("Prefix cannot be null");
        }
    }

    @Nested
    @DisplayName("Generate Tests")
    class GenerateTests {

        @Test
        @DisplayName("Should generate fingerprint with default prefix")
        void shouldGenerateFingerprintWithDefaultPrefix() {
            String fingerprint = defaultStrategy.generate("workload-123");

            assertThat(fingerprint).isNotNull();
            assertThat(fingerprint).startsWith("dfp_");
            assertThat(fingerprint).endsWith("workload-123");
        }

        @Test
        @DisplayName("Should generate fingerprint with custom prefix")
        void shouldGenerateFingerprintWithCustomPrefix() {
            String fingerprint = customStrategy.generate("workload-456");

            assertThat(fingerprint).isNotNull();
            assertThat(fingerprint).startsWith("custom_");
            assertThat(fingerprint).endsWith("workload-456");
        }

        @Test
        @DisplayName("Should concatenate prefix and workload ID")
        void shouldConcatenatePrefixAndWorkloadId() {
            String fingerprint = defaultStrategy.generate("test-workload");

            assertThat(fingerprint).isEqualTo("dfp_test-workload");
        }

        @Test
        @DisplayName("Should handle empty workload ID")
        void shouldHandleEmptyWorkloadId() {
            String fingerprint = defaultStrategy.generate("");

            assertThat(fingerprint).isEqualTo("dfp_");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle special characters in workload ID")
        void shouldHandleSpecialCharactersInWorkloadId() {
            String fingerprint = defaultStrategy.generate("workload-123_abc@def");

            assertThat(fingerprint).isEqualTo("dfp_workload-123_abc@def");
        }

        @Test
        @DisplayName("Should handle long workload ID")
        void shouldHandleLongWorkloadId() {
            String longWorkloadId = "a".repeat(1000);
            String fingerprint = defaultStrategy.generate(longWorkloadId);

            assertThat(fingerprint).startsWith("dfp_");
            assertThat(fingerprint).endsWith(longWorkloadId);
        }

        @Test
        @DisplayName("Should handle whitespace in workload ID")
        void shouldHandleWhitespaceInWorkloadId() {
            String fingerprint = defaultStrategy.generate("workload 123");

            assertThat(fingerprint).isEqualTo("dfp_workload 123");
        }

        @Test
        @DisplayName("Should handle numeric workload ID")
        void shouldHandleNumericWorkloadId() {
            String fingerprint = defaultStrategy.generate("12345");

            assertThat(fingerprint).isEqualTo("dfp_12345");
        }

        @Test
        @DisplayName("Should handle Unicode characters in workload ID")
        void shouldHandleUnicodeCharactersInWorkloadId() {
            String fingerprint = defaultStrategy.generate("workload中文测试");

            assertThat(fingerprint).isEqualTo("dfp_workload中文测试");
        }
    }

    @Nested
    @DisplayName("Prefix Tests")
    class PrefixTests {

        @Test
        @DisplayName("Should use default prefix \"dfp_\"")
        void shouldUseDefaultPrefix() {
            String fingerprint = defaultStrategy.generate("test");

            assertThat(fingerprint).startsWith("dfp_");
        }

        @Test
        @DisplayName("Should use custom prefix")
        void shouldUseCustomPrefix() {
            DefaultDeviceFingerprintStrategy strategy = new DefaultDeviceFingerprintStrategy("custom-prefix-");
            String fingerprint = strategy.generate("test");

            assertThat(fingerprint).startsWith("custom-prefix-");
        }

        @Test
        @DisplayName("Should handle empty prefix")
        void shouldHandleEmptyPrefix() {
            DefaultDeviceFingerprintStrategy strategy = new DefaultDeviceFingerprintStrategy("");
            String fingerprint = strategy.generate("test");

            assertThat(fingerprint).isEqualTo("test");
        }

        @Test
        @DisplayName("Should handle prefix with special characters")
        void shouldHandlePrefixWithSpecialCharacters() {
            DefaultDeviceFingerprintStrategy strategy = new DefaultDeviceFingerprintStrategy("prefix-@#123_");
            String fingerprint = strategy.generate("test");

            assertThat(fingerprint).startsWith("prefix-@#123_");
        }
    }
}
