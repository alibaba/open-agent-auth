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
package com.alibaba.openagentauth.sample.agent.integration.llm.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link MockConfig}.
 * <p>
 * This test class validates the mock configuration functionality
 * including strategy management and property getters/setters.
 * </p>
 */
@DisplayName("MockConfig Tests")
class MockConfigTest {

    private MockConfig mockConfig;

    @BeforeEach
    void setUp() {
        mockConfig = new MockConfig();
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with default values")
        void shouldInitializeWithDefaultValues() {
            assertThat(mockConfig.isEnabled()).isFalse();
            assertThat(mockConfig.getStrategies()).isNotNull();
            assertThat(mockConfig.getStrategies()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Enabled Property")
    class EnabledPropertyTests {

        @Test
        @DisplayName("Should set and get enabled property")
        void shouldSetAndGetEnabledProperty() {
            mockConfig.setEnabled(true);
            
            assertThat(mockConfig.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should handle false value")
        void shouldHandleFalseValue() {
            mockConfig.setEnabled(false);
            
            assertThat(mockConfig.isEnabled()).isFalse();
        }
    }

    @Nested
    @DisplayName("Strategies Property")
    class StrategiesPropertyTests {

        @Test
        @DisplayName("Should set and get strategies")
        void shouldSetAndGetStrategies() {
            List<MockConfig.Strategy> strategies = new ArrayList<>();
            MockConfig.Strategy strategy = new MockConfig.Strategy();
            strategy.setName("test");
            strategies.add(strategy);
            
            mockConfig.setStrategies(strategies);
            
            assertThat(mockConfig.getStrategies()).hasSize(1);
            assertThat(mockConfig.getStrategies().get(0).getName()).isEqualTo("test");
        }

        @Test
        @DisplayName("Should handle empty strategies list")
        void shouldHandleEmptyStrategiesList() {
            mockConfig.setStrategies(new ArrayList<>());
            
            assertThat(mockConfig.getStrategies()).isEmpty();
        }
    }

    @Nested
    @DisplayName("Strategy Class")
    class StrategyClassTests {

        @Test
        @DisplayName("Should set and get all strategy properties")
        void shouldSetAndGetAllStrategyProperties() {
            MockConfig.Strategy strategy = new MockConfig.Strategy();
            
            strategy.setName("search");
            strategy.setIntent("search for products");
            strategy.setKeywords(List.of("search", "find"));
            strategy.setToolServer("product-server");
            strategy.setToolName("search_products");
            strategy.setResponseTemplate("Result: {result}");
            strategy.setErrorTemplate("Error: {error}");
            strategy.setNoTool(false);
            strategy.setResponse("Static response");
            
            assertThat(strategy.getName()).isEqualTo("search");
            assertThat(strategy.getIntent()).isEqualTo("search for products");
            assertThat(strategy.getKeywords()).hasSize(2);
            assertThat(strategy.getToolServer()).isEqualTo("product-server");
            assertThat(strategy.getToolName()).isEqualTo("search_products");
            assertThat(strategy.getResponseTemplate()).isEqualTo("Result: {result}");
            assertThat(strategy.getErrorTemplate()).isEqualTo("Error: {error}");
            assertThat(strategy.isNoTool()).isFalse();
            assertThat(strategy.getResponse()).isEqualTo("Static response");
        }

        @Test
        @DisplayName("Should handle null properties")
        void shouldHandleNullProperties() {
            MockConfig.Strategy strategy = new MockConfig.Strategy();
            
            strategy.setName(null);
            strategy.setIntent(null);
            strategy.setKeywords(null);
            strategy.setToolServer(null);
            strategy.setToolName(null);
            strategy.setResponseTemplate(null);
            strategy.setErrorTemplate(null);
            strategy.setResponse(null);
            
            assertThat(strategy.getName()).isNull();
            assertThat(strategy.getIntent()).isNull();
            assertThat(strategy.getKeywords()).isNull();
            assertThat(strategy.getToolServer()).isNull();
            assertThat(strategy.getToolName()).isNull();
            assertThat(strategy.getResponseTemplate()).isNull();
            assertThat(strategy.getErrorTemplate()).isNull();
            assertThat(strategy.getResponse()).isNull();
        }
    }

    @Nested
    @DisplayName("ParamRule Class")
    class ParamRuleClassTests {

        @Test
        @DisplayName("Should set and get all param rule properties")
        void shouldSetAndGetAllParamRuleProperties() {
            MockConfig.ParamRule rule = new MockConfig.ParamRule();
            
            rule.setParam("keywords");
            rule.setSource("user_input");
            rule.setPattern("search for (.+)");
            rule.setDefaultValue("default");
            
            assertThat(rule.getParam()).isEqualTo("keywords");
            assertThat(rule.getSource()).isEqualTo("user_input");
            assertThat(rule.getPattern()).isEqualTo("search for (.+)");
            assertThat(rule.getDefaultValue()).isEqualTo("default");
        }

        @Test
        @DisplayName("Should handle null properties")
        void shouldHandleNullProperties() {
            MockConfig.ParamRule rule = new MockConfig.ParamRule();
            
            rule.setParam(null);
            rule.setSource(null);
            rule.setPattern(null);
            rule.setDefaultValue(null);
            
            assertThat(rule.getParam()).isNull();
            assertThat(rule.getSource()).isNull();
            assertThat(rule.getPattern()).isNull();
            assertThat(rule.getDefaultValue()).isNull();
        }
    }
}
