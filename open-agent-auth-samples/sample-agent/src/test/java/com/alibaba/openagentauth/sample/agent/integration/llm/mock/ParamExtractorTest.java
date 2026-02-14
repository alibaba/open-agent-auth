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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ParamExtractor}.
 * <p>
 * This test class validates the parameter extraction functionality
 * including regex pattern matching, default values, and JSON conversion.
 * </p>
 */
@DisplayName("ParamExtractor Tests")
class ParamExtractorTest {

    private ParamExtractor paramExtractor;
    private MockConfig.Strategy strategy;

    @BeforeEach
    void setUp() {
        paramExtractor = new ParamExtractor();
        strategy = new MockConfig.Strategy();
        strategy.setName("search");
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize successfully")
        void shouldInitializeSuccessfully() {
            assertThat(paramExtractor).isNotNull();
        }
    }

    @Nested
    @DisplayName("extract()")
    class ExtractTests {

        @Test
        @DisplayName("Should extract parameter using regex pattern")
        void shouldExtractParameterUsingRegexPattern() {
            List<MockConfig.ParamRule> rules = new ArrayList<>();
            MockConfig.ParamRule rule = new MockConfig.ParamRule();
            rule.setParam("keywords");
            rule.setPattern("search for (.+)");
            rules.add(rule);
            strategy.setParamRules(rules);

            Map<String, Object> result = paramExtractor.extract("search for iPhone 15", strategy);

            assertThat(result).isNotNull();
            assertThat(result).hasSize(1);
            assertThat(result.get("keywords")).isEqualTo("iPhone 15");
        }

        @Test
        @DisplayName("Should extract multiple parameters")
        void shouldExtractMultipleParameters() {
            List<MockConfig.ParamRule> rules = new ArrayList<>();
            
            MockConfig.ParamRule rule1 = new MockConfig.ParamRule();
            rule1.setParam("product");
            rule1.setPattern("buy (.+),");
            rules.add(rule1);
            
            MockConfig.ParamRule rule2 = new MockConfig.ParamRule();
            rule2.setParam("quantity");
            rule2.setPattern("(\\d+) units");
            rules.add(rule2);
            
            strategy.setParamRules(rules);

            Map<String, Object> result = paramExtractor.extract("buy iPhone 15, 5 units", strategy);

            assertThat(result).isNotNull();
            assertThat(result).hasSize(2);
            assertThat(result.get("product")).isEqualTo("iPhone 15");
            assertThat(result.get("quantity")).isEqualTo("5");
        }

        @Test
        @DisplayName("Should use default value when extraction fails")
        void shouldUseDefaultValueWhenExtractionFails() {
            List<MockConfig.ParamRule> rules = new ArrayList<>();
            MockConfig.ParamRule rule = new MockConfig.ParamRule();
            rule.setParam("keywords");
            rule.setPattern("search for (.+)");
            rule.setDefaultValue("default product");
            rules.add(rule);
            strategy.setParamRules(rules);

            Map<String, Object> result = paramExtractor.extract("hello world", strategy);

            assertThat(result).isNotNull();
            assertThat(result).hasSize(1);
            assertThat(result.get("keywords")).isEqualTo("default product");
        }

        @Test
        @DisplayName("Should use entire user input as parameter")
        void shouldUseEntireUserInputAsParameter() {
            List<MockConfig.ParamRule> rules = new ArrayList<>();
            MockConfig.ParamRule rule = new MockConfig.ParamRule();
            rule.setParam("query");
            rule.setSource("user_input");
            rules.add(rule);
            strategy.setParamRules(rules);

            Map<String, Object> result = paramExtractor.extract("search for products", strategy);

            assertThat(result).isNotNull();
            assertThat(result).hasSize(1);
            assertThat(result.get("query")).isEqualTo("search for products");
        }

        @Test
        @DisplayName("Should return empty map when no rules defined")
        void shouldReturnEmptyMapWhenNoRulesDefined() {
            Map<String, Object> result = paramExtractor.extract("any input", strategy);

            assertThat(result).isNotNull();
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should handle null rules")
        void shouldHandleNullRules() {
            Map<String, Object> result = paramExtractor.extract("any input", strategy);

            assertThat(result).isNotNull();
            assertThat(result).isEmpty();
        }
    }

    @Nested
    @DisplayName("toJson()")
    class ToJsonTests {

        @Test
        @DisplayName("Should convert parameters to JSON")
        void shouldConvertParametersToJson() {
            Map<String, Object> params = Map.of(
                    "keywords", "iPhone 15",
                    "limit", 10
            );

            String result = paramExtractor.toJson(params);

            assertThat(result).isNotNull();
            assertThat(result).contains("keywords");
            assertThat(result).contains("iPhone 15");
            assertThat(result).contains("limit");
            assertThat(result).contains("10");
        }

        @Test
        @DisplayName("Should return empty JSON for empty map")
        void shouldReturnEmptyJsonForEmptyMap() {
            String result = paramExtractor.toJson(Map.of());

            assertThat(result).isEqualTo("{}");
        }
    }
}
