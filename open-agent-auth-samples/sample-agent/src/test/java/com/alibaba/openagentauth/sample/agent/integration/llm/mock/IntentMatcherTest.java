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
 * Unit tests for {@link IntentMatcher}.
 * <p>
 * This test class validates the intent matching functionality
 * including keyword matching, default strategy handling, and edge cases.
 * </p>
 */
@DisplayName("IntentMatcher Tests")
class IntentMatcherTest {

    private IntentMatcher intentMatcher;
    private List<MockConfig.Strategy> strategies;

    @BeforeEach
    void setUp() {
        strategies = new ArrayList<>();
        
        // Create search strategy
        MockConfig.Strategy searchStrategy = new MockConfig.Strategy();
        searchStrategy.setName("search");
        searchStrategy.setIntent("search for products");
        searchStrategy.setKeywords(List.of("search", "find", "look for"));
        strategies.add(searchStrategy);
        
        // Create purchase strategy
        MockConfig.Strategy purchaseStrategy = new MockConfig.Strategy();
        purchaseStrategy.setName("purchase");
        purchaseStrategy.setIntent("purchase a product");
        purchaseStrategy.setKeywords(List.of("buy", "purchase", "order"));
        strategies.add(purchaseStrategy);
        
        // Create default strategy
        MockConfig.Strategy defaultStrategy = new MockConfig.Strategy();
        defaultStrategy.setName("default");
        defaultStrategy.setIntent("general conversation");
        defaultStrategy.setResponse("I'm not sure how to help with that.");
        strategies.add(defaultStrategy);
        
        intentMatcher = new IntentMatcher(strategies);
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with strategies")
        void shouldInitializeWithStrategies() {
            assertThat(intentMatcher).isNotNull();
        }
    }

    @Nested
    @DisplayName("match()")
    class MatchTests {

        @Test
        @DisplayName("Should match search intent")
        void shouldMatchSearchIntent() {
            MockConfig.Strategy result = intentMatcher.match("I want to search for iPhone 15");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("search");
        }

        @Test
        @DisplayName("Should match purchase intent")
        void shouldMatchPurchaseIntent() {
            MockConfig.Strategy result = intentMatcher.match("I want to buy a laptop");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("purchase");
        }

        @Test
        @DisplayName("Should return default strategy when no match")
        void shouldReturnDefaultStrategyWhenNoMatch() {
            MockConfig.Strategy result = intentMatcher.match("Hello, how are you?");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("default");
        }

        @Test
        @DisplayName("Should return default strategy for empty input")
        void shouldReturnDefaultStrategyForEmptyInput() {
            MockConfig.Strategy result = intentMatcher.match("");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("default");
        }

        @Test
        @DisplayName("Should return default strategy for null input")
        void shouldReturnDefaultStrategyForNullInput() {
            MockConfig.Strategy result = intentMatcher.match(null);
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("default");
        }

        @Test
        @DisplayName("Should be case insensitive")
        void shouldBeCaseInsensitive() {
            MockConfig.Strategy result = intentMatcher.match("I WANT TO SEARCH FOR PRODUCTS");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("search");
        }

        @Test
        @DisplayName("Should match first matching strategy")
        void shouldMatchFirstMatchingStrategy() {
            MockConfig.Strategy result = intentMatcher.match("find products");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("search");
        }
    }

    @Nested
    @DisplayName("getStrategy()")
    class GetStrategyTests {

        @Test
        @DisplayName("Should return strategy by name")
        void shouldReturnStrategyByName() {
            MockConfig.Strategy result = intentMatcher.getStrategy("search");
            
            assertThat(result).isNotNull();
            assertThat(result.getName()).isEqualTo("search");
        }

        @Test
        @DisplayName("Should return null for non-existent strategy")
        void shouldReturnNullForNonExistentStrategy() {
            MockConfig.Strategy result = intentMatcher.getStrategy("non-existent");
            
            assertThat(result).isNull();
        }
    }

    @Nested
    @DisplayName("hasStrategy()")
    class HasStrategyTests {

        @Test
        @DisplayName("Should return true for existing strategy")
        void shouldReturnTrueForExistingStrategy() {
            boolean result = intentMatcher.hasStrategy("search");
            
            assertThat(result).isTrue();
        }

        @Test
        @DisplayName("Should return false for non-existent strategy")
        void shouldReturnFalseForNonExistentStrategy() {
            boolean result = intentMatcher.hasStrategy("non-existent");
            
            assertThat(result).isFalse();
        }
    }
}
