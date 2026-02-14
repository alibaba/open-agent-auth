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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Intent Matcher
 * 
 * Matches user input to predefined intents based on keyword matching.
 * This is a simple but effective approach for mock LLM scenarios.
 * 
 * <p>The matching strategy:
 * <ul>
 *   <li>Checks if any keyword from a strategy matches the user input</li>
 *   <li>Returns the first matching strategy</li>
 *   <li>If no match found, returns the default strategy</li>
 * </ul>
 * 
 * @since 1.0
 */
public class IntentMatcher {
    
    private static final Logger log = LoggerFactory.getLogger(IntentMatcher.class);
    
    /**
     * Strategy cache for faster matching
     */
    private final Map<String, MockConfig.Strategy> strategyCache = new ConcurrentHashMap<>();
    
    /**
     * Default strategy for unmatched intents
     */
    private MockConfig.Strategy defaultStrategy;
    
    public IntentMatcher(List<MockConfig.Strategy> strategies) {
        // Build strategy cache and find default strategy
        for (MockConfig.Strategy strategy : strategies) {
            strategyCache.put(strategy.getName(), strategy);
            
            // Identify default strategy
            if ("default".equals(strategy.getName())) {
                defaultStrategy = strategy;
            }
        }
        
        log.info("IntentMatcher initialized with {} strategies", strategies.size());
    }
    
    /**
     * Match user input to a strategy.
     * 
     * @param userInput the user's input message
     * @return the matching strategy, or default strategy if no match
     */
    public MockConfig.Strategy match(String userInput) {
        if (userInput == null || userInput.isBlank()) {
            log.debug("User input is empty, returning default strategy");
            return defaultStrategy;
        }
        
        String normalizedInput = userInput.toLowerCase().trim();
        
        // Iterate through strategies to find a match
        for (MockConfig.Strategy strategy : strategyCache.values()) {
            // Skip default strategy during matching
            if ("default".equals(strategy.getName())) {
                continue;
            }
            
            // Check if any keyword matches
            if (matchesKeywords(normalizedInput, strategy.getKeywords())) {
                log.info("Matched strategy '{}' for user input: '{}'", strategy.getName(), userInput);
                return strategy;
            }
        }
        
        log.info("No strategy matched for user input: '{}', returning default strategy", userInput);
        return defaultStrategy;
    }
    
    /**
     * Check if the normalized input matches any of the keywords.
     * 
     * @param normalizedInput the normalized user input
     * @param keywords the list of keywords to match
     * @return true if any keyword matches, false otherwise
     */
    private boolean matchesKeywords(String normalizedInput, List<String> keywords) {
        if (keywords == null || keywords.isEmpty()) {
            return false;
        }
        
        for (String keyword : keywords) {
            if (keyword != null && !keyword.isBlank()) {
                String normalizedKeyword = keyword.toLowerCase().trim();
                if (normalizedInput.contains(normalizedKeyword)) {
                    log.debug("Keyword matched: '{}'", keyword);
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Get strategy by name.
     * 
     * @param name the strategy name
     * @return the strategy, or null if not found
     */
    public MockConfig.Strategy getStrategy(String name) {
        return strategyCache.get(name);
    }
    
    /**
     * Check if a strategy exists.
     * 
     * @param name the strategy name
     * @return true if the strategy exists, false otherwise
     */
    public boolean hasStrategy(String name) {
        return strategyCache.containsKey(name);
    }
}
