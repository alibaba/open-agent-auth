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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parameter Extractor
 * 
 * Extracts tool parameters from user input based on predefined rules.
 * Supports regex pattern matching and default values.
 * 
 * @since 1.0
 */
public class ParamExtractor {
    
    private static final Logger log = LoggerFactory.getLogger(ParamExtractor.class);
    
    private final ObjectMapper objectMapper;
    
    public ParamExtractor() {
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Extract parameters from user input based on strategy rules.
     * 
     * @param userInput the user's input message
     * @param strategy the matched strategy
     * @return a map of parameter names to values
     */
    public Map<String, Object> extract(String userInput, MockConfig.Strategy strategy) {
        Map<String, Object> params = new HashMap<>();
        
        if (strategy.getParamRules() == null || strategy.getParamRules().isEmpty()) {
            log.debug("No parameter rules defined for strategy: {}", strategy.getName());
            return params;
        }
        
        for (MockConfig.ParamRule rule : strategy.getParamRules()) {
            String value = extractParam(userInput, rule);
            if (value != null) {
                params.put(rule.getParam(), value);
                log.debug("Extracted parameter: {} = {}", rule.getParam(), value);
            } else if (rule.getDefaultValue() != null) {
                params.put(rule.getParam(), rule.getDefaultValue());
                log.debug("Using default value for parameter: {} = {}", rule.getParam(), rule.getDefaultValue());
            }
        }
        
        return params;
    }
    
    /**
     * Extract a single parameter based on the rule.
     * 
     * @param userInput the user's input
     * @param rule the parameter extraction rule
     * @return the extracted value, or null if extraction failed
     */
    private String extractParam(String userInput, MockConfig.ParamRule rule) {
        if (rule.getPattern() != null && !rule.getPattern().isBlank()) {
            // Extract using regex pattern
            return extractByPattern(userInput, rule.getPattern());
        } else if ("user_input".equals(rule.getSource())) {
            // Use entire user input as parameter value
            return userInput;
        }
        
        return null;
    }
    
    /**
     * Extract value from user input using regex pattern.
     * 
     * @param userInput the user's input
     * @param pattern the regex pattern
     * @return the extracted value, or null if no match
     */
    private String extractByPattern(String userInput, String pattern) {
        try {
            Pattern regex = Pattern.compile(pattern);
            Matcher matcher = regex.matcher(userInput);
            
            if (matcher.find()) {
                // Return the first capture group if available, otherwise the entire match
                if (matcher.groupCount() > 0) {
                    return matcher.group(1).trim();
                } else {
                    return matcher.group().trim();
                }
            }
        } catch (Exception e) {
            log.error("Failed to extract parameter using pattern: {}", pattern, e);
        }
        
        return null;
    }
    
    /**
     * Convert parameter map to JSON string.
     * 
     * @param params the parameter map
     * @return JSON string representation
     */
    public String toJson(Map<String, Object> params) {
        try {
            return objectMapper.writeValueAsString(params);
        } catch (JsonProcessingException e) {
            log.error("Failed to convert parameters to JSON", e);
            return "{}";
        }
    }
}
