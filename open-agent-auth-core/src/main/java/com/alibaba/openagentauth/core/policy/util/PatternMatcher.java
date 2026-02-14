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
package com.alibaba.openagentauth.core.policy.util;

import java.util.List;

/**
 * Pattern matcher for policy evaluation.
 * <p>
 * Supports wildcard matching using the * character.
 * </p>
 */
public class PatternMatcher {
    
    /**
     * Matches a value against a list of patterns.
     * Supports wildcard matching (* character).
     *
     * @param patterns the list of patterns to match against
     * @param value    the value to match
     * @return true if the value matches any pattern, false otherwise
     */
    public boolean match(List<String> patterns, String value) {
        if (value == null || patterns == null || patterns.isEmpty()) {
            return false;
        }
        
        for (String pattern : patterns) {
            if (matchSinglePattern(pattern, value)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Matches a value against a single pattern.
     * Supports wildcard matching (* character).
     *
     * @param pattern the pattern to match
     * @param value   the value to match
     * @return true if the value matches the pattern, false otherwise
     */
    public boolean matchSinglePattern(String pattern, String value) {
        if (pattern == null || value == null) {
            return false;
        }
        
        // Exact match
        if (pattern.equals(value)) {
            return true;
        }
        
        // Wildcard match at the end
        if (pattern.endsWith("*")) {
            String prefix = pattern.substring(0, pattern.length() - 1);
            return value.startsWith(prefix);
        }
        
        // Wildcard match at the beginning
        if (pattern.startsWith("*")) {
            String suffix = pattern.substring(1);
            return value.endsWith(suffix);
        }
        
        // Wildcard match in the middle
        int wildcardIndex = pattern.indexOf('*');
        if (wildcardIndex > 0 && wildcardIndex < pattern.length() - 1) {
            String prefix = pattern.substring(0, wildcardIndex);
            String suffix = pattern.substring(wildcardIndex + 1);
            return value.startsWith(prefix) && value.endsWith(suffix);
        }
        
        return false;
    }
}
