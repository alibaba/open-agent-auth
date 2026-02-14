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

import com.alibaba.openagentauth.core.model.policy.RamPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Condition evaluator for RAM policies.
 */
public class ConditionEvaluator {
    
    private static final Logger logger = LoggerFactory.getLogger(ConditionEvaluator.class);
    
    /**
     * Evaluates a RAM condition against input data.
     *
     * @param condition  the condition to evaluate
     * @param inputData  the input data
     * @return true if the condition is satisfied, false otherwise
     */
    public boolean evaluate(RamPolicy.RamCondition condition, Map<String, Object> inputData) {
        Object actualValue = getNestedValue(inputData, condition.getKey());
        
        try {
            return switch (condition.getOperator()) {
                case "StringEquals" -> Objects.equals(actualValue, condition.getValue());
                case "StringNotEquals" -> !Objects.equals(actualValue, condition.getValue());
                case "NumericLessThan" -> compareNumbers(actualValue, condition.getValue()) < 0;
                case "NumericLessThanEquals" -> compareNumbers(actualValue, condition.getValue()) <= 0;
                case "NumericGreaterThan" -> compareNumbers(actualValue, condition.getValue()) > 0;
                case "NumericGreaterThanEquals" -> compareNumbers(actualValue, condition.getValue()) >= 0;
                case "Bool" -> Boolean.TRUE.equals(actualValue);
                case "Null" -> actualValue == null;
                case "NotNull" -> actualValue != null;
                case "StringContains" -> actualValue != null && actualValue.toString().contains(condition.getValue().toString());
                case "StringStartsWith" -> actualValue != null && actualValue.toString().startsWith(condition.getValue().toString());
                case "StringEndsWith" -> actualValue != null && actualValue.toString().endsWith(condition.getValue().toString());
                case "IpInRange" -> evaluateIpRange(actualValue, condition.getValue());
                case "DateLessThan" -> compareDates(actualValue, condition.getValue()) < 0;
                case "DateGreaterThan" -> compareDates(actualValue, condition.getValue()) > 0;
                default -> {
                    logger.warn("Unknown condition operator: {}", condition.getOperator());
                    yield false;
                }
            };
        } catch (Exception e) {
            logger.error("Failed to evaluate condition: {}", condition, e);
            return false; // Fail-safe: deny on evaluation error
        }
    }
    
    /**
     * Gets a nested value from a map using dot notation.
     *
     * @param map  the map to search
     * @param path the dot-notation path to the value
     * @return the value at the specified path, or null if not found
     */
    private Object getNestedValue(Map<String, Object> map, String path) {
        if (map == null || path == null) {
            return null;
        }
        
        String[] parts = path.split("\\.");
        Object current = map;
        
        for (String part : parts) {
            if (current instanceof Map) {
                current = ((Map<?, ?>) current).get(part);
            } else {
                return null;
            }
        }
        
        return current;
    }
    
    /**
     * Compares two numeric values.
     *
     * @param a the first value
     * @param b the second value
     * @return negative if a < b, zero if a == b, positive if a > b
     */
    private int compareNumbers(Object a, Object b) {
        if (a instanceof Number && b instanceof Number) {
            return Double.compare(((Number) a).doubleValue(), ((Number) b).doubleValue());
        }
        throw new IllegalArgumentException("Both values must be numbers");
    }
    
    /**
     * Compares two date values.
     *
     * @param a the first value
     * @param b the second value
     * @return negative if a < b, zero if a == b, positive if a > b
     */
    private int compareDates(Object a, Object b) {
        Instant dateA = parseInstant(a);
        Instant dateB = parseInstant(b);
        return dateA.compareTo(dateB);
    }
    
    /**
     * Parses an instant from various formats.
     *
     * @param value the value to parse
     * @return the parsed instant
     */
    private Instant parseInstant(Object value) {
        if (value instanceof Instant) {
            return (Instant) value;
        }
        if (value instanceof String) {
            return Instant.parse((String) value);
        }
        if (value instanceof Long) {
            return Instant.ofEpochMilli((Long) value);
        }
        throw new IllegalArgumentException("Cannot parse instant from: " + value);
    }
    
    /**
     * Evaluates if an IP address is in a range.
     * Simplified implementation for demonstration.
     *
     * @param ip    the IP address
     * @param range the IP range
     * @return true if the IP is in the range, false otherwise
     */
    private boolean evaluateIpRange(Object ip, Object range) {
        // Simplified IP range evaluation
        // In production, use a proper IP address library like Apache Commons Net
        String ipStr = ip != null ? ip.toString() : "";
        String rangeStr = range != null ? range.toString() : "";
        return ipStr.startsWith(rangeStr.replace("*", ""));
    }
}
