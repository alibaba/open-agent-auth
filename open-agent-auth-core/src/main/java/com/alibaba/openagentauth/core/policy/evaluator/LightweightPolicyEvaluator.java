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
package com.alibaba.openagentauth.core.policy.evaluator;

import com.alibaba.openagentauth.core.exception.policy.PolicyEvaluationException;
import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Production-ready Java-based implementation of {@link PolicyEvaluator} for basic Rego policy evaluation.
 * <p>
 * This evaluator provides a simplified, self-contained implementation for evaluating
 * Rego policies without requiring external OPA dependencies. It is designed for
 * both development/testing environments and production use cases with simple
 * authorization requirements.
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li>Evaluate basic Rego policies using Java-based parsing</li>
 *   <li>Support common Rego patterns (allow rules, conditions)</li>
 *   <li>Provide detailed evaluation results with reasoning</li>
 *   <li>Handle evaluation errors gracefully with fail-safe defaults</li>
 *   <li>Cache compiled policies for performance with thread-safe operations</li>
 *   <li>Validate policy syntax before evaluation</li>
 *   <li>Track evaluation metrics for monitoring</li>
 * </ul>
 * </p>
 * <p>
 * <b>Supported Rego Features:</b></p>
 * <ul>
 *   <li>Package declarations (e.g., {@code package agent})</li>
 *   <li>Allow rules (e.g., {@code allow { true }})</li>
 *   <li>Comparison operators ({@code <=, >=, ==, !=, <, >})</li>
 *   <li>Input data access using dot notation (e.g., {@code input.transaction.amount})</li>
 *   <li>Nested input data structures</li>
 *   <li>String equality comparisons</li>
 * </ul>
 * </p>
 * <p>
 * <b>Production-Ready Features:</b></p>
 * <ul>
 *   <li><b>Thread Safety:</b> Uses {@code ConcurrentHashMap} for safe concurrent access</li>
 *   <li><b>Fail-Safe Defaults:</b> Evaluation errors default to DENY for security</li>
 *   <li><b>Policy Validation:</b> Validates policy syntax before compilation</li>
 *   <li><b>Cache Management:</b> Configurable cache with size limits</li>
 *   <li><b>Performance Metrics:</b> Tracks evaluation count and cache hit rate</li>
 *   <li><b>Comprehensive Logging:</b> Detailed logs for debugging and monitoring</li>
 * </ul>
 * </p>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Does not support full Rego language specification</li>
 *   <li>No support for advanced features (functions, comprehensions, recursion, sets)</li>
 *   <li>No support for deny rules or partial evaluation</li>
 *   <li>Not suitable for complex policy logic requiring data.json</li>
 *   <li>Only supports numeric and string comparisons for input values</li>
 * </ul>
 * </p>
 * <p>
 * <b>Use Cases:</b></p>
 * <ul>
 *   <li>Production environments with simple authorization needs</li>
 *   <li>Development and testing environments</li>
 *   <li>Simple authorization policies with numeric/string conditions</li>
 *   <li>Prototyping and PoC projects</li>
 *   <li>Environments where external dependencies are restricted</li>
 * </ul>
 * </p>
 * <p>
 * <b>Example Usage:</b></p>
 * <pre>{@code
 * // Create a policy
 * Policy policy = Policy.builder()
 *     .policyId("policy-001")
 *     .regoPolicy("package agent\nallow { input.transaction.amount <= 50.0 }")
 *     .description("Allow transactions under $50")
 *     .build();
 * 
 * // Register the policy
 * PolicyRegistry registry = new InMemoryPolicyRegistry();
 * registry.register(policy);
 * 
 * // Create evaluator with production settings
 * PolicyEvaluator evaluator = new LightweightPolicyEvaluator(
 *     registry, 
 *     true,   // enable cache
 *     1000    // max cache size
 * );
 * 
 * // Evaluate
 * Map<String, Object> inputData = new HashMap<>();
 * Map<String, Object> transaction = new HashMap<>();
 * transaction.put("amount", 30.0);
 * inputData.put("transaction", transaction);
 * 
 * boolean allowed = evaluator.evaluate("policy-001", inputData);
 * // Result: true
 * }</pre>
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is fully thread-safe. The policy cache uses {@code ConcurrentHashMap}
 * for concurrent access, and all operations are stateless with respect to evaluation.
 * </p>
 *
 * @see PolicyEvaluator
 * @see OpaRestPolicyEvaluator
 * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
public class LightweightPolicyEvaluator implements PolicyEvaluator {

    /**
     * Logger for the lightweight policy evaluator.
     */
    private static final Logger logger = LoggerFactory.getLogger(LightweightPolicyEvaluator.class);

    /**
     * Default maximum cache size for compiled policies.
     */
    private static final int DEFAULT_MAX_CACHE_SIZE = 1000;

    /**
     * The policy registry for policy retrieval.
     */
    private final PolicyRegistry policyRegistry;

    /**
     * Thread-safe cache for compiled policies to improve performance.
     * Key: policy ID, Value: compiled policy representation.
     */
    private final Map<String, CompiledPolicy> policyCache;

    /**
     * Flag indicating whether policy caching is enabled.
     */
    private final boolean enableCache;

    /**
     * Maximum number of policies to cache.
     */
    private final int maxCacheSize;

    /**
     * Atomic counter for total evaluation requests.
     */
    private final AtomicLong totalEvaluationCount;

    /**
     * Atomic counter for cache hits.
     */
    private final AtomicLong cacheHitCount;

    /**
     * Creates a new LightweightPolicyEvaluator with the specified policy registry and caching enabled.
     *
     * @param policyRegistry the policy registry to use for policy retrieval
     * @throws IllegalArgumentException if policyRegistry is null
     */
    public LightweightPolicyEvaluator(PolicyRegistry policyRegistry) {
        this(policyRegistry, true, DEFAULT_MAX_CACHE_SIZE);
    }

    /**
     * Creates a new LightweightPolicyEvaluator with the specified policy registry and cache setting.
     *
     * @param policyRegistry the policy registry to use for policy retrieval
     * @param enableCache    whether to enable policy caching for performance
     * @throws IllegalArgumentException if policyRegistry is null
     */
    public LightweightPolicyEvaluator(PolicyRegistry policyRegistry, boolean enableCache) {
        this(policyRegistry, enableCache, DEFAULT_MAX_CACHE_SIZE);
    }

    /**
     * Creates a new LightweightPolicyEvaluator with the specified policy registry and cache settings.
     *
     * @param policyRegistry the policy registry to use for policy retrieval
     * @param enableCache    whether to enable policy caching for performance
     * @param maxCacheSize   the maximum number of policies to cache
     * @throws IllegalArgumentException if policyRegistry is null or maxCacheSize is negative
     */
    public LightweightPolicyEvaluator(PolicyRegistry policyRegistry, boolean enableCache, int maxCacheSize) {
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "PolicyRegistry cannot be null");
        this.enableCache = enableCache;
        this.maxCacheSize = maxCacheSize > 0 ? maxCacheSize : DEFAULT_MAX_CACHE_SIZE;
        this.policyCache = new ConcurrentHashMap<>();
        this.totalEvaluationCount = new AtomicLong(0);
        this.cacheHitCount = new AtomicLong(0);
        logger.info("LightweightPolicyEvaluator initialized with cache: {}, maxCacheSize: {}",
                   enableCache, this.maxCacheSize);
    }

    /**
     * Evaluates a policy against input data and returns a boolean decision.
     * <p>
     * This method evaluates the policy with the specified ID against the provided
     * input data. If the evaluation fails, a {@link PolicyEvaluationException} is thrown.
     * </p>
     *
     * @param policyId  the unique identifier of the policy to evaluate
     * @param inputData the input data for evaluation, typically containing operation context
     * @return true if the policy allows the operation, false otherwise
     * @throws PolicyEvaluationException if the policy evaluation fails
     * @throws PolicyNotFoundException   if the policy with the given ID is not found
     */
    @Override
    public boolean evaluate(String policyId, Map<String, Object> inputData) {

        logger.debug("Evaluating policy: {}", policyId);
        totalEvaluationCount.incrementAndGet();
        
        PolicyEvaluationResult result = evaluateWithDetails(policyId, inputData);
        
        if (!result.isSuccess()) {
            throw new PolicyEvaluationException(result.getErrorMessage(), null, policyId);
        }
        return result.isAllowed();
    }

    /**
     * Evaluates a policy against input data with detailed results.
     * <p>
     * This method evaluates the policy and returns detailed information about
     * the evaluation, including the allow/deny decision, reasoning, and any errors.
     * </p>
     *
     * @param policyId  the unique identifier of the policy to evaluate
     * @param inputData the input data for evaluation
     * @return the evaluation result containing the decision and details
     * @throws PolicyEvaluationException if the policy evaluation fails
     * @throws PolicyNotFoundException   if the policy with the given ID is not found
     */
    @Override
    public PolicyEvaluationResult evaluateWithDetails(String policyId, Map<String, Object> inputData) {
        logger.debug("Evaluating policy with details: {}", policyId);
        
        try {
            // Retrieve the policy
            Policy policy = policyRegistry.get(policyId);
            logger.debug("Evaluating policy: {} with input data: {}", policy, inputData);
            
            // Validate policy syntax before evaluation
            validatePolicySyntax(policy);

            // Compile the policy and evaluate
            CompiledPolicy compiledPolicy = getCompiledPolicy(policy);
            EvaluationResult result = evaluatePolicy(compiledPolicy, inputData);
            String reasoning = buildReasoning(result, policy);

            // Return the evaluation result
            return new PolicyEvaluationResult(
                    result.allowed(),
                    reasoning,
                    null,
                    result.output()
            );
            
        } catch (PolicyNotFoundException | PolicyEvaluationException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to evaluate policy: {}", policyId, e);
            // Return a deny result instead of throwing exception for fail-safe behavior
            return new PolicyEvaluationResult(
                    false,
                    "Policy evaluation failed: " + e.getMessage() + ". Defaulting to DENY for security.",
                    e.getMessage(),
                    Map.of("allowed", false, "error", e.getMessage())
            );
        }
    }

    /**
     * Retrieves or compiles the policy.
     * <p>
     * This method checks the cache first if caching is enabled. If the policy
     * is not cached, it compiles the policy and optionally caches it.
     * Cache size is managed to prevent memory leaks.
     * </p>
     *
     * @param policy the policy to compile
     * @return the compiled policy representation
     */
    private CompiledPolicy getCompiledPolicy(Policy policy) {

        String policyId = policy.getPolicyId();
        if (enableCache) {
            CompiledPolicy cached = policyCache.get(policyId);
            if (cached != null) {
                cacheHitCount.incrementAndGet();
                logger.debug("Using cached policy: {}", policyId);
                return cached;
            }
        }
        
        logger.debug("Compiling policy: {}", policyId);
        CompiledPolicy compiledPolicy = compilePolicy(policy);
        
        if (enableCache) {
            // Manage cache size
            if (policyCache.size() >= maxCacheSize) {
                logger.warn("Cache size limit reached ({}), clearing cache", maxCacheSize);
                policyCache.clear();
            }
            policyCache.put(policyId, compiledPolicy);
            logger.debug("Cached compiled policy: {}", policyId);
        }
        
        return compiledPolicy;
    }

    /**
     * Compiles a policy into a form suitable for evaluation.
     * <p>
     * This method extracts the package name and stores the Rego policy string
     * for later evaluation. Note that this is a lightweight compilation that
     * does not perform full Rego parsing.
     * </p>
     *
     * @param policy the policy to compile
     * @return the compiled policy representation
     */
    private CompiledPolicy compilePolicy(Policy policy) {
        String regoPolicy = policy.getRegoPolicy();
        String packageName = extractPackageName(regoPolicy);
        return new CompiledPolicy(policy.getPolicyId(), packageName, regoPolicy);
    }

    /**
     * Evaluates a compiled policy against input data.
     * <p>
     * This method performs the actual evaluation by:
     * <ol>
     *   <li>Checking if an allow rule exists</li>
     *   <li>Extracting the allow rule body</li>
     *   <li>Evaluating any conditions in the rule</li>
     *   <li>Returning the allow/deny decision</li>
     * </ol>
     * </p>
     *
     * @param compiledPolicy the compiled policy to evaluate
     * @param inputData      the input data for evaluation
     * @return the evaluation result
     */
    private EvaluationResult evaluatePolicy(CompiledPolicy compiledPolicy, Map<String, Object> inputData) {

        String regoPolicy = compiledPolicy.regoPolicy();
        if (!regoPolicy.contains("allow")) {
            return new EvaluationResult(false, "No 'allow' rule defined in policy", Map.of());
        }
        
        boolean allowed = evaluateAllowRule(regoPolicy, inputData);
        
        Map<String, Object> output = new HashMap<>();
        output.put("allowed", allowed);
        
        String reasoning = allowed ? "Policy allows the operation" : "Policy denies the operation";
        
        return new EvaluationResult(allowed, reasoning, output);
    }

    /**
     * Evaluates the allow rule in the policy.
     * <p>
     * This method extracts the allow rule and evaluates any conditions
     * present in the rule body.
     * </p>
     *
     * @param regoPolicy the Rego policy string
     * @param inputData  the input data for evaluation
     * @return true if the allow rule evaluates to true, false otherwise
     */
    private boolean evaluateAllowRule(String regoPolicy, Map<String, Object> inputData) {

        String allowRule = extractAllowRule(regoPolicy);
        if (allowRule == null) {
            return false;
        }
        
        if (allowRule.contains("input.")) {
            return evaluateConditions(allowRule, inputData);
        }
        
        // Allow rule without conditions defaults to true
        return true;
    }

    /**
     * Extracts the allow rule body from a Rego policy.
     * <p>
     * This method parses the Rego policy string to find the allow rule
     * and extracts its body (the content between braces).
     * </p>
     *
     * @param regoPolicy the Rego policy string
     * @return the allow rule body, or null if not found
     */
    private String extractAllowRule(String regoPolicy) {

        int allowIndex = regoPolicy.indexOf("allow");
        if (allowIndex == -1) {
            return null;
        }
        
        int braceStart = regoPolicy.indexOf("{", allowIndex);
        if (braceStart == -1) {
            return null;
        }
        
        // Find matching closing brace
        int braceCount = 1;
        int i = braceStart + 1;
        while (i < regoPolicy.length() && braceCount > 0) {
            if (regoPolicy.charAt(i) == '{') {
                braceCount++;
            } else if (regoPolicy.charAt(i) == '}') {
                braceCount--;
            }
            i++;
        }
        
        return regoPolicy.substring(braceStart, Math.min(i, regoPolicy.length()));
    }

    /**
     * Evaluates conditions in the allow rule.
     * <p>
     * This method supports numeric and string comparison conditions with
     * input data access using dot notation. For example:
     * <pre>
     * input.transaction.amount <= 50.0
     * input.user.role == "admin"
     * </pre>
     * </p>
     * <p>
     * <b>Supported Operators:</b> {@code <=, >=, ==, !=, <, >}
     * </p>
     *
     * @param rule       the rule body containing conditions
     * @param inputData  the input data for evaluation
     * @return true if all conditions evaluate to true, false otherwise
     */
    private boolean evaluateConditions(String rule, Map<String, Object> inputData) {
        logger.debug("Evaluating conditions in rule: {}", rule);
        
        // Split rule into individual conditions (each line is a condition)
        String[] lines = rule.split("\n");
        
        for (String line : lines) {
            line = line.trim();
            
            // Skip empty lines and comments
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            
            // Skip the opening brace
            if (line.equals("{") || line.equals("}")) {
                continue;
            }
            
            // Evaluate each condition containing "input."
            if (line.contains("input.")) {
                logger.debug("Evaluating condition: {}", line);
                
                String inputPath = extractInputPath(line);
                if (inputPath == null) {
                    logger.warn("Could not extract input path from condition: {}", line);
                    return false; // Fail-safe: deny if path cannot be extracted
                }
                
                Object value = getNestedValue(inputData, inputPath);
                logger.debug("Extracted path: {}, value: {}", inputPath, value);
                
                if (value == null) {
                    logger.debug("Input value not found for path: {}", inputPath);
                    return false; // Fail-safe: deny if value is missing
                }
                
                // Evaluate based on operator
                boolean conditionResult;
                if (line.contains("<=")) {
                    conditionResult = evaluateComparison(value, "<=", extractLimit(line, "<="));
                } else if (line.contains(">=")) {
                    conditionResult = evaluateComparison(value, ">=", extractLimit(line, ">="));
                } else if (line.contains("==")) {
                    conditionResult = evaluateComparison(value, "==", extractLimit(line, "=="));
                } else if (line.contains("!=")) {
                    conditionResult = evaluateComparison(value, "!=", extractLimit(line, "!="));
                } else if (line.contains("<")) {
                    conditionResult = evaluateComparison(value, "<", extractLimit(line, "<"));
                } else if (line.contains(">")) {
                    conditionResult = evaluateComparison(value, ">", extractLimit(line, ">"));
                } else {
                    logger.warn("No recognized operator in condition: {}", line);
                    return false; // Fail-safe: deny if operator not recognized
                }
                
                logger.debug("Condition result: {}", conditionResult);
                
                // All conditions must be true (AND logic)
                if (!conditionResult) {
                    logger.debug("Condition failed: {}", line);
                    return false;
                }
            }
        }
        
        logger.debug("All conditions passed");
        return true;
    }

    /**
     * Extracts the input path from a rule.
     * For example, extracts "transaction.amount" from "input.transaction.amount <= 50.0"
     *
     * @param rule the rule string
     * @return the input path, or null if not found
     */
    private String extractInputPath(String rule) {

        int inputIndex = rule.indexOf("input.");
        if (inputIndex == -1) {
            return null;
        }
        
        String afterInput = rule.substring(inputIndex + 6); // Skip "input."
        
        // Find the end of the path (first operator or space)
        for (int i = 0; i < afterInput.length(); i++) {
            char c = afterInput.charAt(i);
            if (c == ' ' || c == '<' || c == '>' || c == '=' || c == '!') {
                return afterInput.substring(0, i);
            }
        }
        
        return afterInput;
    }

    /**
     * Extracts the limit value from a rule.
     * For example, extracts "50.0" from "input.amount <= 50.0"
     * or extracts "search_products" from "input.operationType == "search_products""
     *
     * @param rule     the rule string
     * @param operator the operator to search for
     * @return the limit value as a string
     */
    private String extractLimit(String rule, String operator) {
        String[] parts = rule.split(operator);
        if (parts.length > 1) {
            String limit = parts[1].trim();
            
            // If the limit is a quoted string, extract the content between quotes
            if (limit.startsWith("\"") && limit.endsWith("\"")) {
                limit = limit.substring(1, limit.length() - 1);
            }
            
            return limit;
        }
        return "";
    }

    /**
     * Evaluates a comparison between a value and a limit.
     *
     * @param value    the input value
     * @param operator the comparison operator
     * @param limitStr the limit value as a string
     * @return true if the comparison evaluates to true, false otherwise
     */
    private boolean evaluateComparison(Object value, String operator, String limitStr) {
        try {
            if (value instanceof Number) {
                double numValue = ((Number) value).doubleValue();
                double limit = Double.parseDouble(limitStr);
                
                return switch (operator) {
                    case "<=" -> numValue <= limit;
                    case ">=" -> numValue >= limit;
                    case "<" -> numValue < limit;
                    case ">" -> numValue > limit;
                    case "==" -> numValue == limit;
                    case "!=" -> numValue != limit;
                    default -> {
                        logger.warn("Unknown operator: {}", operator);
                        yield false;
                    }
                };
            } else if (value instanceof String strValue) {

                // Remove quotes from limit if present
                String limit = limitStr.replaceAll("^\"|\"$", "");
                
                return switch (operator) {
                    case "==" -> strValue.equals(limit);
                    case "!=" -> !strValue.equals(limit);
                    default -> {
                        logger.warn("Operator {} not supported for string comparison", operator);
                        yield false;
                    }
                };
            } else {
                logger.warn("Unsupported value type for comparison: {}", value.getClass());
                return false;
            }
        } catch (NumberFormatException e) {
            logger.warn("Failed to parse limit value: {}", limitStr, e);
            return false; // Fail-safe: deny on parse error
        }
    }

    /**
     * Validates the syntax of a policy before evaluation.
     *
     * @param policy the policy to validate
     * @throws PolicyEvaluationException if the policy syntax is invalid
     */
    private void validatePolicySyntax(Policy policy) {

        // Check for empty policy
        String regoPolicy = policy.getRegoPolicy();
        if (regoPolicy == null || regoPolicy.trim().isEmpty()) {
            throw new PolicyEvaluationException("Policy Rego content is empty", null, policy.getPolicyId());
        }
        
        // Check for package declaration
        if (!regoPolicy.contains("package ")) {
            logger.warn("Policy {} does not contain a package declaration", policy.getPolicyId());
        }
        
        // Check for allow rule
        if (!regoPolicy.contains("allow")) {
            logger.warn("Policy {} does not contain an allow rule", policy.getPolicyId());
        }
        
        // Check for balanced braces
        int braceCount = 0;
        for (char c : regoPolicy.toCharArray()) {
            if (c == '{') braceCount++;
            else if (c == '}') braceCount--;
        }
        if (braceCount != 0) {
            throw new PolicyEvaluationException(
                    "Policy has unbalanced braces", null, policy.getPolicyId());
        }
    }

    /**
     * Retrieves a nested value from a map using dot notation.
     * <p>
     * For example, given a map with nested structure, this method can
     * retrieve values using paths like "transaction.amount".
     * </p>
     *
     * @param map  the map to search
     * @param path the dot-notation path to the value
     * @return the value at the specified path, or null if not found
     */
    private Object getNestedValue(Map<String, Object> map, String path) {
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
     * Extracts the package name from a Rego policy.
     *
     * @param regoPolicy the Rego policy string
     * @return the package name, or "default" if not found
     */
    private String extractPackageName(String regoPolicy) {
        if (regoPolicy.contains("package ")) {
            int start = regoPolicy.indexOf("package ") + 8;
            int end = regoPolicy.indexOf("\n", start);
            if (end == -1) {
                end = regoPolicy.length();
            }
            return regoPolicy.substring(start, end).trim();
        }
        return "default";
    }

    /**
     * Builds a human-readable reasoning string for the evaluation result.
     *
     * @param result the evaluation result
     * @param policy the evaluated policy
     * @return the reasoning string
     */
    private String buildReasoning(EvaluationResult result, Policy policy) {

        StringBuilder reasoning = new StringBuilder();
        
        reasoning.append("Policy evaluation result: ");
        reasoning.append(result.allowed() ? "ALLOWED" : "DENIED");
        reasoning.append(". ");
        
        if (result.message() != null) {
            reasoning.append(result.message());
        }
        
        if (policy.getDescription() != null) {
            reasoning.append(" Description: ");
            reasoning.append(policy.getDescription());
        }
        
        return reasoning.toString();
    }

    /**
     * Clears the policy cache.
     * <p>
     * This method is primarily intended for testing purposes or when
     * policies need to be reloaded.
     * </p>
     */
    public void clearCache() {
        policyCache.clear();
        logger.info("Policy cache cleared");
    }

    /**
     * Returns the current size of the policy cache.
     *
     * @return the number of policies in the cache
     */
    public int getCacheSize() {
        return policyCache.size();
    }

    /**
     * Returns the total number of policy evaluations performed.
     *
     * @return the total evaluation count
     */
    public long getTotalEvaluationCount() {
        return totalEvaluationCount.get();
    }

    /**
     * Returns the number of cache hits.
     *
     * @return the cache hit count
     */
    public long getCacheHitCount() {
        return cacheHitCount.get();
    }

    /**
     * Returns the cache hit rate as a percentage.
     *
     * @return the cache hit rate (0-100), or 0 if no evaluations have been performed
     */
    public double getCacheHitRate() {
        long total = totalEvaluationCount.get();
        if (total == 0) {
            return 0.0;
        }
        return (cacheHitCount.get() * 100.0) / total;
    }

    /**
     * Internal representation of a compiled policy.
     * <p>
     * This class holds the parsed information needed for evaluation,
     * including the policy ID, package name, and the Rego policy string.
     * </p>
     */
    private record CompiledPolicy(String policyId, String packageName, String regoPolicy) {
        private CompiledPolicy(String policyId, String packageName, String regoPolicy) {
            this.policyId = Objects.requireNonNull(policyId, "Policy ID cannot be null");
            this.packageName = Objects.requireNonNull(packageName, "Package name cannot be null");
            this.regoPolicy = Objects.requireNonNull(regoPolicy, "Rego policy cannot be null");
        }
    }

    /**
     * Internal representation of an evaluation result.
     * <p>
     * This class holds the outcome of a policy evaluation, including
     * the allow/deny decision, a message explaining the result, and
     * any additional output data.
     * </p>
     */
    private record EvaluationResult(boolean allowed, String message, Map<String, Object> output) { }

}