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
import com.alibaba.openagentauth.core.model.policy.RamPolicy;
import com.alibaba.openagentauth.core.policy.util.ConditionEvaluator;
import com.alibaba.openagentauth.core.policy.util.InternalEvaluationResult;
import com.alibaba.openagentauth.core.policy.util.PatternMatcher;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RAM (Resource Access Management) policy evaluator implementation.
 * <p>
 * Evaluates RAM-style policies similar to AWS IAM and Alibaba Cloud RAM.
 * Supports structured policy definitions with effects, actions, resources, and conditions.
 * </p>
 *
 * @see PolicyEvaluator
 * @see RamPolicy
 */
public class RamPolicyEvaluator implements PolicyEvaluator {
    
    private static final Logger logger = LoggerFactory.getLogger(RamPolicyEvaluator.class);
    private static final com.fasterxml.jackson.databind.ObjectMapper OBJECT_MAPPER = new com.fasterxml.jackson.databind.ObjectMapper();
    static {
        OBJECT_MAPPER.registerModules(new JavaTimeModule());
    }
    
    private final PolicyRegistry policyRegistry;
    private final ConditionEvaluator conditionEvaluator;
    private final PatternMatcher patternMatcher;
    
    private final Map<String, RamPolicy> policyCache;
    private final boolean enableCache;
    private final int maxCacheSize;
    
    /**
     * Creates a RamPolicyEvaluator with default settings.
     *
     * @param policyRegistry the policy registry
     */
    public RamPolicyEvaluator(PolicyRegistry policyRegistry) {
        this(policyRegistry, true, 100);
    }
    
    /**
     * Creates a RamPolicyEvaluator with custom settings.
     *
     * @param policyRegistry the policy registry
     * @param enableCache    whether to enable policy caching
     * @param maxCacheSize   the maximum number of policies to cache
     */
    public RamPolicyEvaluator(PolicyRegistry policyRegistry, boolean enableCache, int maxCacheSize) {
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "PolicyRegistry cannot be null");
        this.conditionEvaluator = new ConditionEvaluator();
        this.patternMatcher = new PatternMatcher();
        this.enableCache = enableCache;
        this.maxCacheSize = maxCacheSize;
        this.policyCache = new ConcurrentHashMap<>();
        logger.info("RamPolicyEvaluator initialized with cache: {}, maxCacheSize: {}", enableCache, maxCacheSize);
    }
    
    @Override
    public boolean evaluate(String policyId, Map<String, Object> inputData) {
        PolicyEvaluationResult result = evaluateWithDetails(policyId, inputData);
        if (!result.isSuccess()) {
            throw new PolicyEvaluationException(result.getErrorMessage(), null, policyId);
        }
        return result.isAllowed();
    }
    
    @Override
    public PolicyEvaluationResult evaluateWithDetails(String policyId, Map<String, Object> inputData) {
        try {
            Policy policy = policyRegistry.get(policyId);
            RamPolicy ramPolicy = getOrParsePolicy(policy);
            
            boolean hasDeny = false;
            boolean hasAllow = false;
            String denyReason = null;
            String allowReason = null;
            
            for (RamPolicy.RamStatement statement : ramPolicy.getStatements()) {
                InternalEvaluationResult result = evaluateStatement(statement, inputData);
                
                if (result.isMatched() && result.isAllowed() && statement.getEffect() == RamPolicy.Effect.DENY) {
                    hasDeny = true;
                    denyReason = result.getReasoning();
                    break; // DENY takes precedence
                }
                
                if (result.isMatched() && result.isAllowed() && statement.getEffect() == RamPolicy.Effect.ALLOW) {
                    hasAllow = true;
                    allowReason = result.getReasoning();
                }
            }
            
            boolean allowed = hasAllow && !hasDeny;
            String reasoning = hasDeny ? denyReason : (hasAllow ? allowReason : "Default DENY");
            
            return new PolicyEvaluationResult(allowed, reasoning, null, Map.of(
                "allowed", allowed,
                "hasAllow", hasAllow,
                "hasDeny", hasDeny
            ));
            
        } catch (PolicyNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to evaluate RAM policy: {}", policyId, e);
            return new PolicyEvaluationResult(
                false,
                "RAM policy evaluation failed: " + e.getMessage(),
                e.getMessage(),
                Map.of("allowed", false, "error", e.getMessage())
            );
        }
    }
    
    /**
     * Gets or parses a RAM policy.
     *
     * @param policy the policy to parse
     * @return the RAM policy
     */
    private RamPolicy getOrParsePolicy(Policy policy) {
        String policyId = policy.getPolicyId();
        
        if (enableCache) {
            RamPolicy cached = policyCache.get(policyId);
            if (cached != null) {
                return cached;
            }
        }
        
        RamPolicy ramPolicy = parsePolicy(policy.getRegoPolicy());
        
        if (enableCache) {
            if (policyCache.size() >= maxCacheSize) {
                policyCache.clear();
            }
            policyCache.put(policyId, ramPolicy);
        }
        
        return ramPolicy;
    }
    
    /**
     * Parses a RAM policy from JSON string.
     *
     * @param jsonPolicy the JSON policy string
     * @return the parsed RAM policy
     */
    private RamPolicy parsePolicy(String jsonPolicy) {
        try {
            return OBJECT_MAPPER.readValue(jsonPolicy, RamPolicy.class);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new PolicyEvaluationException("Failed to parse RAM policy: " + e.getMessage(), e, null);
        }
    }
    
    /**
     * Evaluates a RAM statement.
     *
     * @param statement  the statement to evaluate
     * @param inputData  the input data
     * @return the evaluation result
     */
    private InternalEvaluationResult evaluateStatement(RamPolicy.RamStatement statement, Map<String, Object> inputData) {
        // Match action pattern
        String action = extractAction(inputData);
        if (action == null || !patternMatcher.match(statement.getActions(), action)) {
            return InternalEvaluationResult.notMatched("Action not matched");
        }
        
        // Match resource pattern
        String resource = extractResource(inputData);
        if (resource == null || !patternMatcher.match(statement.getResources(), resource)) {
            return InternalEvaluationResult.notMatched("Resource not matched");
        }
        
        // Evaluate condition if present
        if (statement.getCondition() != null) {
            boolean conditionResult = conditionEvaluator.evaluate(
                statement.getCondition(), inputData
            );
            if (!conditionResult) {
                return InternalEvaluationResult.denied("Condition not satisfied");
            }
        }
        
        return InternalEvaluationResult.allowed("Statement matched");
    }
    
    /**
     * Extracts the action from input data.
     *
     * @param inputData the input data
     * @return the action, or null if not found
     */
    private String extractAction(Map<String, Object> inputData) {
        Object action = inputData.get("operationType");
        return action != null ? action.toString() : null;
    }
    
    /**
     * Extracts the resource from input data.
     *
     * @param inputData the input data
     * @return the resource, or null if not found
     */
    private String extractResource(Map<String, Object> inputData) {
        Object resource = inputData.get("resourceId");
        return resource != null ? resource.toString() : null;
    }
    
    /**
     * Clears the policy cache.
     */
    public void clearCache() {
        policyCache.clear();
        logger.info("RAM policy cache cleared");
    }
    
    /**
     * Returns the current size of the policy cache.
     *
     * @return the number of policies in the cache
     */
    public int getCacheSize() {
        return policyCache.size();
    }
}
