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
import com.alibaba.openagentauth.core.model.policy.ScopePolicy;
import com.alibaba.openagentauth.core.policy.util.ResourceValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth Scope policy evaluator implementation.
 * <p>
 * Evaluates scope-based authorization following OAuth 2.0 standards (RFC 6749, RFC 8707).
 * </p>
 *
 * @see PolicyEvaluator
 * @see ScopePolicy
 */
public class ScopePolicyEvaluator implements PolicyEvaluator {
    
    private static final Logger logger = LoggerFactory.getLogger(ScopePolicyEvaluator.class);
    private static final com.fasterxml.jackson.databind.ObjectMapper OBJECT_MAPPER = new com.fasterxml.jackson.databind.ObjectMapper();
    
    private final PolicyRegistry policyRegistry;
    private final ResourceValidator resourceValidator;
    
    private final Map<String, ScopePolicy> policyCache;
    private final boolean enableCache;
    private final int maxCacheSize;
    
    /**
     * Creates a ScopePolicyEvaluator with default settings.
     *
     * @param policyRegistry the policy registry
     */
    public ScopePolicyEvaluator(PolicyRegistry policyRegistry) {
        this(policyRegistry, true, 100);
    }
    
    /**
     * Creates a ScopePolicyEvaluator with custom settings.
     *
     * @param policyRegistry the policy registry
     * @param enableCache    whether to enable policy caching
     * @param maxCacheSize   the maximum number of policies to cache
     */
    public ScopePolicyEvaluator(PolicyRegistry policyRegistry, boolean enableCache, int maxCacheSize) {
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "PolicyRegistry cannot be null");
        this.resourceValidator = new ResourceValidator();
        this.enableCache = enableCache;
        this.maxCacheSize = maxCacheSize;
        this.policyCache = new ConcurrentHashMap<>();
        logger.info("ScopePolicyEvaluator initialized with cache: {}, maxCacheSize: {}", enableCache, maxCacheSize);
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
            ScopePolicy scopePolicy = getOrParsePolicy(policy);
            
            // Extract required scope from input
            String requiredScope = extractRequiredScope(inputData);
            String resource = extractResource(inputData);
            
            if (requiredScope == null) {
                return new PolicyEvaluationResult(
                    false,
                    "No scope provided in input data",
                    null,
                    Map.of("allowed", false, "error", "missing_scope")
                );
            }
            
            // Find the scope definition
            Optional<ScopePolicy.ScopeDefinition> scopeDef = scopePolicy.getScopes().stream()
                .filter(s -> s.getName().equals(requiredScope))
                .findFirst();
            
            if (scopeDef.isEmpty()) {
                return new PolicyEvaluationResult(
                    false, 
                    "Scope not found: " + requiredScope, 
                    null,
                    Map.of("allowed", false, "scope", requiredScope)
                );
            }
            
            // Validate resource access
            boolean resourceAllowed = resourceValidator.validate(
                scopeDef.get().getResources(), resource
            );
            
            if (!resourceAllowed) {
                return new PolicyEvaluationResult(
                    false,
                    "Scope " + requiredScope + " does not grant access to resource: " + resource,
                    null,
                    Map.of("allowed", false, "scope", requiredScope, "resource", resource)
                );
            }
            
            return new PolicyEvaluationResult(
                true,
                "Access granted via scope: " + requiredScope,
                null,
                Map.of("allowed", true, "scope", requiredScope, "resource", resource)
            );
            
        } catch (PolicyNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to evaluate Scope policy: {}", policyId, e);
            return new PolicyEvaluationResult(
                false,
                "Scope policy evaluation failed: " + e.getMessage(),
                e.getMessage(),
                Map.of("allowed", false, "error", e.getMessage())
            );
        }
    }
    
    /**
     * Gets or parses a Scope policy.
     *
     * @param policy the policy to parse
     * @return the Scope policy
     */
    private ScopePolicy getOrParsePolicy(Policy policy) {
        String policyId = policy.getPolicyId();
        
        if (enableCache) {
            ScopePolicy cached = policyCache.get(policyId);
            if (cached != null) {
                return cached;
            }
        }
        
        ScopePolicy scopePolicy = parsePolicy(policy.getRegoPolicy());
        
        if (enableCache) {
            if (policyCache.size() >= maxCacheSize) {
                policyCache.clear();
            }
            policyCache.put(policyId, scopePolicy);
        }
        
        return scopePolicy;
    }
    
    /**
     * Parses a Scope policy from JSON string.
     *
     * @param jsonPolicy the JSON policy string
     * @return the parsed Scope policy
     */
    private ScopePolicy parsePolicy(String jsonPolicy) {
        try {
            return OBJECT_MAPPER.readValue(jsonPolicy, ScopePolicy.class);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new PolicyEvaluationException("Failed to parse Scope policy: " + e.getMessage(), e, null);
        }
    }
    
    /**
     * Extracts the required scope from input data.
     *
     * @param inputData the input data
     * @return the required scope, or null if not found
     */
    private String extractRequiredScope(Map<String, Object> inputData) {
        Object scope = inputData.get("operationType");
        return scope != null ? scope.toString() : null;
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
        logger.info("Scope policy cache cleared");
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
