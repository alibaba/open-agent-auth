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
import com.alibaba.openagentauth.core.model.policy.AclPolicy;
import com.alibaba.openagentauth.core.policy.util.PatternMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ACL (Access Control List) policy evaluator implementation.
 * <p>
 * Evaluates ACL-based policies where each resource has an associated
 * list of permissions for specific principals.
 * </p>
 *
 * @see PolicyEvaluator
 * @see AclPolicy
 */
public class AclPolicyEvaluator implements PolicyEvaluator {
    
    private static final Logger logger = LoggerFactory.getLogger(AclPolicyEvaluator.class);
    private static final com.fasterxml.jackson.databind.ObjectMapper OBJECT_MAPPER = new com.fasterxml.jackson.databind.ObjectMapper();
    
    private final PolicyRegistry policyRegistry;
    private final PatternMatcher patternMatcher;
    
    private final Map<String, AclPolicy> policyCache;
    private final boolean enableCache;
    private final int maxCacheSize;
    
    /**
     * Creates an AclPolicyEvaluator with default settings.
     *
     * @param policyRegistry the policy registry
     */
    public AclPolicyEvaluator(PolicyRegistry policyRegistry) {
        this(policyRegistry, true, 100);
    }
    
    /**
     * Creates an AclPolicyEvaluator with custom settings.
     *
     * @param policyRegistry the policy registry
     * @param enableCache    whether to enable policy caching
     * @param maxCacheSize   the maximum number of policies to cache
     */
    public AclPolicyEvaluator(PolicyRegistry policyRegistry, boolean enableCache, int maxCacheSize) {
        this.policyRegistry = Objects.requireNonNull(policyRegistry, "PolicyRegistry cannot be null");
        this.patternMatcher = new PatternMatcher();
        this.enableCache = enableCache;
        this.maxCacheSize = maxCacheSize;
        this.policyCache = new ConcurrentHashMap<>();
        logger.info("AclPolicyEvaluator initialized with cache: {}, maxCacheSize: {}", enableCache, maxCacheSize);
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
            AclPolicy aclPolicy = getOrParsePolicy(policy);
            
            String principal = extractPrincipal(inputData);
            String resource = extractResource(inputData);
            String permission = extractPermission(inputData);
            
            boolean hasAllow = false;
            boolean hasDeny = false;
            String matchedEntry = null;
            
            for (AclPolicy.AclEntry entry : aclPolicy.getEntries()) {
                if (!matchPrincipal(entry.getPrincipal(), principal)) {
                    continue;
                }
                
                if (!patternMatcher.matchSinglePattern(entry.getResource(), resource)) {
                    continue;
                }
                
                if (!entry.getPermissions().contains(permission)) {
                    continue;
                }
                
                if (entry.getEffect() == AclPolicy.AclEffect.DENY) {
                    hasDeny = true;
                    matchedEntry = entry.toString();
                    break; // DENY takes precedence
                } else {
                    hasAllow = true;
                    matchedEntry = entry.toString();
                }
            }
            
            boolean allowed = hasAllow && !hasDeny;
            String reasoning = hasDeny 
                ? "DENY by ACL entry: " + matchedEntry
                : (hasAllow ? "ALLOW by ACL entry: " + matchedEntry : "Default DENY");
            
            Map<String, Object> output = new java.util.HashMap<>();
            output.put("allowed", allowed);
            output.put("matchedEntry", matchedEntry);
            
            return new PolicyEvaluationResult(allowed, reasoning, null, output);
            
        } catch (PolicyNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to evaluate ACL policy: {}", policyId, e);
            return new PolicyEvaluationResult(
                false,
                "ACL policy evaluation failed: " + e.getMessage(),
                e.getMessage(),
                Map.of("allowed", false, "error", e.getMessage())
            );
        }
    }
    
    /**
     * Gets or parses an ACL policy.
     *
     * @param policy the policy to parse
     * @return the ACL policy
     */
    private AclPolicy getOrParsePolicy(Policy policy) {
        String policyId = policy.getPolicyId();
        
        if (enableCache) {
            AclPolicy cached = policyCache.get(policyId);
            if (cached != null) {
                return cached;
            }
        }
        
        AclPolicy aclPolicy = parsePolicy(policy.getRegoPolicy());
        
        if (enableCache) {
            if (policyCache.size() >= maxCacheSize) {
                policyCache.clear();
            }
            policyCache.put(policyId, aclPolicy);
        }
        
        return aclPolicy;
    }
    
    /**
     * Parses an ACL policy from JSON string.
     *
     * @param jsonPolicy the JSON policy string
     * @return the parsed ACL policy
     */
    private AclPolicy parsePolicy(String jsonPolicy) {
        try {
            return OBJECT_MAPPER.readValue(jsonPolicy, AclPolicy.class);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new PolicyEvaluationException("Failed to parse ACL policy: " + e.getMessage(), e, null);
        }
    }
    
    /**
     * Extracts the principal from input data.
     *
     * @param inputData the input data
     * @return the principal, or null if not found
     */
    private String extractPrincipal(Map<String, Object> inputData) {
        Object principal = inputData.get("operationType");
        return principal != null ? principal.toString() : null;
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
     * Extracts the permission from input data.
     *
     * @param inputData the input data
     * @return the permission, or null if not found
     */
    private String extractPermission(Map<String, Object> inputData) {
        Object permission = inputData.get("operationType");
        return permission != null ? permission.toString() : null;
    }
    
    /**
     * Matches a principal against an entry principal.
     *
     * @param entryPrincipal  the entry principal
     * @param inputPrincipal  the input principal
     * @return true if matched, false otherwise
     */
    private boolean matchPrincipal(String entryPrincipal, String inputPrincipal) {
        if (entryPrincipal == null || inputPrincipal == null) {
            return false;
        }
        
        // Support wildcards in principal
        if (entryPrincipal.equals("*")) {
            return true;
        }
        
        // Support role-based matching
        if (entryPrincipal.startsWith("role:")) {
            return inputPrincipal.startsWith("user:") || inputPrincipal.equals(entryPrincipal);
        }
        
        return entryPrincipal.equals(inputPrincipal);
    }
    
    /**
     * Clears the policy cache.
     */
    public void clearCache() {
        policyCache.clear();
        logger.info("ACL policy cache cleared");
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
