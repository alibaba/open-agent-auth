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
package com.alibaba.openagentauth.core.policy.registry;

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.exception.policy.PolicyRegistrationException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyMetadata;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link PolicyRegistry}.
 * <p>
 * This implementation stores policies in memory using a concurrent hash map.
 * It provides a thread-safe, production-ready implementation suitable for
 * development and testing environments.
 * </p>
 * <p>
 * <b>Implementation Details:</b></p>
 * <ul>
 *   <li>Uses ConcurrentHashMap for thread-safe policy storage</li>
 *   <li>Supports policy expiration and cleanup</li>
 *   <li>Generates unique policy IDs automatically</li>
 *   <li>Provides comprehensive policy lifecycle management</li>
 * </ul>
 * </p>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Policies are lost when the application restarts</li>
 *   <li>Not suitable for distributed environments</li>
 *   <li>Memory usage grows with the number of policies</li>
 * </ul>
 * </p>
 * <p>
 * <b>Production Considerations:</b></p>
 * For production use, consider implementing a persistent registry using:
 * <ul>
 *   <li>Relational database (PostgreSQL, MySQL)</li>
 *   <li>NoSQL database (MongoDB, Redis)</li>
 *   <li>Distributed cache (Hazelcast, Apache Ignite)</li>
 * </ul>
 * </p>
 *
 * @see PolicyRegistry
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
public class InMemoryPolicyRegistry implements PolicyRegistry {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(InMemoryPolicyRegistry.class);

    /**
     * In-memory storage for policies.
     * Uses ConcurrentHashMap for thread-safe operations.
     */
    private final Map<String, Policy> policyStore;

    /**
     * Prefix for generated policy IDs.
     */
    private static final String POLICY_ID_PREFIX = "policy-";

    /**
     * Creates a new InMemoryPolicyRegistry.
     */
    public InMemoryPolicyRegistry() {
        this.policyStore = new ConcurrentHashMap<>();
        logger.info("InMemoryPolicyRegistry initialized");
    }

    /**
     * Registers a new policy.
     *
     * @param regoPolicy     the Rego policy
     * @param description    the policy description
     * @param createdBy      the creator of the policy
     * @param expirationTime the expiration time of the policy
     * @return the registration result
     * @throws PolicyRegistrationException if the policy registration fails
     */
    @Override
    public PolicyRegistration register(String regoPolicy, String description, String createdBy, Instant expirationTime) {

        logger.info("Registering new policy created by: {}", createdBy);
        
        // Validate input parameters
        if (ValidationUtils.isNullOrEmpty(regoPolicy)) {
            throw PolicyRegistrationException.validationFailed("Rego policy cannot be empty");
        }
        
        if (ValidationUtils.isNullOrEmpty(createdBy)) {
            throw PolicyRegistrationException.validationFailed("Creator cannot be empty");
        }
        
        try {
            // Generate a unique policy ID
            String policyId = generatePolicyId();
            
            // Create policy metadata
            PolicyMetadata metadata = PolicyMetadata.builder()
                    .version("1.0")
                    .createdAt(Instant.now())
                    .createdBy(createdBy)
                    .expirationTime(expirationTime)
                    .build();
            
            // Create the policy
            Policy policy = Policy.builder()
                    .policyId(policyId)
                    .regoPolicy(regoPolicy)
                    .description(description)
                    .metadata(metadata)
                    .build();
            
            // Store the policy
            policyStore.put(policyId, policy);
            
            logger.info("Policy registered successfully: {}", policyId);
            
            // Create and return the registration result
            return PolicyRegistration.builder()
                    .policy(policy)
                    .originalProposal(regoPolicy)
                    .registeredAt(Instant.now())
                    .status("SUCCESS")
                    .build();
            
        } catch (Exception e) {
            logger.error("Failed to register policy", e);
            throw PolicyRegistrationException.storageError("Failed to register policy: " + e.getMessage(), e);
        }
    }

    /**
     * Gets a policy by ID.
     *
     * @param policyId the policy ID
     * @return the policy
     * @throws PolicyNotFoundException if the policy is not found
     */
    @Override
    public Policy get(String policyId) {

        // Check if policy exists
        Optional<Policy> policy = get(policyId, false);
        if (policy.isEmpty()) {
            throw new PolicyNotFoundException(policyId);
        }
        
        return policy.get();
    }

    /**
     * Gets a policy by ID.
     *
     * @param policyId         the policy ID
     * @param includeExpired   whether to include expired policies
     * @return the policy, or empty if not found
     */
    @Override
    public Optional<Policy> get(String policyId, boolean includeExpired) {

        // Get the policy from the store
        Policy policy = policyStore.get(policyId);
        if (policy == null) {
            return Optional.empty();
        }
        
        // Check if policy is expired
        if (!includeExpired && policy.isExpired()) {
            logger.debug("Policy {} is expired", policyId);
            return Optional.empty();
        }
        
        return Optional.of(policy);
    }

    /**
     * Checks if a policy exists.
     *
     * @param policyId the policy ID
     * @return true if the policy exists, false otherwise
     */
    @Override
    public boolean exists(String policyId) {
        return get(policyId, false).isPresent();
    }

    /**
     * Updates a policy.
     *
     * @param policyId     the policy ID
     * @param regoPolicy   the Rego policy
     * @param description  the policy description
     * @return the updated policy
     * @throws PolicyNotFoundException if the policy is not found
     */
    @Override
    public Policy update(String policyId, String regoPolicy, String description) {

        // Validate input parameters
        logger.info("Updating policy: {}", policyId);
        if (ValidationUtils.isNullOrEmpty(regoPolicy)) {
            throw PolicyRegistrationException.validationFailed("Rego policy cannot be empty");
        }
        
        // Check if policy exists
        Policy existingPolicy = get(policyId);
        
        try {
            // Create updated policy
            Policy updatedPolicy = Policy.builder()
                    .policyId(existingPolicy.getPolicyId())
                    .regoPolicy(regoPolicy)
                    .description(description != null ? description : existingPolicy.getDescription())
                    .metadata(existingPolicy.getMetadata())
                    .build();
            
            // Update the policy in the store
            policyStore.put(policyId, updatedPolicy);
            logger.info("Policy updated successfully: {}", policyId);

            return updatedPolicy;
            
        } catch (Exception e) {
            logger.error("Failed to update policy: {}", policyId, e);
            throw PolicyRegistrationException.storageError("Failed to update policy: " + e.getMessage(), e);
        }
    }

    /**
     * Deletes a policy.
     *
     * @param policyId the policy ID
     * @throws PolicyNotFoundException if the policy is not found
     */
    @Override
    public void delete(String policyId) {

        logger.info("Deleting policy: {}", policyId);
        
        // Check if policy exists
        get(policyId);
        
        // Remove the policy
        policyStore.remove(policyId);
        
        logger.info("Policy deleted successfully: {}", policyId);
    }

    /**
     * Lists all policies.
     *
     * @return the list of policies
     */
    @Override
    public List<Policy> listAll() {

        logger.debug("Listing all policies");
        List<Policy> policies = new ArrayList<>();
        
        for (Policy policy : policyStore.values()) {
            // Exclude expired policies
            if (!policy.isExpired()) {
                policies.add(policy);
            }
        }
        
        return policies;
    }

    /**
     * Lists policies by creator.
     *
     * @param createdBy the creator
     * @return the list of policies
     */
    @Override
    public List<Policy> listByCreator(String createdBy) {

        logger.debug("Listing policies by creator: {}", createdBy);
        List<Policy> policies = new ArrayList<>();
        
        for (Policy policy : policyStore.values()) {
            // Filter by creator and exclude expired policies
            if (createdBy.equals(policy.getMetadata().getCreatedBy()) && !policy.isExpired()) {
                policies.add(policy);
            }
        }
        
        return policies;
    }

    /**
     * Lists expired policies.
     *
     * @return the list of expired policies
     */
    @Override
    public List<Policy> listExpired() {

        logger.debug("Listing expired policies");
        List<Policy> policies = new ArrayList<>();
        
        for (Policy policy : policyStore.values()) {
            if (policy.isExpired()) {
                policies.add(policy);
            }
        }
        
        return policies;
    }

    /**
     * Cleans up expired policies.
     *
     * @return the number of expired policies removed
     */
    @Override
    public int cleanupExpired() {

        logger.info("Cleaning up expired policies");
        List<String> expiredPolicyIds = new ArrayList<>();
        
        // Find all expired policies
        for (Policy policy : policyStore.values()) {
            if (policy.isExpired()) {
                expiredPolicyIds.add(policy.getPolicyId());
            }
        }
        
        // Remove expired policies
        for (String policyId : expiredPolicyIds) {
            policyStore.remove(policyId);
        }
        
        int count = expiredPolicyIds.size();
        logger.info("Cleaned up {} expired policies", count);
        
        return count;
    }

    @Override
    public int size() {
        return policyStore.size();
    }

    /**
     * Generates a unique policy ID.
     *
     * @return a unique policy ID
     */
    private String generatePolicyId() {
        return POLICY_ID_PREFIX + UUID.randomUUID();
    }

    /**
     * Clears all policies from the registry.
     * <p>
     * This method is primarily intended for testing purposes.
     * </p>
     */
    public void clear() {
        policyStore.clear();
        logger.info("All policies cleared from registry");
    }
}