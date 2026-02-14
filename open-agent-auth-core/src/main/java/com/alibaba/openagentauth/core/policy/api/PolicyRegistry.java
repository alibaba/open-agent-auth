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
package com.alibaba.openagentauth.core.policy.api;

import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Interface for policy registry operations.
 * <p>
 * The PolicyRegistry is responsible for storing, retrieving, and managing policies
 * within the Agent Operation Authorization framework. It serves as the central repository
 * for all registered policies and provides CRUD operations with lifecycle management.
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li>Register new policies after validation</li>
 *   <li>Retrieve policies by ID</li>
 *   <li>Update existing policies</li>
 *   <li>Delete policies</li>
 *   <li>List and search policies</li>
 *   <li>Handle policy expiration</li>
 * </ul>
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Interface Segregation:</b> This interface focuses solely on registry operations</li>
 *   <li><b>Single Responsibility:</b> Only handles policy storage and retrieval</li>
 *   <li><b>Extensibility:</b> Supports multiple storage backends (in-memory, database, etc.)</li>
 *   <li><b>Thread Safety:</b> Implementations MUST be thread-safe</li>
 * </ul>
 * </p>
 *
 * @see Policy
 * @see PolicyRegistration
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
public interface PolicyRegistry {

    /**
     * Registers a new policy.
     * <p>
     * This method validates and stores a new policy in the registry.
     * The policy will be assigned a unique policy ID if not already set.
     * </p>
     *
     * @param regoPolicy      the Rego policy string to register
     * @param description     the policy description (optional)
     * @param createdBy       the entity creating the policy
     * @param expirationTime  the policy expiration time (optional)
     * @return the policy registration result containing the registered policy
     */
    PolicyRegistration register(String regoPolicy, String description, String createdBy, Instant expirationTime);

    /**
     * Retrieves a policy by its ID.
     * <p>
     * This method returns the policy with the specified ID.
     * If the policy does not exist or has expired, an exception is thrown.
     * </p>
     *
     * @param policyId the policy ID
     * @return the policy
     */
    Policy get(String policyId);

    /**
     * Retrieves a policy by its ID, optionally including expired policies.
     * <p>
     * This method returns the policy with the specified ID.
     * If the policy does not exist, an empty Optional is returned.
     * </p>
     *
     * @param policyId          the policy ID
     * @param includeExpired    whether to include expired policies
     * @return an Optional containing the policy, or empty if not found
     */
    Optional<Policy> get(String policyId, boolean includeExpired);

    /**
     * Checks if a policy exists and is valid.
     * <p>
     * This method returns true if a policy with the given ID exists and is not expired.
     * </p>
     *
     * @param policyId the policy ID
     * @return true if the policy exists and is valid, false otherwise
     */
    boolean exists(String policyId);

    /**
     * Updates an existing policy.
     * <p>
     * This method updates the policy with the specified ID.
     * Only the Rego policy and description can be updated.
     * The policy ID, creation time, and creator cannot be changed.
     * </p>
     *
     * @param policyId     the policy ID
     * @param regoPolicy   the new Rego policy string
     * @param description  the new description
     * @return the updated policy
     */
    Policy update(String policyId, String regoPolicy, String description);

    /**
     * Deletes a policy.
     * <p>
     * This method removes the policy with the specified ID from the registry.
     * Once deleted, the policy cannot be retrieved or used for authorization.
     * </p>
     *
     * @param policyId the policy ID
     */
    void delete(String policyId);

    /**
     * Lists all policies.
     * <p>
     * This method returns all policies in the registry.
     * Expired policies are excluded by default.
     * </p>
     *
     * @return a list of all policies
     */
    List<Policy> listAll();

    /**
     * Lists policies by creator.
     * <p>
     * This method returns all policies created by the specified entity.
     * Expired policies are excluded by default.
     * </p>
     *
     * @param createdBy the creator ID
     * @return a list of policies created by the specified entity
     */
    List<Policy> listByCreator(String createdBy);

    /**
     * Lists expired policies.
     * <p>
     * This method returns all policies that have expired.
     * </p>
     *
     * @return a list of expired policies
     */
    List<Policy> listExpired();

    /**
     * Cleans up expired policies.
     * <p>
     * This method removes all expired policies from the registry.
     * This operation is typically run on a scheduled basis.
     * </p>
     *
     * @return the number of policies removed
     */
    int cleanupExpired();

    /**
     * Gets the total number of policies in the registry.
     * <p>
     * This method returns the count of all policies, including expired ones.
     * </p>
     *
     * @return the total number of policies
     */
    int size();

}
