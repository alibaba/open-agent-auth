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
package com.alibaba.openagentauth.core.binding;

/**
 * Storage interface for binding instances.
 * <p>
 * This interface defines the contract for storing and retrieving binding instances
 * that establish the relationship between user identities and workload identities.
 * Implementations can use various storage backends such as in-memory, database,
 * or distributed cache.
 * </p>
 * <p>
 * <b>Storage Requirements:</b></p>
 * <ul>
 *   <li>Store binding instances keyed by binding instance ID</li>
 *   <li>Support CRUD operations for binding management</li>
 *   <li>Handle concurrent access safely</li>
 *   <li>Support expiration of bindings</li>
 * </ul>
 * <p>
 * <b>Use Cases:</b></p>
 * <ul>
 *   <li>Authorization Server stores bindings when issuing AOATs</li>
 *   <li>Resource Servers query bindings to verify identity consistency</li>
 *   <li>Support for two-layer identity verification (user + workload)</li>
 * </ul>
 *
 * @see BindingInstance
 * @since 1.0
 */
public interface BindingInstanceStore {

    /**
     * Stores a new binding instance.
     *
     * @param bindingInstance the binding instance to store
     */
    void store(BindingInstance bindingInstance);

    /**
     * Retrieves a binding instance by its ID.
     *
     * @param bindingInstanceId the binding instance ID
     * @return the binding instance, or null if not found
     */
    BindingInstance retrieve(String bindingInstanceId);

    /**
     * Retrieves a binding instance by user identity.
     * <p>
     * This method is useful for finding all bindings for a specific user.
     * </p>
     *
     * @param userIdentity the user identity
     * @return the binding instance, or null if not found
     */
    BindingInstance retrieveByUserIdentity(String userIdentity);

    /**
     * Retrieves a binding instance by workload identity.
     * <p>
     * This method is useful for finding all bindings for a specific workload.
     * </p>
     *
     * @param workloadIdentity the workload identity
     * @return the binding instance, or null if not found
     */
    BindingInstance retrieveByWorkloadIdentity(String workloadIdentity);

    /**
     * Updates an existing binding instance.
     *
     * @param bindingInstance the updated binding instance
     */
    void update(BindingInstance bindingInstance);

    /**
     * Deletes a binding instance by its ID.
     *
     * @param bindingInstanceId the binding instance ID
     */
    void delete(String bindingInstanceId);

    /**
     * Checks if a binding instance exists.
     *
     * @param bindingInstanceId the binding instance ID
     * @return true if the binding exists, false otherwise
     */
    boolean exists(String bindingInstanceId);

    /**
     * Checks if a binding instance is valid (not expired).
     *
     * @param bindingInstanceId the binding instance ID
     * @return true if the binding exists and is valid, false otherwise
     */
    boolean isValid(String bindingInstanceId);

    /**
     * Deletes expired binding instances.
     * <p>
     * This method should be called periodically to clean up expired bindings.
     * </p>
     *
     * @return the number of bindings deleted
     */
    int deleteExpired();

}
