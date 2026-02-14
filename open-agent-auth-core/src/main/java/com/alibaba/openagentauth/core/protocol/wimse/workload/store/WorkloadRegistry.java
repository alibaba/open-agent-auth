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
package com.alibaba.openagentauth.core.protocol.wimse.workload.store;

import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;

import java.util.Optional;

/**
 * Interface for storing and retrieving workload information.
 * <p>
 * This interface defines the contract for workload storage as part of the WIMSE protocol.
 * It provides a standard abstraction for managing workload identities across different
 * storage implementations (in-memory, database, distributed cache, etc.).
 * </p>
 * <p>
 * <b>Protocol Context:</b></p>
 * <ul>
 *   <li>Workload is a core concept in WIMSE protocol (draft-ietf-wimse-workload-creds)</li>
 *   <li>WorkloadStore provides persistence for Workload Identity Tokens (WIT)</li>
 *   <li>Supports the virtual workload pattern for request-level isolation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Implementation Requirements:</b></p>
 * <ul>
 *   <li>Thread-safe storage and retrieval of workload information</li>
 *   <li>Automatic expiration checking for workloads</li>
 *   <li>Efficient cleanup of expired workloads</li>
 *   <li>Support for concurrent access patterns</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
public interface WorkloadRegistry {

    /**
     * Saves a workload.
     * <p>
     * This method stores the workload information for later retrieval.
     * If a workload with the same ID already exists, it should be replaced.
     * </p>
     *
     * @param workloadInfo the workload information to save
     * @throws IllegalArgumentException if workloadInfo is null
     */
    void save(WorkloadInfo workloadInfo);

    /**
     * Finds a workload by ID.
     * <p>
     * This method retrieves the workload information for the given workload ID.
     * Implementations should automatically filter out expired workloads.
     * </p>
     *
     * @param workloadId the workload ID
     * @return the workload information, or empty if not found or expired
     * @throws IllegalArgumentException if workloadId is null or empty
     */
    Optional<WorkloadInfo> findById(String workloadId);

    /**
     * Deletes a workload by ID.
     * <p>
     * This method removes the workload from storage. If the workload does not exist,
     * the operation should complete silently.
     * </p>
     *
     * @param workloadId the workload ID to delete
     * @throws IllegalArgumentException if workloadId is null or empty
     */
    void delete(String workloadId);

    /**
     * Checks if a workload exists and is not expired.
     * <p>
     * This method provides a quick existence check without retrieving the full
     * workload information.
     * </p>
     *
     * @param workloadId the workload ID
     * @return true if the workload exists and is not expired, false otherwise
     * @throws IllegalArgumentException if workloadId is null or empty
     */
    boolean exists(String workloadId);

    /**
     * Finds a workload by the workload unique key.
     * <p>
     * The workload unique key is used to identify and reuse workloads across
     * multiple requests. The key format depends on the workload binding strategy,
     * which can be customized (e.g., user + client, user + client + operation, etc.).
     * </p>
     * 
     * <p>
     * <b>Design Note:</b></p>
     * <ul>
     *   <li>The workload unique key provides a flexible mechanism for workload lookup</li>
     *   <li>It decouples the lookup strategy from the workload ID generation</li>
     *   <li>Supports various binding strategies without changing the interface</li>
     *   <li>Enables workload reuse across multiple requests for the same binding</li>
     * </ul>
     * 
     * <p>
     * <b>Implementation Requirements:</b></p>
     * <ul>
     *   <li>Implementations should store the workload unique key in the workload metadata</li>
     *   <li>The lookup should be efficient for high-throughput scenarios</li>
     *   <li>Expired workloads should be filtered out automatically</li>
     * </ul>
     * 
     * @param workloadUniqueKey the workload unique key
     * @return the workload information, or empty if not found or expired
     * @throws IllegalArgumentException if workloadUniqueKey is null or empty
     * @since 1.0
     */
    Optional<WorkloadInfo> findByWorkloadUniqueKey(String workloadUniqueKey);
}
