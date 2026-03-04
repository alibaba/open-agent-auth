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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of WorkloadStore.
 * <p>
 * This implementation stores workload information in a concurrent hash map.
 * It is suitable for development and testing purposes. For production,
 * consider implementing a custom {@link WorkloadRegistry} with persistent storage.
 * </p>
 * <p>
 * <b>Thread Safety:</b> This implementation is thread-safe and can be used
 * in concurrent environments. It uses ConcurrentHashMap for storage and
 * provides atomic operations for workload lifecycle management.
 * </p>
 * <p>
 * <b>Expiration Handling:</b> Expired workloads are automatically filtered out
 * during retrieval operations. Periodic cleanup can be triggered using
 * {@link #cleanupExpiredWorkloads()} to free memory.
 * </p>
 *
 * @see WorkloadRegistry
 * @since 1.0
 */
public class InMemoryWorkloadRegistry implements WorkloadRegistry {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryWorkloadRegistry.class);

    /**
     * Concurrent map for storing workload information.
     * <p>
     * Key: workload ID
     * Value: WorkloadInfo
     * </p>
     */
    private final Map<String, WorkloadInfo> store = new ConcurrentHashMap<>();

    /**
     * Index map for fast lookup by workload unique key.
     * <p>
     * Key: workload unique key (e.g., "userId:clientId")
     * Value: workload ID
     * </p>
     * <p>
     * This index provides O(1) lookup performance for findByWorkloadUniqueKey
     * instead of O(n) iteration through all workloads.
     * </p>
     */
    private final Map<String, String> uniqueKeyIndex = new ConcurrentHashMap<>();

    @Override
    public void save(WorkloadInfo workloadInfo) {
        ValidationUtils.validateNotNull(workloadInfo, "WorkloadInfo");
        if (ValidationUtils.isNullOrEmpty(workloadInfo.getWorkloadId())) {
            throw new IllegalArgumentException("Workload ID cannot be null or empty");
        }
        
        String workloadId = workloadInfo.getWorkloadId();
        
        // Save to main store
        store.put(workloadId, workloadInfo);
        
        // Update index if workloadUniqueKey exists in metadata
        Map<String, Object> metadata = workloadInfo.getMetadata();
        if (metadata != null && metadata.containsKey("workloadUniqueKey")) {
            String workloadUniqueKey = (String) metadata.get("workloadUniqueKey");
            uniqueKeyIndex.put(workloadUniqueKey, workloadId);
        }
        
        logger.debug("Saved workload: {}", workloadId);
    }

    @Override
    public Optional<WorkloadInfo> findById(String workloadId) {
        if (ValidationUtils.isNullOrEmpty(workloadId)) {
            throw new IllegalArgumentException("Workload ID cannot be null or empty");
        }
        
        WorkloadInfo workloadInfo = store.get(workloadId);
        
        if (workloadInfo == null) {
            return Optional.empty();
        }
        
        // Check if workload is expired
        if (workloadInfo.isExpired()) {
            logger.debug("Workload is expired: {}", workloadId);
            return Optional.empty();
        }
        
        return Optional.of(workloadInfo);
    }

    @Override
    public void delete(String workloadId) {
        if (ValidationUtils.isNullOrEmpty(workloadId)) {
            throw new IllegalArgumentException("Workload ID cannot be null or empty");
        }
        
        // Get workload before removal to clean up index
        WorkloadInfo removed = store.remove(workloadId);
        
        // Clean up index if workload had a unique key
        if (removed != null) {
            Map<String, Object> metadata = removed.getMetadata();
            if (metadata != null && metadata.containsKey("workloadUniqueKey")) {
                String workloadUniqueKey = (String) metadata.get("workloadUniqueKey");
                uniqueKeyIndex.remove(workloadUniqueKey);
            }
        }
        
        logger.debug("Deleted workload: {}", workloadId);
    }

    @Override
    public boolean exists(String workloadId) {
        if (ValidationUtils.isNullOrEmpty(workloadId)) {
            throw new IllegalArgumentException("Workload ID cannot be null or empty");
        }
        
        return findById(workloadId).isPresent();
    }

    @Override
    public Optional<WorkloadInfo> findByWorkloadUniqueKey(String workloadUniqueKey) {
        if (ValidationUtils.isNullOrEmpty(workloadUniqueKey)) {
            throw new IllegalArgumentException("Workload unique key cannot be null or empty");
        }
        
        // Get workloadId from index (O(1) lookup)
        String workloadId = uniqueKeyIndex.get(workloadUniqueKey);
        
        if (workloadId == null) {
            logger.debug("No workload found for unique key: {}", workloadUniqueKey);
            return Optional.empty();
        }
        
        // Get WorkloadInfo from main store
        WorkloadInfo workloadInfo = store.get(workloadId);
        
        if (workloadInfo == null) {
            // Index and store are inconsistent, clean up index
            uniqueKeyIndex.remove(workloadUniqueKey);
            logger.debug("Workload not found in store, cleaned up stale index for: {}", workloadUniqueKey);
            return Optional.empty();
        }
        
        // Check if workload is expired
        if (workloadInfo.isExpired()) {
            // Expired, clean up both index and store
            uniqueKeyIndex.remove(workloadUniqueKey);
            store.remove(workloadId);
            logger.debug("Workload is expired: {}, cleaned up index and store", workloadId);
            return Optional.empty();
        }
        
        logger.debug("Found workload by unique key: {} -> {}", workloadUniqueKey, workloadId);
        return Optional.of(workloadInfo);
    }

    /**
     * Cleans up expired workloads.
     * <p>
     * This method should be called periodically to remove expired workloads
     * from memory and prevent memory leaks. It iterates through all stored
     * workloads and removes those that have expired, including their index entries.
     * </p>
     * <p>
     * <b>Recommended Usage:</b></p>
     * <pre>
     * // Schedule periodic cleanup (e.g., every 5 minutes)
     * ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
     * scheduler.scheduleAtFixedRate(() -> workloadRegistry.cleanupExpiredWorkloads(),
     *                               5, 5, TimeUnit.MINUTES);
     * </pre>
     *
     * @return the number of workloads cleaned up
     */
    public int cleanupExpiredWorkloads() {
        Instant now = Instant.now();
        int count = 0;
        
        for (Map.Entry<String, WorkloadInfo> entry : store.entrySet()) {
            if (entry.getValue().getExpiresAt().isBefore(now)) {
                String workloadId = entry.getKey();
                
                // Clean up index if workload had a unique key
                Map<String, Object> metadata = entry.getValue().getMetadata();
                if (metadata != null && metadata.containsKey("workloadUniqueKey")) {
                    String workloadUniqueKey = (String) metadata.get("workloadUniqueKey");
                    uniqueKeyIndex.remove(workloadUniqueKey);
                }
                
                // Remove from main store
                store.remove(workloadId);
                count++;
            }
        }
        
        if (count > 0) {
            logger.info("Cleaned up {} expired workloads", count);
        }
        
        return count;
    }

    /**
     * Gets the number of active (non-expired) workloads in the store.
     * <p>
     * This method is useful for monitoring and debugging purposes.
     * </p>
     *
     * @return the count of active workloads
     */
    public int getActiveWorkloadCount() {
        Instant now = Instant.now();
        int count = 0;
        
        for (WorkloadInfo workload : store.values()) {
            if (!workload.getExpiresAt().isBefore(now)) {
                count++;
            }
        }
        
        return count;
    }

    @Override
    public void revoke(String workloadId) {
        if (ValidationUtils.isNullOrEmpty(workloadId)) {
            throw new IllegalArgumentException("Workload ID cannot be null or empty");
        }

        WorkloadInfo existing = store.get(workloadId);
        if (existing == null) {
            logger.warn("Workload not found for revocation: {}", workloadId);
            return;
        }

        // Create a new WorkloadInfo with "revoked" status (WorkloadInfo is immutable)
        WorkloadInfo revokedWorkload = new WorkloadInfo(
                existing.getWorkloadId(),
                existing.getUserId(),
                existing.getTrustDomain(),
                existing.getIssuer(),
                existing.getPublicKey(),
                null,
                existing.getCreatedAt(),
                existing.getExpiresAt(),
                "revoked",
                existing.getContext(),
                existing.getMetadata()
        );

        store.put(workloadId, revokedWorkload);
        logger.debug("Revoked workload: {}", workloadId);
    }

    @Override
    public List<WorkloadInfo> listAll() {
        List<WorkloadInfo> allWorkloads = new ArrayList<>(store.values());
        logger.debug("Listed {} workloads (total in store)", allWorkloads.size());
        return allWorkloads;
    }
}