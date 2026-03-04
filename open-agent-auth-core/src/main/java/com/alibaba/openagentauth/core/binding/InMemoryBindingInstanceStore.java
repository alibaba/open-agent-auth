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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of {@link BindingInstanceStore}.
 * <p>
 * This implementation stores binding instances in memory using concurrent hash maps.
 * It is suitable for testing and development environments.
 * For production use, consider using a persistent storage implementation.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and uses ConcurrentHashMap for storage.
 * </p>
 *
 * @since 1.0
 */
public class InMemoryBindingInstanceStore implements BindingInstanceStore {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryBindingInstanceStore.class);

    /**
     * Map of binding instance ID to BindingInstance.
     */
    private final Map<String, BindingInstance> bindings;

    /**
     * Map of user identity to binding instance ID.
     */
    private final Map<String, String> userIdentityToBindingId;

    /**
     * Map of workload identity to binding instance ID.
     */
    private final Map<String, String> workloadIdentityToBindingId;

    /**
     * Creates a new InMemoryBindingInstanceStore.
     */
    public InMemoryBindingInstanceStore() {
        this.bindings = new ConcurrentHashMap<>();
        this.userIdentityToBindingId = new ConcurrentHashMap<>();
        this.workloadIdentityToBindingId = new ConcurrentHashMap<>();
        
        logger.info("InMemoryBindingInstanceStore initialized");
    }

    @Override
    public void store(BindingInstance bindingInstance) {
        if (bindingInstance == null) {
            logger.warn("Attempted to store null binding instance");
            return;
        }
        
        logger.debug("Storing binding instance: {}", bindingInstance.getBindingInstanceId());
        
        bindings.put(bindingInstance.getBindingInstanceId(), bindingInstance);
        userIdentityToBindingId.put(bindingInstance.getUserIdentity(), bindingInstance.getBindingInstanceId());
        workloadIdentityToBindingId.put(bindingInstance.getWorkloadIdentity(), bindingInstance.getBindingInstanceId());
    }

    @Override
    public BindingInstance retrieve(String bindingInstanceId) {
        if (bindingInstanceId == null) {
            return null;
        }
        
        logger.debug("Retrieving binding instance: {}", bindingInstanceId);
        return bindings.get(bindingInstanceId);
    }

    @Override
    public BindingInstance retrieveByUserIdentity(String userIdentity) {
        if (userIdentity == null) {
            return null;
        }
        
        logger.debug("Retrieving binding instance by user identity: {}", userIdentity);
        String bindingInstanceId = userIdentityToBindingId.get(userIdentity);
        return bindingInstanceId != null ? bindings.get(bindingInstanceId) : null;
    }

    @Override
    public BindingInstance retrieveByWorkloadIdentity(String workloadIdentity) {
        if (workloadIdentity == null) {
            return null;
        }
        
        logger.debug("Retrieving binding instance by workload identity: {}", workloadIdentity);
        String bindingInstanceId = workloadIdentityToBindingId.get(workloadIdentity);
        return bindingInstanceId != null ? bindings.get(bindingInstanceId) : null;
    }

    @Override
    public void update(BindingInstance bindingInstance) {
        if (bindingInstance == null) {
            logger.warn("Attempted to update null binding instance");
            return;
        }
        
        String bindingInstanceId = bindingInstance.getBindingInstanceId();
        if (!bindings.containsKey(bindingInstanceId)) {
            logger.warn("Attempted to update non-existent binding: {}", bindingInstanceId);
            return;
        }
        
        logger.debug("Updating binding instance: {}", bindingInstanceId);
        bindings.put(bindingInstanceId, bindingInstance);
    }

    @Override
    public void delete(String bindingInstanceId) {
        if (bindingInstanceId == null) {
            return;
        }
        
        logger.debug("Deleting binding instance: {}", bindingInstanceId);
        
        BindingInstance binding = bindings.remove(bindingInstanceId);
        if (binding != null) {
            userIdentityToBindingId.remove(binding.getUserIdentity());
            workloadIdentityToBindingId.remove(binding.getWorkloadIdentity());
        }
    }

    @Override
    public boolean exists(String bindingInstanceId) {
        if (bindingInstanceId == null) {
            return false;
        }
        return bindings.containsKey(bindingInstanceId);
    }

    @Override
    public boolean isValid(String bindingInstanceId) {
        if (bindingInstanceId == null) {
            return false;
        }
        
        BindingInstance binding = bindings.get(bindingInstanceId);
        return binding != null && binding.isValid();
    }

    @Override
    public int deleteExpired() {
        logger.info("Deleting expired binding instances");
        
        int deletedCount = 0;
        Instant now = Instant.now();
        
        for (Map.Entry<String, BindingInstance> entry : bindings.entrySet()) {
            BindingInstance binding = entry.getValue();
            if (binding.isExpired()) {
                delete(entry.getKey());
                deletedCount++;
            }
        }
        
        logger.info("Deleted {} expired binding instances", deletedCount);
        return deletedCount;
    }

    /**
     * Clears all stored binding instances.
     * <p>
     * This method is primarily intended for testing purposes.
     * </p>
     */
    public void clear() {
        logger.info("Clearing all binding instances");
        bindings.clear();
        userIdentityToBindingId.clear();
        workloadIdentityToBindingId.clear();
    }

    /**
     * Gets the number of stored binding instances.
     *
     * @return the number of stored bindings
     */
    public int size() {
        return bindings.size();
    }

    @Override
    public List<BindingInstance> listAll() {
        logger.debug("Listing all binding instances, total count: {}", bindings.size());
        return new ArrayList<>(bindings.values());
    }
}
