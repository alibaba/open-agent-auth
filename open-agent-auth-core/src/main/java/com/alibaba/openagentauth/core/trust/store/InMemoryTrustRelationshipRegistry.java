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
package com.alibaba.openagentauth.core.trust.store;

import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.trust.model.TrustRelationship;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * In-memory implementation of TrustRelationshipRegistry.
 * <p>
 * This implementation stores trust relationships in memory using thread-safe
 * data structures. It is suitable for development and testing environments, but
 * should not be used in production as data is lost when the application restarts.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see TrustRelationshipRegistry
 * @since 1.0
 */
public class InMemoryTrustRelationshipRegistry implements TrustRelationshipRegistry {
    
    private static final Logger logger = LoggerFactory.getLogger(InMemoryTrustRelationshipRegistry.class);
    
    /**
     * Map of trust relationships, keyed by source and target domain.
     */
    private final ConcurrentMap<String, TrustRelationship> relationshipMap = new ConcurrentHashMap<>();
    
    /**
     * Creates a new InMemoryTrustRelationshipRegistry.
     */
    public InMemoryTrustRelationshipRegistry() {
        logger.info("InMemoryTrustRelationshipRegistry initialized");
    }
    
    @Override
    public TrustRelationship establishRelationship(TrustDomain sourceDomain, TrustDomain targetDomain) {
        ValidationUtils.validateNotNull(sourceDomain, "Source domain");
        ValidationUtils.validateNotNull(targetDomain, "Target domain");
        
        String key = buildKey(sourceDomain.getDomainId(), targetDomain.getDomainId());
        TrustRelationship relationship = new TrustRelationship(sourceDomain, targetDomain);
        relationshipMap.put(key, relationship);
        
        logger.info("Established trust relationship: source={}, target={}", 
                sourceDomain.getDomainId(), targetDomain.getDomainId());
        
        return relationship;
    }
    
    @Override
    public Optional<TrustRelationship> getRelationship(TrustDomain sourceDomain, TrustDomain targetDomain) {
        if (sourceDomain == null || targetDomain == null) {
            return Optional.empty();
        }
        
        String key = buildKey(sourceDomain.getDomainId(), targetDomain.getDomainId());
        return Optional.ofNullable(relationshipMap.get(key));
    }
    
    @Override
    public List<TrustRelationship> getRelationships(TrustDomain trustDomain) {
        if (trustDomain == null) {
            return Collections.emptyList();
        }
        
        String domainId = trustDomain.getDomainId();
        return relationshipMap.values().stream()
                .filter(rel -> rel.getSourceDomain().getDomainId().equals(domainId) ||
                           rel.getTargetDomain().getDomainId().equals(domainId))
                .collect(Collectors.toList());
    }
    
    @Override
    public void removeRelationship(TrustDomain sourceDomain, TrustDomain targetDomain) {
        if (sourceDomain == null || targetDomain == null) {
            return;
        }
        
        String key = buildKey(sourceDomain.getDomainId(), targetDomain.getDomainId());
        TrustRelationship removed = relationshipMap.remove(key);
        if (removed != null) {
            logger.info("Removed trust relationship: source={}, target={}", 
                    sourceDomain.getDomainId(), targetDomain.getDomainId());
        }
    }
    
    @Override
    public boolean hasActiveRelationship(TrustDomain sourceDomain, TrustDomain targetDomain) {
        if (sourceDomain == null || targetDomain == null) {
            return false;
        }
        
        String key = buildKey(sourceDomain.getDomainId(), targetDomain.getDomainId());
        TrustRelationship relationship = relationshipMap.get(key);
        return relationship != null && relationship.isActive();
    }
    
    @Override
    public List<TrustRelationship> listAllRelationships() {
        return new ArrayList<>(relationshipMap.values());
    }
    
    @Override
    public void clear() {
        int size = relationshipMap.size();
        relationshipMap.clear();
        logger.info("Cleared all trust relationships: {} entries removed", size);
    }
    
    /**
     * Builds a composite key for the map.
     *
     * @param sourceDomainId the source domain ID
     * @param targetDomainId the target domain ID
     * @return the composite key
     */
    private String buildKey(String sourceDomainId, String targetDomainId) {
        return sourceDomainId + "->" + targetDomainId;
    }
}