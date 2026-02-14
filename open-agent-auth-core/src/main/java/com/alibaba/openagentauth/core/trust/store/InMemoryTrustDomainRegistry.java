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

import com.alibaba.openagentauth.core.trust.model.TrustAnchor;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * In-memory implementation of TrustDomainRegistry.
 * <p>
 * This implementation stores trust domains and trust anchors in memory using thread-safe
 * data structures. It is suitable for development and testing environments, but should not
 * be used in production as data is lost when the application restarts.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently from multiple threads.
 * </p>
 *
 * @see TrustDomainRegistry
 * @since 1.0
 */
public class InMemoryTrustDomainRegistry implements TrustDomainRegistry {
    
    private static final Logger logger = LoggerFactory.getLogger(InMemoryTrustDomainRegistry.class);
    
    /**
     * Map of trust anchors, keyed by trust domain and key ID.
     */
    private final ConcurrentMap<String, TrustAnchor> trustAnchorMap = new ConcurrentHashMap<>();
    
    /**
     * Creates a new InMemoryTrustDomainRegistry.
     */
    public InMemoryTrustDomainRegistry() {
        logger.info("InMemoryTrustDomainRegistry initialized");
    }
    
    @Override
    public void registerTrustAnchor(TrustAnchor trustAnchor) {
        ValidationUtils.validateNotNull(trustAnchor, "Trust anchor");
        
        String key = buildKey(trustAnchor.getKeyId(), trustAnchor.getTrustDomain().getDomainId());
        trustAnchorMap.put(key, trustAnchor);
        logger.info("Registered trust anchor: keyId={}, domain={}", 
                trustAnchor.getKeyId(), trustAnchor.getTrustDomain().getDomainId());
    }
    
    @Override
    public Optional<TrustAnchor> getTrustAnchor(String keyId, TrustDomain trustDomain) {
        if (keyId == null || trustDomain == null) {
            return Optional.empty();
        }
        
        String key = buildKey(keyId, trustDomain.getDomainId());
        return Optional.ofNullable(trustAnchorMap.get(key));
    }
    
    @Override
    public List<TrustAnchor> getTrustAnchors(TrustDomain trustDomain) {
        if (trustDomain == null) {
            return Collections.emptyList();
        }
        
        return trustAnchorMap.values().stream()
                .filter(anchor -> anchor.getTrustDomain().equals(trustDomain))
                .collect(Collectors.toList());
    }
    
    @Override
    public void removeTrustAnchor(String keyId, TrustDomain trustDomain) {
        if (keyId == null || trustDomain == null) {
            return;
        }
        
        String key = buildKey(keyId, trustDomain.getDomainId());
        TrustAnchor removed = trustAnchorMap.remove(key);
        if (removed != null) {
            logger.info("Removed trust anchor: keyId={}, domain={}", keyId, trustDomain.getDomainId());
        }
    }
    
    @Override
    public boolean hasTrustAnchor(String keyId, TrustDomain trustDomain) {
        if (keyId == null || trustDomain == null) {
            return false;
        }
        
        String key = buildKey(keyId, trustDomain.getDomainId());
        return trustAnchorMap.containsKey(key);
    }
    
    @Override
    public List<TrustDomain> listTrustDomains() {
        return trustAnchorMap.values().stream()
                .map(TrustAnchor::getTrustDomain)
                .distinct()
                .collect(Collectors.toList());
    }
    
    @Override
    public void clear() {
        int size = trustAnchorMap.size();
        trustAnchorMap.clear();
        logger.info("Cleared all trust anchors: {} entries removed", size);
    }
    
    /**
     * Builds a composite key for the map.
     *
     * @param keyId the key ID
     * @param domainId the domain ID
     * @return the composite key
     */
    private String buildKey(String keyId, String domainId) {
        return domainId + ":" + keyId;
    }
}