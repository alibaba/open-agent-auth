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

import java.util.List;
import java.util.Optional;

/**
 * Registry for managing trust domains and their trust anchors.
 * <p>
 * This interface provides methods for registering, retrieving, and managing trust domains
 * and their associated trust anchors. It serves as the central repository for trust
 * relationships in the system.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations of this interface should be thread-safe and can be used
 * concurrently from multiple threads.
 * </p>
 *
 * @see TrustDomain
 * @see TrustAnchor
 * @since 1.0
 */
public interface TrustDomainRegistry {
    
    /**
     * Registers a trust anchor for a trust domain.
     *
     * @param trustAnchor the trust anchor to register
     */
    void registerTrustAnchor(TrustAnchor trustAnchor);
    
    /**
     * Retrieves a trust anchor by key ID and trust domain.
     *
     * @param keyId the key ID
     * @param trustDomain the trust domain
     * @return the trust anchor, or empty if not found
     */
    Optional<TrustAnchor> getTrustAnchor(String keyId, TrustDomain trustDomain);
    
    /**
     * Retrieves all trust anchors for a trust domain.
     *
     * @param trustDomain the trust domain
     * @return list of trust anchors
     */
    List<TrustAnchor> getTrustAnchors(TrustDomain trustDomain);
    
    /**
     * Removes a trust anchor.
     *
     * @param keyId the key ID
     * @param trustDomain the trust domain
     */
    void removeTrustAnchor(String keyId, TrustDomain trustDomain);
    
    /**
     * Checks if a trust anchor exists.
     *
     * @param keyId the key ID
     * @param trustDomain the trust domain
     * @return true if the trust anchor exists, false otherwise
     */
    boolean hasTrustAnchor(String keyId, TrustDomain trustDomain);
    
    /**
     * Lists all registered trust domains.
     *
     * @return list of trust domains
     */
    List<TrustDomain> listTrustDomains();
    
    /**
     * Clears all registered trust anchors.
     */
    void clear();
}
