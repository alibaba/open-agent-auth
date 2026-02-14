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

import java.util.List;
import java.util.Optional;

/**
 * Registry for managing trust relationships between trust domains.
 * <p>
 * This interface provides methods for establishing, retrieving, and managing trust
 * relationships between trust domains. It enables cross-domain authentication and
 * authorization.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations of this interface should be thread-safe and can be used
 * concurrently from multiple threads.
 * </p>
 *
 * @see TrustRelationship
 * @see TrustDomain
 * @since 1.0
 */
public interface TrustRelationshipRegistry {
    
    /**
     * Establishes a trust relationship between two trust domains.
     *
     * @param sourceDomain the source trust domain
     * @param targetDomain the target trust domain
     * @return the created trust relationship
     */
    TrustRelationship establishRelationship(TrustDomain sourceDomain, TrustDomain targetDomain);
    
    /**
     * Retrieves a trust relationship.
     *
     * @param sourceDomain the source trust domain
     * @param targetDomain the target trust domain
     * @return the trust relationship, or empty if not found
     */
    Optional<TrustRelationship> getRelationship(TrustDomain sourceDomain, TrustDomain targetDomain);
    
    /**
     * Retrieves all trust relationships for a trust domain.
     *
     * @param trustDomain the trust domain
     * @return list of trust relationships
     */
    List<TrustRelationship> getRelationships(TrustDomain trustDomain);
    
    /**
     * Removes a trust relationship.
     *
     * @param sourceDomain the source trust domain
     * @param targetDomain the target trust domain
     */
    void removeRelationship(TrustDomain sourceDomain, TrustDomain targetDomain);
    
    /**
     * Checks if a trust relationship exists and is active.
     *
     * @param sourceDomain the source trust domain
     * @param targetDomain the target trust domain
     * @return true if the relationship exists and is active, false otherwise
     */
    boolean hasActiveRelationship(TrustDomain sourceDomain, TrustDomain targetDomain);
    
    /**
     * Lists all trust relationships.
     *
     * @return list of all trust relationships
     */
    List<TrustRelationship> listAllRelationships();
    
    /**
     * Clears all trust relationships.
     */
    void clear();
}
