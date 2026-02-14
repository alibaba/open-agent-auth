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
package com.alibaba.openagentauth.core.trust.model;

import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a trust relationship between two trust domains.
 * <p>
 * A trust relationship allows workloads from one trust domain to be verified
 * by another trust domain. This enables cross-domain authentication and
 * authorization.
 * </p>
 * <p>
 * <b>Trust Relationship Properties:</b></p>
 * <ul>
 *   <li><b>Source Domain:</b> The trust domain that issues tokens</li>
 *   <li><b>Target Domain:</b> The trust domain that accepts tokens</li>
 *   <li><b>Established At:</b> When the relationship was established</li>
 *   <li><b>Active:</b> Whether the relationship is currently active</li>
 * </ul>
 * </p>
 *
 * @see TrustDomain
 * @since 1.0
 */
public class TrustRelationship {
    
    /**
     * The source trust domain (token issuer).
     */
    private final TrustDomain sourceDomain;
    
    /**
     * The target trust domain (token verifier).
     */
    private final TrustDomain targetDomain;
    
    /**
     * When the relationship was established.
     */
    private final Instant establishedAt;
    
    /**
     * Whether the relationship is active.
     */
    private boolean active;
    
    /**
     * Creates a new TrustRelationship.
     *
     * @param sourceDomain the source trust domain
     * @param targetDomain the target trust domain
     * @throws IllegalArgumentException if any parameter is null
     */
    public TrustRelationship(TrustDomain sourceDomain, TrustDomain targetDomain) {
        this.sourceDomain = ValidationUtils.validateNotNull(sourceDomain, "Source domain");
        this.targetDomain = ValidationUtils.validateNotNull(targetDomain, "Target domain");
        this.establishedAt = Instant.now();
        this.active = true;
    }
    
    /**
     * Gets the source trust domain.
     *
     * @return the source domain
     */
    public TrustDomain getSourceDomain() {
        return sourceDomain;
    }
    
    /**
     * Gets the target trust domain.
     *
     * @return the target domain
     */
    public TrustDomain getTargetDomain() {
        return targetDomain;
    }
    
    /**
     * Gets when the relationship was established.
     *
     * @return the establishment time
     */
    public Instant getEstablishedAt() {
        return establishedAt;
    }
    
    /**
     * Checks if the relationship is active.
     *
     * @return true if active, false otherwise
     */
    public boolean isActive() {
        return active;
    }
    
    /**
     * Sets whether the relationship is active.
     *
     * @param active true to activate, false to deactivate
     */
    public void setActive(boolean active) {
        this.active = active;
    }
    
    /**
     * Deactivates the trust relationship.
     */
    public void deactivate() {
        this.active = false;
    }
    
    /**
     * Activates the trust relationship.
     */
    public void activate() {
        this.active = true;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustRelationship that = (TrustRelationship) o;
        return Objects.equals(sourceDomain, that.sourceDomain) &&
                Objects.equals(targetDomain, that.targetDomain);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(sourceDomain, targetDomain);
    }
    
    @Override
    public String toString() {
        return "TrustRelationship{" +
                "sourceDomain=" + sourceDomain +
                ", targetDomain=" + targetDomain +
                ", establishedAt=" + establishedAt +
                ", active=" + active +
                '}';
    }
}
