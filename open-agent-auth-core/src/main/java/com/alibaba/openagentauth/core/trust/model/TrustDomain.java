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

import com.alibaba.openagentauth.core.trust.store.TrustDomainRegistry;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.Objects;

/**
 * Represents a trust domain in the WIMSE protocol.
 * <p>
 * A trust domain is a logical boundary that defines a scope of trust for workload
 * identities. Each trust domain has its own trust anchor and can establish trust
 * relationships with other trust domains.
 * </p>
 * <p>
 * <b>Trust Domain Format:</b></p>
 * The trust domain identifier follows the format: {@code wimse://<domain>}
 * </p>
 * <p>
 * <b>Example:</b></p>
 * <pre>{@code
 * TrustDomain domain = new TrustDomain("wimse://example.com");
 * }</pre>
 * </p>
 *
 * @see TrustAnchor
 * @see TrustDomainRegistry
 * @since 1.0
 */
public class TrustDomain {
    
    /**
     * The trust domain identifier.
     */
    private final String domainId;
    
    /**
     * Creates a new TrustDomain.
     *
     * @param domainId the trust domain identifier (e.g., "wimse://example.com")
     * @throws IllegalArgumentException if domainId is null or empty
     */
    public TrustDomain(String domainId) {
        if (ValidationUtils.isNullOrEmpty(domainId)) {
            throw new IllegalArgumentException("Domain ID cannot be null or empty");
        }
        this.domainId = domainId;
    }
    
    /**
     * Gets the trust domain identifier.
     *
     * @return the domain ID
     */
    public String getDomainId() {
        return domainId;
    }
    
    /**
     * Gets the domain name (without the wimse:// prefix).
     *
     * @return the domain name
     */
    public String getDomainName() {
        if (domainId.startsWith("wimse://")) {
            return domainId.substring(8);
        }
        return domainId;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustDomain that = (TrustDomain) o;
        return Objects.equals(domainId, that.domainId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(domainId);
    }
    
    @Override
    public String toString() {
        return "TrustDomain{" +
                "domainId='" + domainId + '\'' +
                '}';
    }
}