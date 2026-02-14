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

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.trust.store.TrustDomainRegistry;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.security.PublicKey;
import java.util.Objects;

/**
 * Represents a trust anchor for a trust domain.
 * <p>
 * A trust anchor is a cryptographic key or certificate that serves as the root of trust
 * for a trust domain. It is used to verify signatures issued by identity providers within
 * that trust domain.
 * </p>
 * <p>
 * <b>Trust Anchor Properties:</b></p>
 * <ul>
 *   <li><b>Public Key:</b> The public key used for signature verification</li>
 *   <li><b>Key ID:</b> The unique identifier of the key</li>
 *   <li><b>Algorithm:</b> The cryptographic algorithm used by the key</li>
 *   <li><b>Trust Domain:</b> The trust domain this anchor belongs to</li>
 * </ul>
 * </p>
 *
 * @see TrustDomain
 * @see TrustDomainRegistry
 * @since 1.0
 */
public class TrustAnchor {
    
    /**
     * The public key.
     */
    private final PublicKey publicKey;
    
    /**
     * The key ID.
     */
    private final String keyId;
    
    /**
     * The key algorithm.
     */
    private final KeyAlgorithm algorithm;
    
    /**
     * The trust domain.
     */
    private final TrustDomain trustDomain;
    
    /**
     * Creates a new TrustAnchor.
     *
     * @param publicKey the public key
     * @param keyId the key ID
     * @param algorithm the key algorithm
     * @param trustDomain the trust domain
     * @throws IllegalArgumentException if any parameter is null
     */
    public TrustAnchor(PublicKey publicKey, String keyId, KeyAlgorithm algorithm, TrustDomain trustDomain) {
        this.publicKey = ValidationUtils.validateNotNull(publicKey, "Public key");
        this.keyId = ValidationUtils.validateNotEmpty(keyId, "Key ID");
        this.algorithm = ValidationUtils.validateNotNull(algorithm, "Algorithm");
        this.trustDomain = ValidationUtils.validateNotNull(trustDomain, "Trust domain");
    }
    
    /**
     * Gets the public key.
     *
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Gets the key ID.
     *
     * @return the key ID
     */
    public String getKeyId() {
        return keyId;
    }
    
    /**
     * Gets the key algorithm.
     *
     * @return the algorithm
     */
    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Gets the trust domain.
     *
     * @return the trust domain
     */
    public TrustDomain getTrustDomain() {
        return trustDomain;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TrustAnchor that = (TrustAnchor) o;
        return Objects.equals(keyId, that.keyId) &&
                Objects.equals(trustDomain, that.trustDomain);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(keyId, trustDomain);
    }
    
    @Override
    public String toString() {
        return "TrustAnchor{" +
                "keyId='" + keyId + '\'' +
                ", algorithm=" + algorithm +
                ", trustDomain=" + trustDomain +
                '}';
    }
}
