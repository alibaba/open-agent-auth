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
package com.alibaba.openagentauth.core.crypto.key.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents metadata information about a cryptographic key.
 * <p>
 * This class encapsulates all metadata associated with a key, including its identifier,
 * algorithm, creation time, activation status, and rotation information. This metadata
 * is used for key lifecycle management and auditing purposes.
 * </p>
 * <p>
 * <b>Immutable Design:</b></p>
 * This class is immutable to ensure thread safety and prevent accidental modifications.
 * Use the {@link Builder} to create new instances.
 * </p>
 *
 * @since 1.0
 */
public class KeyInfo {
    
    /**
     * The unique identifier for this key.
     */
    private final String keyId;
    
    /**
     * The cryptographic algorithm used for this key.
     */
    private final KeyAlgorithm algorithm;
    
    /**
     * The timestamp when this key was created.
     */
    private final Instant createdAt;
    
    /**
     * The timestamp when this key was activated.
     */
    private final Instant activatedAt;
    
    /**
     * The timestamp when this key was rotated (if applicable).
     */
    private final Instant rotatedAt;
    
    /**
     * The timestamp when this key expires.
     */
    private final Instant expiresAt;
    
    /**
     * Whether this key is currently active.
     */
    private final boolean active;
    
    /**
     * The key ID of the previous key if this is a rotated key.
     */
    private final String previousKeyId;
    
    /**
     * Creates a new KeyInfo.
     *
     * @param keyId the key identifier
     * @param algorithm the cryptographic algorithm
     * @param createdAt the creation timestamp
     * @param activatedAt the activation timestamp
     * @param rotatedAt the rotation timestamp
     * @param expiresAt the expiration timestamp
     * @param active whether the key is active
     * @param previousKeyId the previous key ID (if rotated)
     */
    private KeyInfo(String keyId, KeyAlgorithm algorithm, Instant createdAt, Instant activatedAt,
                   Instant rotatedAt, Instant expiresAt, boolean active, String previousKeyId) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.createdAt = createdAt;
        this.activatedAt = activatedAt;
        this.rotatedAt = rotatedAt;
        this.expiresAt = expiresAt;
        this.active = active;
        this.previousKeyId = previousKeyId;
    }
    
    /**
     * Gets the key identifier.
     *
     * @return the key ID
     */
    public String getKeyId() {
        return keyId;
    }
    
    /**
     * Gets the cryptographic algorithm.
     *
     * @return the algorithm
     */
    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Gets the creation timestamp.
     *
     * @return the creation timestamp
     */
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    /**
     * Gets the activation timestamp.
     *
     * @return the activation timestamp
     */
    public Instant getActivatedAt() {
        return activatedAt;
    }
    
    /**
     * Gets the rotation timestamp.
     *
     * @return the rotation timestamp, or null if never rotated
     */
    public Instant getRotatedAt() {
        return rotatedAt;
    }
    
    /**
     * Gets the expiration timestamp.
     *
     * @return the expiration timestamp, or null if never expires
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }
    
    /**
     * Checks if the key is active.
     *
     * @return true if active, false otherwise
     */
    public boolean isActive() {
        return active;
    }
    
    /**
     * Gets the previous key ID.
     *
     * @return the previous key ID, or null if not a rotated key
     */
    public String getPreviousKeyId() {
        return previousKeyId;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyInfo keyInfo = (KeyInfo) o;
        return active == keyInfo.active && 
               Objects.equals(keyId, keyInfo.keyId) && 
               algorithm == keyInfo.algorithm && 
               Objects.equals(createdAt, keyInfo.createdAt) && 
               Objects.equals(activatedAt, keyInfo.activatedAt) && 
               Objects.equals(rotatedAt, keyInfo.rotatedAt) && 
               Objects.equals(expiresAt, keyInfo.expiresAt) && 
               Objects.equals(previousKeyId, keyInfo.previousKeyId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(keyId, algorithm, createdAt, activatedAt, rotatedAt, expiresAt, active, previousKeyId);
    }
    
    @Override
    public String toString() {
        return "KeyInfo{" +
                "keyId='" + keyId + '\'' +
                ", algorithm=" + algorithm +
                ", createdAt=" + createdAt +
                ", activatedAt=" + activatedAt +
                ", rotatedAt=" + rotatedAt +
                ", expiresAt=" + expiresAt +
                ", active=" + active +
                ", previousKeyId='" + previousKeyId + '\'' +
                '}';
    }
    
    /**
     * Creates a new builder for KeyInfo.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for KeyInfo.
     */
    public static class Builder {
        
        private String keyId;
        private KeyAlgorithm algorithm;
        private Instant createdAt;
        private Instant activatedAt;
        private Instant rotatedAt;
        private Instant expiresAt;
        private boolean active;
        private String previousKeyId;
        
        /**
         * Sets the key identifier.
         *
         * @param keyId the key ID
         * @return this builder
         */
        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }
        
        /**
         * Sets the cryptographic algorithm.
         *
         * @param algorithm the algorithm
         * @return this builder
         */
        public Builder algorithm(KeyAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }
        
        /**
         * Sets the creation timestamp.
         *
         * @param createdAt the creation timestamp
         * @return this builder
         */
        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }
        
        /**
         * Sets the activation timestamp.
         *
         * @param activatedAt the activation timestamp
         * @return this builder
         */
        public Builder activatedAt(Instant activatedAt) {
            this.activatedAt = activatedAt;
            return this;
        }
        
        /**
         * Sets the rotation timestamp.
         *
         * @param rotatedAt the rotation timestamp
         * @return this builder
         */
        public Builder rotatedAt(Instant rotatedAt) {
            this.rotatedAt = rotatedAt;
            return this;
        }
        
        /**
         * Sets the expiration timestamp.
         *
         * @param expiresAt the expiration timestamp
         * @return this builder
         */
        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }
        
        /**
         * Sets whether the key is active.
         *
         * @param active true if active, false otherwise
         * @return this builder
         */
        public Builder active(boolean active) {
            this.active = active;
            return this;
        }
        
        /**
         * Sets the previous key ID.
         *
         * @param previousKeyId the previous key ID
         * @return this builder
         */
        public Builder previousKeyId(String previousKeyId) {
            this.previousKeyId = previousKeyId;
            return this;
        }
        
        /**
         * Builds the KeyInfo instance.
         *
         * @return the KeyInfo instance
         */
        public KeyInfo build() {
            return new KeyInfo(keyId, algorithm, createdAt, activatedAt, rotatedAt, expiresAt, active, previousKeyId);
        }
    }
}
