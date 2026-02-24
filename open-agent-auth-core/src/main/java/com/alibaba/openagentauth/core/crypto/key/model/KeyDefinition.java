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

import java.util.Objects;

/**
 * Immutable value object representing a key definition that describes how a key
 * should be resolved and managed.
 * <p>
 * A {@code KeyDefinition} captures the metadata needed to locate and resolve a
 * cryptographic key from various sources. It decouples the key's identity from
 * its storage mechanism, enabling the {@link com.alibaba.openagentauth.core.crypto.key.resolve.KeyResolver}
 * SPI to determine the appropriate resolution strategy at runtime.
 * </p>
 *
 * <p><b>Resolution Strategy:</b></p>
 * <ul>
 *   <li>If {@code jwksConsumer} is set, the key is resolved from a remote JWKS endpoint
 *       identified by the consumer name.</li>
 *   <li>If {@code provider} is set (and {@code jwksConsumer} is null), the key is resolved
 *       from a local key store (e.g., in-memory, file-based).</li>
 *   <li>Custom {@code KeyResolver} implementations can introduce additional resolution
 *       strategies (e.g., HashiCorp Vault, AWS KMS).</li>
 * </ul>
 *
 * <p><b>Usage Example:</b></p>
 * <pre>{@code
 * // Local key definition
 * KeyDefinition localKey = KeyDefinition.builder()
 *     .keyId("aoat-signing-key")
 *     .algorithm(KeyAlgorithm.RS256)
 *     .provider("local")
 *     .build();
 *
 * // Remote JWKS key definition
 * KeyDefinition remoteKey = KeyDefinition.builder()
 *     .keyId("wit-signing-key")
 *     .algorithm(KeyAlgorithm.ES256)
 *     .jwksConsumer("agent-idp")
 *     .build();
 * }</pre>
 *
 * @see KeyAlgorithm
 * @see com.alibaba.openagentauth.core.crypto.key.resolve.KeyResolver
 * @since 1.0
 */
public final class KeyDefinition {

    private final String keyId;
    private final KeyAlgorithm algorithm;
    private final String provider;
    private final String jwksConsumer;

    private KeyDefinition(String keyId, KeyAlgorithm algorithm, String provider, String jwksConsumer) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.provider = provider;
        this.jwksConsumer = jwksConsumer;
    }

    /**
     * Gets the unique key identifier (kid) used in JWT and JWKS.
     *
     * @return the key ID
     */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Gets the cryptographic algorithm for this key.
     *
     * @return the key algorithm
     */
    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the key provider name (e.g., "local", "file").
     * <p>
     * When set, the key is resolved from a local key store managed by the provider.
     * </p>
     *
     * @return the provider name, or {@code null} if the key is resolved via JWKS consumer
     */
    public String getProvider() {
        return provider;
    }

    /**
     * Gets the JWKS consumer name for remote key resolution.
     * <p>
     * When set, the key is resolved from a remote JWKS endpoint identified by
     * this consumer name. The consumer name maps to a configured JWKS consumer
     * in the infrastructure properties.
     * </p>
     *
     * @return the JWKS consumer name, or {@code null} if the key is resolved locally
     */
    public String getJwksConsumer() {
        return jwksConsumer;
    }

    /**
     * Checks whether this key definition requires remote JWKS resolution.
     *
     * @return {@code true} if the key should be resolved from a remote JWKS endpoint
     */
    public boolean isRemoteKey() {
        return jwksConsumer != null && !jwksConsumer.isBlank();
    }

    /**
     * Checks whether this key definition uses local key store resolution.
     *
     * @return {@code true} if the key should be resolved from a local key store
     */
    public boolean isLocalKey() {
        return !isRemoteKey();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyDefinition that = (KeyDefinition) o;
        return Objects.equals(keyId, that.keyId) &&
                algorithm == that.algorithm &&
                Objects.equals(provider, that.provider) &&
                Objects.equals(jwksConsumer, that.jwksConsumer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, algorithm, provider, jwksConsumer);
    }

    @Override
    public String toString() {
        return "KeyDefinition{" +
                "keyId='" + keyId + '\'' +
                ", algorithm=" + algorithm +
                ", provider='" + provider + '\'' +
                ", jwksConsumer='" + jwksConsumer + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@code KeyDefinition}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing {@link KeyDefinition} instances.
     */
    public static final class Builder {

        private String keyId;
        private KeyAlgorithm algorithm;
        private String provider;
        private String jwksConsumer;

        private Builder() {
        }

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
         * @param algorithm the key algorithm
         * @return this builder
         */
        public Builder algorithm(KeyAlgorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        /**
         * Sets the key provider name.
         *
         * @param provider the provider name
         * @return this builder
         */
        public Builder provider(String provider) {
            this.provider = provider;
            return this;
        }

        /**
         * Sets the JWKS consumer name for remote key resolution.
         *
         * @param jwksConsumer the JWKS consumer name
         * @return this builder
         */
        public Builder jwksConsumer(String jwksConsumer) {
            this.jwksConsumer = jwksConsumer;
            return this;
        }

        /**
         * Builds the {@code KeyDefinition} instance.
         *
         * @return the constructed key definition
         * @throws IllegalArgumentException if keyId is null or empty
         */
        public KeyDefinition build() {
            if (keyId == null || keyId.isBlank()) {
                throw new IllegalArgumentException("KeyDefinition keyId cannot be null or empty");
            }
            return new KeyDefinition(keyId, algorithm, provider, jwksConsumer);
        }
    }
}
