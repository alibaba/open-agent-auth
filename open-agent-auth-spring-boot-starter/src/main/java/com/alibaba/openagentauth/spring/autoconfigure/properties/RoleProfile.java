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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable role profile that defines the default configuration for a specific role.
 * <p>
 * Each role in the Open Agent Auth framework has a well-defined set of requirements:
 * signing keys, verification keys, required peers, and required capabilities.
 * A {@code RoleProfile} captures these requirements as an immutable value object,
 * enabling the framework to automatically infer and configure the necessary
 * infrastructure when a role is enabled.
 * </p>
 * <p>
 * This follows the "Convention over Configuration" principle — developers only need
 * to declare which role they want to enable and which peers they connect to; the
 * framework handles the rest.
 * </p>
 *
 * @since 2.1
 */
public final class RoleProfile {

    private final List<String> signingKeys;
    private final List<String> verificationKeys;
    private final List<String> encryptionKeys;
    private final List<String> decryptionKeys;
    private final List<String> requiredPeers;
    private final List<String> requiredCapabilities;
    private final boolean jwksProviderEnabled;
    private final Map<String, String> keyDefaultAlgorithms;
    private final Map<String, String> keyToPeerMapping;

    private RoleProfile(Builder builder) {
        this.signingKeys = Collections.unmodifiableList(builder.signingKeys);
        this.verificationKeys = Collections.unmodifiableList(builder.verificationKeys);
        this.encryptionKeys = Collections.unmodifiableList(builder.encryptionKeys);
        this.decryptionKeys = Collections.unmodifiableList(builder.decryptionKeys);
        this.requiredPeers = Collections.unmodifiableList(builder.requiredPeers);
        this.requiredCapabilities = Collections.unmodifiableList(builder.requiredCapabilities);
        this.jwksProviderEnabled = builder.jwksProviderEnabled;
        this.keyDefaultAlgorithms = Collections.unmodifiableMap(builder.keyDefaultAlgorithms);
        this.keyToPeerMapping = Collections.unmodifiableMap(builder.keyToPeerMapping);
    }

    /**
     * Returns the key names that this role needs to sign tokens with (local private keys).
     *
     * @return unmodifiable list of signing key names
     */
    public List<String> getSigningKeys() {
        return signingKeys;
    }

    /**
     * Returns the key names that this role needs to verify tokens with (remote public keys).
     *
     * @return unmodifiable list of verification key names
     */
    public List<String> getVerificationKeys() {
        return verificationKeys;
    }

    /**
     * Returns the key names that this role needs to encrypt data with (remote public keys).
     *
     * @return unmodifiable list of encryption key names
     */
    public List<String> getEncryptionKeys() {
        return encryptionKeys;
    }

    /**
     * Returns the key names that this role needs to decrypt data with (local private keys).
     *
     * @return unmodifiable list of decryption key names
     */
    public List<String> getDecryptionKeys() {
        return decryptionKeys;
    }

    /**
     * Returns the peer service names that this role depends on.
     *
     * @return unmodifiable list of required peer names
     */
    public List<String> getRequiredPeers() {
        return requiredPeers;
    }

    /**
     * Returns the capability names that this role requires.
     *
     * @return unmodifiable list of required capability names
     */
    public List<String> getRequiredCapabilities() {
        return requiredCapabilities;
    }

    /**
     * Returns whether this role should expose a JWKS provider endpoint.
     *
     * @return true if the JWKS provider should be enabled
     */
    public boolean isJwksProviderEnabled() {
        return jwksProviderEnabled;
    }

    /**
     * Gets the default algorithm for a given key name.
     *
     * @param keyName the key name (e.g., "wit-signing")
     * @return the default algorithm (e.g., "ES256"), or null if not defined
     */
    public String getDefaultAlgorithm(String keyName) {
        return keyDefaultAlgorithms.get(keyName);
    }

    /**
     * Gets the peer that provides the public key for a given verification/encryption key.
     *
     * @param keyName the key name (e.g., "wit-verification")
     * @return the peer name (e.g., "agent-idp"), or null if the key is local
     */
    public String getPeerForKey(String keyName) {
        return keyToPeerMapping.get(keyName);
    }

    /**
     * Gets all key names that require a specific peer.
     *
     * @return unmodifiable map of key name to peer name
     */
    public Map<String, String> getKeyToPeerMapping() {
        return keyToPeerMapping;
    }

    /**
     * Creates a new builder for constructing a {@code RoleProfile}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing immutable {@link RoleProfile} instances.
     * <p>
     * All collection fields default to empty immutable collections.
     * The built profile wraps all collections in unmodifiable views.
     * </p>
     */
    public static final class Builder {
        private List<String> signingKeys = List.of();
        private List<String> verificationKeys = List.of();
        private List<String> encryptionKeys = List.of();
        private List<String> decryptionKeys = List.of();
        private List<String> requiredPeers = List.of();
        private List<String> requiredCapabilities = List.of();
        private boolean jwksProviderEnabled = true;
        private Map<String, String> keyDefaultAlgorithms = Map.of();
        private Map<String, String> keyToPeerMapping = Map.of();

        private Builder() {
        }

        /** Sets the signing key names for this role. */
        public Builder signingKeys(String... keys) {
            this.signingKeys = List.of(keys);
            return this;
        }

        /** Sets the verification key names for this role. */
        public Builder verificationKeys(String... keys) {
            this.verificationKeys = List.of(keys);
            return this;
        }

        /** Sets the encryption key names for this role. */
        public Builder encryptionKeys(String... keys) {
            this.encryptionKeys = List.of(keys);
            return this;
        }

        /** Sets the decryption key names for this role. */
        public Builder decryptionKeys(String... keys) {
            this.decryptionKeys = List.of(keys);
            return this;
        }

        /** Sets the required peer service names for this role. */
        public Builder requiredPeers(String... peers) {
            this.requiredPeers = List.of(peers);
            return this;
        }

        /** Sets the required capability names for this role. */
        public Builder requiredCapabilities(String... capabilities) {
            this.requiredCapabilities = List.of(capabilities);
            return this;
        }

        /** Sets whether the JWKS provider endpoint should be enabled. */
        public Builder jwksProviderEnabled(boolean enabled) {
            this.jwksProviderEnabled = enabled;
            return this;
        }

        /**
         * Sets the default algorithm mapping for each key name.
         *
         * @param algorithms map of key name to default algorithm (e.g., "ES256", "RS256")
         * @throws NullPointerException if algorithms is null
         */
        public Builder keyDefaultAlgorithms(Map<String, String> algorithms) {
            this.keyDefaultAlgorithms = Map.copyOf(Objects.requireNonNull(algorithms));
            return this;
        }

        /**
         * Sets the mapping from key names to their source peer services.
         *
         * @param mapping map of key name to peer name (e.g., "wit-verification" → "agent-idp")
         * @throws NullPointerException if mapping is null
         */
        public Builder keyToPeerMapping(Map<String, String> mapping) {
            this.keyToPeerMapping = Map.copyOf(Objects.requireNonNull(mapping));
            return this;
        }

        /**
         * Builds an immutable {@link RoleProfile} from this builder's state.
         *
         * @return a new RoleProfile instance
         */
        public RoleProfile build() {
            return new RoleProfile(this);
        }
    }
}
