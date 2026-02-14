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
package com.alibaba.openagentauth.core.crypto.key;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * Interface for managing cryptographic keys in the Agent Operation Authorization framework.
 * <p>
 * This interface provides a unified API for key generation, storage, retrieval, and rotation.
 * It abstracts the underlying key storage mechanism, allowing implementations to use
 * in-memory storage.
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li><b>Key Generation:</b> Generate new key pairs with specified algorithms</li>
 *   <li><b>Key Storage:</b> Store keys with metadata (key ID, algorithm, creation time)</li>
 *   <li><b>Key Retrieval:</b> Retrieve signing and verification keys by key ID</li>
 *   <li><b>Key Rotation:</b> Rotate keys while maintaining backward compatibility</li>
 *   <li><b>Key Lifecycle:</b> Manage key activation and deactivation</li>
 * </ul>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations must be thread-safe for concurrent access.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * KeyManager keyManager = new InMemoryKeyManager();
 * 
 * // Generate a new key pair
 * KeyPair keyPair = keyManager.generateKeyPair(
 *     KeyAlgorithm.ES256,
 *     "wit-signing-key-001"
 * );
 * 
 * // Retrieve signing key
 * PrivateKey signingKey = keyManager.getSigningKey("wit-signing-key-001");
 * 
 * // Retrieve verification key
 * PublicKey verificationKey = keyManager.getVerificationKey("wit-signing-key-001");
 * 
 * // Rotate key
 * keyManager.rotateKey("wit-signing-key-001");
 * 
 * // Get all active keys
 * List<KeyInfo> activeKeys = keyManager.getActiveKeys();
 * }</pre>
 * </p>
 *
 * @see KeyAlgorithm
 * @see KeyInfo
 * @see KeyStore
 * @since 1.0
 */
public interface KeyManager {
    
    /**
     * Generates a new key pair with the specified algorithm and key ID.
     * <p>
     * This method creates a new cryptographic key pair and stores it in the underlying
     * key store. The key ID must be unique within the key manager.
     * </p>
     * <p>
     * <b>Key ID Format:</b></p>
     * Key IDs should follow a consistent naming convention, such as:
     * <ul>
     *   <li>{@code wit-signing-key-001} for WIT signing keys</li>
     *   <li>{@code wpt-signing-key-001} for WPT signing keys</li>
     *   <li>{@code aoat-signing-key-001} for AOAT signing keys</li>
     * </ul>
     * </p>
     *
     * @param algorithm the cryptographic algorithm to use
     * @param keyId the unique identifier for this key pair
     * @return the generated key pair
     * @throws KeyManagementException if key generation fails or key ID already exists
     * @throws IllegalArgumentException if algorithm or keyId is null or invalid
     */
    KeyPair generateKeyPair(KeyAlgorithm algorithm, String keyId) throws KeyManagementException;
    
    /**
     * Gets the signing private key for the specified key ID.
     * <p>
     * This method retrieves the private key that should be used for signing operations.
     * The key must be active and valid.
     * </p>
     *
     * @param keyId the key identifier
     * @return the private signing key
     * @throws KeyManagementException if the key is not found or not available for signing
     * @throws IllegalArgumentException if keyId is null or empty
     */
    PrivateKey getSigningKey(String keyId) throws KeyManagementException;
    
    /**
     * Gets the signing JWK for the specified key ID.
     * <p>
     * This method retrieves the JWK (JSON Web Key) that contains both the private key
     * and metadata including the key ID (kid). This is useful for signing operations
     * that require the kid to be included in the JWT header.
     * </p>
     *
     * @param keyId the key identifier
     * @return the signing JWK (RSAKey or ECKey)
     * @throws KeyManagementException if the key is not found or not available for signing
     * @throws IllegalArgumentException if keyId is null or empty
     */
    Object getSigningJWK(String keyId) throws KeyManagementException;
    
    /**
     * Gets the verification public key for the specified key ID.
     * <p>
     * This method retrieves the public key that should be used for signature verification.
     * The key must be active and valid.
     * </p>
     *
     * @param keyId the key identifier
     * @return the public verification key
     * @throws KeyManagementException if the key is not found or not available for verification
     * @throws IllegalArgumentException if keyId is null or empty
     */
    PublicKey getVerificationKey(String keyId) throws KeyManagementException;
    
    /**
     * Rotates the key pair for the specified key ID.
     * <p>
     * This method generates a new key pair with the same algorithm and replaces the old key.
     * The old key is retained for a grace period to allow for smooth transition.
     * </p>
     * <p>
     * <b>Key Rotation Process:</b></p>
     * <ol>
     *   <li>Generate new key pair with the same algorithm</li>
     *   <li>Mark old key as "rotating" (still valid for verification)</li>
     *   <li>Activate new key for signing operations</li>
     *   <li>After grace period, mark old key as "inactive"</li>
     * </ol>
     * </p>
     *
     * @param keyId the key identifier to rotate
     * @throws KeyManagementException if rotation fails or key is not found
     * @throws IllegalArgumentException if keyId is null or empty
     */
    void rotateKey(String keyId) throws KeyManagementException;
    
    /**
     * Gets all active keys in the key manager.
     * <p>
     * This method returns a list of all keys that are currently active and can be used
     * for signing or verification operations.
     * </p>
     *
     * @return a list of active key information
     */
    List<KeyInfo> getActiveKeys();
    
    /**
     * Checks if a key with the specified ID exists.
     *
     * @param keyId the key identifier
     * @return true if the key exists, false otherwise
     */
    boolean hasKey(String keyId);
    
    /**
     * Deletes the key with the specified ID.
     * <p>
     * <b>Warning:</b> This operation is irreversible. Use with caution.
     * </p>
     *
     * @param keyId the key identifier to delete
     * @throws KeyManagementException if deletion fails or key is not found
     * @throws IllegalArgumentException if keyId is null or empty
     */
    void deleteKey(String keyId) throws KeyManagementException;
    
    /**
     * Gets or generates a signing key with the specified ID and algorithm.
     * <p>
     * This convenience method checks if a key with the given ID already exists.
     * If it exists, it returns the existing key. If not, it generates a new key pair
     * and returns it. This eliminates the need for repetitive "check-exist-generate" patterns.
     * </p>
     * <p>
     * <b>Usage Example:</b></p>
     * <pre>{@code
     * // Instead of:
     * if (keyManager.hasKey(keyId)) {
     *     return (JWK) keyManager.getSigningJWK(keyId);
     * }
     * keyManager.generateKeyPair(KeyAlgorithm.RS256, keyId);
     * return (JWK) keyManager.getSigningJWK(keyId);
     * 
     * // Simply use:
     * return (JWK) keyManager.getOrGenerateKey(keyId, KeyAlgorithm.RS256);
     * }</pre>
     * </p>
     *
     * @param keyId the key identifier
     * @param algorithm the cryptographic algorithm to use for generation if key doesn't exist
     * @return the signing JWK (RSAKey or ECKey)
     * @throws KeyManagementException if key generation fails
     * @throws IllegalArgumentException if algorithm or keyId is null or invalid
     * @since 1.0
     */
    default Object getOrGenerateKey(String keyId, KeyAlgorithm algorithm) throws KeyManagementException {
        if (hasKey(keyId)) {
            return getSigningJWK(keyId);
        }
        generateKeyPair(algorithm, keyId);
        return getSigningJWK(keyId);
    }
}
