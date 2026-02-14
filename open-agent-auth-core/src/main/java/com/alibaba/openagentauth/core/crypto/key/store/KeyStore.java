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
package com.alibaba.openagentauth.core.crypto.key.store;

import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;

import java.security.KeyPair;
import java.util.List;
import java.util.Optional;

/**
 * Interface for storing and retrieving cryptographic keys.
 * <p>
 * This interface abstracts the underlying storage mechanism for keys, allowing
 * implementations to use different storage backends such as in-memory storage.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Strategy Pattern</p>
 * <p>
 * This interface allows the KeyManager to use different storage strategies without
 * modifying its core logic. Different storage implementations can be plugged in
 * at runtime based on deployment requirements.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * Implementations must be thread-safe for concurrent access.
 * </p>
 *
 * @see KeyManager
 * @see InMemoryKeyStore
 * @since 1.0
 */
public interface KeyStore {
    
    /**
     * Stores a key pair with the specified key ID and metadata.
     *
     * @param keyId the unique identifier for this key pair
     * @param keyPair the key pair to store
     * @param keyInfo the metadata information for this key
     * @throws KeyManagementException if storage fails
     */
    void store(String keyId, KeyPair keyPair, KeyInfo keyInfo) throws KeyManagementException;
    
    /**
     * Stores a JWK with the specified key ID and metadata.
     * <p>
     * This method stores the complete JWK object (RSAKey or ECKey) which contains
     * both the key material and metadata including the key ID (kid). This is
     * preferred over storing just the KeyPair as it preserves the kid information.
     * </p>
     *
     * @param keyId the unique identifier for this JWK
     * @param jwk the JWK to store (RSAKey or ECKey)
     * @param keyInfo the metadata information for this key
     * @throws KeyManagementException if storage fails
     */
    void storeJWK(String keyId, Object jwk, KeyInfo keyInfo) throws KeyManagementException;
    
    /**
     * Retrieves the JWK for the specified key ID.
     *
     * @param keyId the key identifier
     * @return an Optional containing the JWK (RSAKey or ECKey), or empty if not found
     * @throws KeyManagementException if retrieval fails
     */
    Optional<Object> retrieveJWK(String keyId) throws KeyManagementException;
    
    /**
     * Retrieves the key pair for the specified key ID.
     *
     * @param keyId the key identifier
     * @return an Optional containing the key pair, or empty if not found
     * @throws KeyManagementException if retrieval fails
     */
    Optional<KeyPair> retrieve(String keyId) throws KeyManagementException;
    
    /**
     * Retrieves the key info for the specified key ID.
     *
     * @param keyId the key identifier
     * @return an Optional containing the key info, or empty if not found
     * @throws KeyManagementException if retrieval fails
     */
    Optional<KeyInfo> retrieveInfo(String keyId) throws KeyManagementException;
    
    /**
     * Checks if a key with the specified ID exists.
     *
     * @param keyId the key identifier
     * @return true if the key exists, false otherwise
     */
    boolean exists(String keyId);
    
    /**
     * Deletes the key with the specified ID.
     *
     * @param keyId the key identifier to delete
     * @throws KeyManagementException if deletion fails
     */
    void delete(String keyId) throws KeyManagementException;
    
    /**
     * Gets all key IDs stored in this key store.
     *
     * @return a list of all key IDs
     */
    List<String> listKeyIds();
    
    /**
     * Clears all keys from this key store.
     * <p>
     * <b>Warning:</b> This operation is irreversible. Use with caution.
     * </p>
     *
     * @throws KeyManagementException if clearing fails
     */
    void clear() throws KeyManagementException;
}
