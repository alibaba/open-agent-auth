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
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.KeyPair;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory implementation of KeyStore.
 * <p>
 * This implementation stores keys in memory using a thread-safe ConcurrentHashMap.
 * It is suitable for development and testing environments, but should not be used
 * in production as keys are lost when the application restarts.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently.
 * </p>
 * <p>
 * <b>Limitations:</b></p>
 * <ul>
 *   <li>Keys are not persisted across application restarts</li>
 *   <li>Not suitable for production deployments</li>
 *   <li>Keys are stored in plain text in memory</li>
 * </ul>
 * </p>
 *
 * @see KeyStore
 * @since 1.0
 */
public class InMemoryKeyStore implements KeyStore {
    
    /**
     * Thread-safe map for storing key pairs.
     */
    private final ConcurrentHashMap<String, KeyPair> keyPairMap;
    
    /**
     * Thread-safe map for storing key metadata.
     */
    private final ConcurrentHashMap<String, KeyInfo> keyInfoMap;
    
    /**
     * Thread-safe map for storing JWK objects (preserves kid information).
     */
    private final ConcurrentHashMap<String, Object> jwkMap;
    
    /**
     * Creates a new InMemoryKeyStore.
     */
    public InMemoryKeyStore() {
        this.keyPairMap = new ConcurrentHashMap<>();
        this.keyInfoMap = new ConcurrentHashMap<>();
        this.jwkMap = new ConcurrentHashMap<>();
    }

    /**
     * Stores a key pair and its metadata in the store.
     *
     * @param keyId the key ID
     * @param keyPair the key pair
     * @param keyInfo the key info
     * @throws KeyManagementException if storage fails
     */
    @Override
    public void store(String keyId, KeyPair keyPair, KeyInfo keyInfo) throws KeyManagementException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        ValidationUtils.validateNotNull(keyPair, "Key pair");
        ValidationUtils.validateNotNull(keyInfo, "Key info");

        // Store key pair and key info
        keyPairMap.put(keyId, keyPair);
        keyInfoMap.put(keyId, keyInfo);
    }

    /**
     * Retrieves a key pair from the store.
     *
     * @param keyId the key ID
     * @return the key pair, or null if not found
     * @throws KeyManagementException if retrieval fails
     */
    @Override
    public Optional<KeyPair> retrieve(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        return Optional.ofNullable(keyPairMap.get(keyId));
    }

    /**
     * Retrieves key info from the store.
     *
     * @param keyId the key ID
     * @return the key info, or null if not found
     * @throws KeyManagementException if retrieval fails
     */
    @Override
    public Optional<KeyInfo> retrieveInfo(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        return Optional.ofNullable(keyInfoMap.get(keyId));
    }

    /**
     * Checks if a key pair exists in the store.
     *
     * @param keyId the key ID
     * @return true if the key pair exists, false otherwise
     */
    @Override
    public boolean exists(String keyId) {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            return false;
        }
        
        return keyPairMap.containsKey(keyId);
    }

    /**
     * Deletes a key pair and its metadata from the store.
     *
     * @param keyId the key ID
     * @throws KeyManagementException if an error occurs
     */
    @Override
    public void delete(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        keyPairMap.remove(keyId);
        keyInfoMap.remove(keyId);
    }

    /**
     * Lists all key IDs in the store.
     *
     * @return a list of key IDs
     * @throws KeyManagementException if an error occurs
     */
    @Override
    public List<String> listKeyIds() {
        return keyPairMap.keySet().stream().toList();
    }

    /**
     * Clears all keys from the store.
     *
     * @throws KeyManagementException if an error occurs
     */
    @Override
    public void clear() throws KeyManagementException {
        keyPairMap.clear();
        keyInfoMap.clear();
        jwkMap.clear();
    }
    
    /**
     * Stores a JWK and its metadata in the store.
     *
     * @param keyId the key ID
     * @param jwk the JWK to store (RSAKey or ECKey)
     * @param keyInfo the key info
     * @throws KeyManagementException if storage fails
     */
    @Override
    public void storeJWK(String keyId, Object jwk, KeyInfo keyInfo) throws KeyManagementException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        ValidationUtils.validateNotNull(jwk, "JWK");
        ValidationUtils.validateNotNull(keyInfo, "Key info");

        // Store JWK and key info
        jwkMap.put(keyId, jwk);
        keyInfoMap.put(keyId, keyInfo);
        
        // Also store the KeyPair for backward compatibility
        try {
            if (jwk instanceof RSAKey) {
                keyPairMap.put(keyId, ((RSAKey) jwk).toKeyPair());
            } else if (jwk instanceof ECKey) {
                keyPairMap.put(keyId, ((ECKey) jwk).toKeyPair());
            }
        } catch (JOSEException e) {
            throw new KeyManagementException("Failed to convert JWK to KeyPair: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves a JWK from the store.
     *
     * @param keyId the key ID
     * @return the JWK, or null if not found
     * @throws KeyManagementException if retrieval fails
     */
    @Override
    public Optional<Object> retrieveJWK(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        return Optional.ofNullable(jwkMap.get(keyId));
    }
}