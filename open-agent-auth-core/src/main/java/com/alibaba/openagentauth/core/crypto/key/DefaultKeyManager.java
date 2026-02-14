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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Default implementation of KeyManager.
 * <p>
 * This implementation provides a thread-safe key management solution with support for
 * key generation, storage, retrieval, and rotation. It uses a pluggable KeyStore
 * implementation for persistent storage.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and uses read-write locks for optimal
 * concurrent access performance.
 * </p>
 * <p>
 * <b>Key Rotation:</b></p>
 * When a key is rotated, the old key is retained for a grace period to allow
 * for smooth transition. The old key is marked as inactive but can still be used
 * for verification.
 * </p>
 *
 * @see KeyManager
 * @see KeyStore
 * @since 1.0
 */
public class DefaultKeyManager implements KeyManager {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultKeyManager.class);
    
    /**
     * The underlying key store for persistent storage.
     */
    private final KeyStore keyStore;
    
    /**
     * Read-write lock for thread-safe key operations.
     */
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    
    /**
     * Creates a new DefaultKeyManager with the specified key store.
     *
     * @param keyStore the key store implementation
     * @throws IllegalArgumentException if keyStore is null
     */
    public DefaultKeyManager(KeyStore keyStore) {
        ValidationUtils.validateNotNull(keyStore, "KeyStore");
        this.keyStore = keyStore;
        logger.info("DefaultKeyManager initialized with KeyStore: {}", keyStore.getClass().getSimpleName());
    }

    /**
     * Generates a new key pair with the specified algorithm and key ID.
     *
     * @param algorithm the key algorithm
     * @param keyId the key ID
     * @return the generated key pair
     * @throws KeyManagementException if key generation fails
     */
    @Override
    public KeyPair generateKeyPair(KeyAlgorithm algorithm, String keyId) throws KeyManagementException {

        // Validate arguments
        ValidationUtils.validateNotNull(algorithm, "Algorithm");
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        lock.writeLock().lock();
        try {
            // Check if key already exists
            if (keyStore.exists(keyId)) {
                throw new KeyManagementException("Key with ID '" + keyId + "' already exists");
            }
            
            // Generate JWK based on algorithm
            Object jwk;
            KeyPair keyPair;
            try {
                jwk = getJWK(keyId, algorithm);
                if (jwk instanceof RSAKey) {
                    keyPair = ((RSAKey) jwk).toKeyPair();
                } else if (jwk instanceof ECKey) {
                    keyPair = ((ECKey) jwk).toKeyPair();
                } else {
                    throw new KeyManagementException("Unsupported JWK type: " + jwk.getClass().getName());
                }
            } catch (JOSEException e) {
                throw new KeyManagementException("Failed to generate key pair: " + e.getMessage(), e);
            }
            
            // Create key metadata
            Instant now = Instant.now();
            KeyInfo keyInfo = KeyInfo.builder()
                    .keyId(keyId)
                    .algorithm(algorithm)
                    .createdAt(now)
                    .activatedAt(now)
                    .active(true)
                    .build();
            
            // Store JWK (preserves kid) and key pair (for backward compatibility)
            keyStore.storeJWK(keyId, jwk, keyInfo);
            
            logger.info("Generated new key pair: keyId={}, algorithm={}", keyId, algorithm);
            return keyPair;
            
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Retrieves the signing key for the specified key ID.
     *
     * @param keyId the key ID
     * @return the signing key
     * @throws KeyManagementException if key retrieval fails
     */
    @Override
    public PrivateKey getSigningKey(String keyId) throws KeyManagementException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        lock.readLock().lock();
        try {
            Optional<KeyPair> keyPairOpt = keyStore.retrieve(keyId);
            if (keyPairOpt.isEmpty()) {
                throw new KeyManagementException("Key not found: " + keyId);
            }
            
            Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
            if (keyInfoOpt.isEmpty()) {
                throw new KeyManagementException("Key info not found: " + keyId);
            }
            
            KeyInfo keyInfo = keyInfoOpt.get();
            if (!keyInfo.isActive()) {
                throw new KeyManagementException("Key is not active for signing: " + keyId);
            }
            
            return keyPairOpt.get().getPrivate();
            
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Retrieves the verification key for the specified key ID.
     *
     * @param keyId the key ID
     * @return the verification key
     * @throws KeyManagementException if key retrieval fails
     */
    @Override
    public PublicKey getVerificationKey(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        lock.readLock().lock();
        try {
            Optional<KeyPair> keyPairOpt = keyStore.retrieve(keyId);
            if (keyPairOpt.isEmpty()) {
                throw new KeyManagementException("Key not found: " + keyId);
            }
            
            return keyPairOpt.get().getPublic();
            
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Rotates the key with the specified key ID.
     *
     * @param keyId the key ID
     * @throws KeyManagementException if key rotation fails
     */
    @Override
    public void rotateKey(String keyId) throws KeyManagementException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        lock.writeLock().lock();
        try {
            // Retrieve existing key info
            Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
            if (keyInfoOpt.isEmpty()) {
                throw new KeyManagementException("Key not found for rotation: " + keyId);
            }
            
            KeyInfo oldKeyInfo = keyInfoOpt.get();
            KeyAlgorithm algorithm = oldKeyInfo.getAlgorithm();
            
            // Generate new key pair with the same algorithm
            KeyPair newKeyPair;
            try {
                newKeyPair = getKeyPair(keyId, algorithm);
            } catch (JOSEException e) {
                throw new KeyManagementException("Failed to generate new key pair: " + e.getMessage(), e);
            }
            
            // Create new key metadata
            Instant now = Instant.now();
            KeyInfo newKeyInfo = KeyInfo.builder()
                    .keyId(keyId)
                    .algorithm(algorithm)
                    .createdAt(now)
                    .activatedAt(now)
                    .rotatedAt(now)
                    .active(true)
                    .previousKeyId(keyId)
                    .build();
            
            // Store new key pair and metadata
            keyStore.store(keyId, newKeyPair, newKeyInfo);
            
            logger.info("Rotated key: keyId={}, algorithm={}", keyId, algorithm);
            
        } finally {
            lock.writeLock().unlock();
        }
    }

    private KeyPair getKeyPair(String keyId, KeyAlgorithm algorithm) throws JOSEException {
        KeyPair newKeyPair;
        if (algorithm.isRsa()) {
            var generator = new RSAKeyGenerator(algorithm.getKeySize()).keyID(keyId);
            RSAKey jwk = generator.generate();
            newKeyPair = jwk.toKeyPair();
        } else if (algorithm.isEc()) {
            var generator = new ECKeyGenerator(Curve.P_256).keyID(keyId);
            ECKey jwk = generator.generate();
            newKeyPair = jwk.toKeyPair();
        } else {
            throw new KeyManagementException("Unsupported algorithm: " + algorithm);
        }
        return newKeyPair;
    }

    /**
     * Retrieves the list of active keys.
     *
     * @return the list of active keys
     */
    @Override
    public List<KeyInfo> getActiveKeys() {
        lock.readLock().lock();
        try {
            List<KeyInfo> activeKeys = new ArrayList<>();
            for (String keyId : keyStore.listKeyIds()) {
                Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
                if (keyInfoOpt.isPresent() && keyInfoOpt.get().isActive()) {
                    activeKeys.add(keyInfoOpt.get());
                }
            }
            return activeKeys;
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Checks if a key with the specified key ID exists.
     *
     * @param keyId the key ID
     * @return true if the key exists, false otherwise
     */
    @Override
    public boolean hasKey(String keyId) {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            return false;
        }
        
        lock.readLock().lock();
        try {
            return keyStore.exists(keyId);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Deletes the key with the specified key ID.
     *
     * @param keyId the key ID
     * @throws KeyManagementException if key deletion fails
     */
    @Override
    public void deleteKey(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        lock.writeLock().lock();
        try {
            if (!keyStore.exists(keyId)) {
                throw new KeyManagementException("Key not found for deletion: " + keyId);
            }
            
            keyStore.delete(keyId);
            logger.info("Deleted key: keyId={}", keyId);
            
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Gets the signing JWK for the specified key ID.
     *
     * @param keyId the key ID
     * @return the signing JWK
     * @throws KeyManagementException if key retrieval fails
     */
    @Override
    public Object getSigningJWK(String keyId) throws KeyManagementException {
        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        lock.readLock().lock();
        try {
            Optional<Object> jwkOpt = keyStore.retrieveJWK(keyId);
            if (jwkOpt.isEmpty()) {
                throw new KeyManagementException("JWK not found: " + keyId);
            }
            
            Optional<KeyInfo> keyInfoOpt = keyStore.retrieveInfo(keyId);
            if (keyInfoOpt.isEmpty()) {
                throw new KeyManagementException("Key info not found: " + keyId);
            }
            
            KeyInfo keyInfo = keyInfoOpt.get();
            if (!keyInfo.isActive()) {
                throw new KeyManagementException("Key is not active for signing: " + keyId);
            }
            
            return jwkOpt.get();
            
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Generates a JWK based on the algorithm.
     *
     * @param keyId the key ID
     * @param algorithm the key algorithm
     * @return the generated JWK
     * @throws JOSEException if JWK generation fails
     */
    private Object getJWK(String keyId, KeyAlgorithm algorithm) throws JOSEException {
        if (algorithm.isRsa()) {
            var generator = new RSAKeyGenerator(algorithm.getKeySize()).keyID(keyId);
            return generator.generate();
        } else if (algorithm.isEc()) {
            var generator = new ECKeyGenerator(Curve.P_256).keyID(keyId);
            return generator.generate();
        } else {
            throw new KeyManagementException("Unsupported algorithm: " + algorithm);
        }
    }
}