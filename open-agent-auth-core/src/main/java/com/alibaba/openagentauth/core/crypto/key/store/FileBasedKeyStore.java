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

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * File-based implementation of KeyStore.
 * <p>
 * This implementation persists keys to the file system, allowing keys to survive
 * application restarts. Keys are stored in a JSON format for easy inspection and
 * backup.
 * </p>
 * <p>
 * <b>Thread Safety:</b></p>
 * This implementation is thread-safe and can be used concurrently.
 * </p>
 * <p>
 * <b>Storage Format:</b></p>
 * Keys are stored as JSON files in the specified directory:
 * <ul>
 *   <li>{@code <keyId>.json} - Contains key metadata and JWK representation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Security Considerations:</b></p>
 * <ul>
 *   <li>File permissions should be restricted (600)</li>
 *   <li>Store only in environments with controlled access</li>
 * </ul>
 * </p>
 *
 * @see KeyStore
 * @see InMemoryKeyStore
 * @since 1.0
 */
public class FileBasedKeyStore implements KeyStore {
    
    /**
     * Object mapper for JSON serialization.
     */
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);
    
    /**
     * The directory where keys are stored.
     */
    private final Path storageDirectory;
    
    /**
     * In-memory cache for fast access.
     */
    private final ConcurrentHashMap<String, KeyPair> keyPairCache;
    
    /**
     * In-memory cache for key info.
     */
    private final ConcurrentHashMap<String, KeyInfo> keyInfoCache;
    
    /**
     * Creates a new FileBasedKeyStore.
     *
     * @param storageDirectory the directory where keys are stored
     * @throws IllegalArgumentException if storageDirectory is null
     */
    public FileBasedKeyStore(String storageDirectory) {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(storageDirectory)) {
            throw new IllegalArgumentException("Storage directory cannot be null or empty");
        }

        // Initialize
        this.storageDirectory = Paths.get(storageDirectory);
        this.keyPairCache = new ConcurrentHashMap<>();
        this.keyInfoCache = new ConcurrentHashMap<>();
        
        try {
            // Create directory if it doesn't exist
            if (!Files.exists(this.storageDirectory)) {
                Files.createDirectories(this.storageDirectory);
            }
            
            // Load existing keys from disk
            loadKeysFromDisk();
            
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to initialize storage directory: " + e.getMessage(), e);
        }
    }
    
    @Override
    public void store(String keyId, KeyPair keyPair, KeyInfo keyInfo) throws KeyManagementException {

        // Validate arguments
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        ValidationUtils.validateNotNull(keyPair, "Key pair");
        ValidationUtils.validateNotNull(keyInfo, "Key info");
        
        try {
            // Create JWK from key pair based on key type
            JWK jwk;
            java.security.PublicKey publicKey = keyPair.getPublic();
            
            if (publicKey instanceof RSAPublicKey) {
                jwk = new RSAKey.Builder((RSAPublicKey) publicKey)
                        .privateKey(keyPair.getPrivate())
                        .keyID(keyInfo.getKeyId())
                        .build();
            } else if (publicKey instanceof ECPublicKey) {
                jwk = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                        .privateKey(keyPair.getPrivate())
                        .keyID(keyInfo.getKeyId())
                        .build();
            } else {
                throw new KeyManagementException("Unsupported key type: " + publicKey.getClass().getName());
            }
            
            // Create storage map
            Map<String, Object> storageMap = new HashMap<>();
            storageMap.put("keyId", keyInfo.getKeyId());
            storageMap.put("algorithm", keyInfo.getAlgorithm().name());
            storageMap.put("createdAt", keyInfo.getCreatedAt().toString());
            storageMap.put("activatedAt", keyInfo.getActivatedAt().toString());
            storageMap.put("active", keyInfo.isActive());
            storageMap.put("jwk", jwk.toJSONString());
            
            // Write to file
            Path keyFile = storageDirectory.resolve(keyId + ".json");
            OBJECT_MAPPER.writeValue(keyFile.toFile(), storageMap);
            
            // Update cache
            keyPairCache.put(keyId, keyPair);
            keyInfoCache.put(keyId, keyInfo);
            
        } catch (IOException e) {
            throw new KeyManagementException("Failed to store key: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves a key pair from the cache.
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
        
        return Optional.ofNullable(keyPairCache.get(keyId));
    }

    /**
     * Retrieves key info from the cache.
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
        
        return Optional.ofNullable(keyInfoCache.get(keyId));
    }

    /**
     * Checks if a key exists in the cache.
     *
     * @param keyId the key ID
     * @return true if the key exists, false otherwise
     */
    @Override
    public boolean exists(String keyId) {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            return false;
        }
        
        return keyPairCache.containsKey(keyId);
    }

    /**
     * Deletes a key from the cache.
     *
     * @param keyId the key ID
     * @throws KeyManagementException if deletion fails
     */
    @Override
    public void delete(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        try {
            // Delete file
            Path keyFile = storageDirectory.resolve(keyId + ".json");
            if (Files.exists(keyFile)) {
                Files.delete(keyFile);
            }
            
            // Remove from cache
            keyPairCache.remove(keyId);
            keyInfoCache.remove(keyId);
            
        } catch (IOException e) {
            throw new KeyManagementException("Failed to delete key: " + e.getMessage(), e);
        }
    }

    /**
     * Lists all key IDs in the cache.
     *
     * @return the list of key IDs
     */
    @Override
    public List<String> listKeyIds() {
        return new ArrayList<>(keyPairCache.keySet());
    }

    /**
     * Clears all keys from the cache.
     *
     * @throws KeyManagementException if clearing fails
     */
    @Override
    public void clear() throws KeyManagementException {
        try {
            // Delete all key files
            for (String keyId : keyPairCache.keySet()) {
                Path keyFile = storageDirectory.resolve(keyId + ".json");
                if (Files.exists(keyFile)) {
                    Files.delete(keyFile);
                }
            }
            
            // Clear cache
            keyPairCache.clear();
            keyInfoCache.clear();
            
        } catch (IOException e) {
            throw new KeyManagementException("Failed to clear key store: " + e.getMessage(), e);
        }
    }
    
    /**
     * Stores a JWK with the specified key ID and metadata.
     *
     * @param keyId the unique identifier for this JWK
     * @param jwk the JWK to store (RSAKey or ECKey)
     * @param keyInfo the metadata information for this key
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
        
        try {
            // Convert JWK to JSON string
            String jwkString;
            if (jwk instanceof RSAKey) {
                jwkString = ((RSAKey) jwk).toJSONString();
            } else if (jwk instanceof ECKey) {
                jwkString = ((ECKey) jwk).toJSONString();
            } else {
                throw new KeyManagementException("Unsupported JWK type: " + jwk.getClass().getName());
            }
            
            // Create storage map
            Map<String, Object> storageMap = new HashMap<>();
            storageMap.put("keyId", keyInfo.getKeyId());
            storageMap.put("algorithm", keyInfo.getAlgorithm().name());
            storageMap.put("createdAt", keyInfo.getCreatedAt().toString());
            storageMap.put("activatedAt", keyInfo.getActivatedAt().toString());
            storageMap.put("active", keyInfo.isActive());
            storageMap.put("jwk", jwkString);
            
            // Write to file
            Path keyFile = storageDirectory.resolve(keyId + ".json");
            OBJECT_MAPPER.writeValue(keyFile.toFile(), storageMap);
            
            // Update cache
            if (jwk instanceof RSAKey) {
                keyPairCache.put(keyId, ((RSAKey) jwk).toKeyPair());
            } else if (jwk instanceof ECKey) {
                keyPairCache.put(keyId, ((ECKey) jwk).toKeyPair());
            }
            keyInfoCache.put(keyId, keyInfo);
            
        } catch (IOException | com.nimbusds.jose.JOSEException e) {
            throw new KeyManagementException("Failed to store JWK: " + e.getMessage(), e);
        }
    }

    /**
     * Retrieves the JWK for the specified key ID.
     *
     * @param keyId the key identifier
     * @return an Optional containing the JWK (RSAKey or ECKey), or empty if not found
     * @throws KeyManagementException if retrieval fails
     */
    @Override
    public Optional<Object> retrieveJWK(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        
        try {
            Path keyFile = storageDirectory.resolve(keyId + ".json");
            if (!Files.exists(keyFile)) {
                return Optional.empty();
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> storageMap = OBJECT_MAPPER.readValue(keyFile.toFile(), Map.class);
            
            // Parse JWK
            String jwkString = (String) storageMap.get("jwk");
            JWK jwk = JWK.parse(jwkString);
            
            return Optional.of(jwk);
            
        } catch (IOException | java.text.ParseException e) {
            throw new KeyManagementException("Failed to retrieve JWK: " + e.getMessage(), e);
        }
    }
    
    /**
     * Loads existing keys from disk into cache.
     *
     * @throws IOException if loading fails
     */
    private void loadKeysFromDisk() throws IOException {

        if (!Files.exists(storageDirectory)) {
            return;
        }
        
        File[] files = storageDirectory.toFile().listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            return;
        }
        
        for (File file : files) {
            try {
                String keyId = file.getName().replace(".json", "");
                
                @SuppressWarnings("unchecked")
                Map<String, Object> storageMap = OBJECT_MAPPER.readValue(file, Map.class);
                
                // Parse JWK
                String jwkString = (String) storageMap.get("jwk");
                JWK jwk = JWK.parse(jwkString);
                KeyPair keyPair;
                if (jwk instanceof RSAKey) {
                    keyPair = ((RSAKey) jwk).toKeyPair();
                } else if (jwk instanceof ECKey) {
                    keyPair = ((ECKey) jwk).toKeyPair();
                } else {
                    throw new IOException("Unsupported JWK type: " + jwk.getClass().getName());
                }
                
                // Parse KeyInfo
                KeyAlgorithm algorithm = KeyAlgorithm.valueOf((String) storageMap.get("algorithm"));
                KeyInfo keyInfo = KeyInfo.builder()
                        .keyId((String) storageMap.get("keyId"))
                        .algorithm(algorithm)
                        .createdAt(Instant.parse((String) storageMap.get("createdAt")))
                        .activatedAt(Instant.parse((String) storageMap.get("activatedAt")))
                        .active((Boolean) storageMap.get("active"))
                        .build();
                
                // Add to cache
                keyPairCache.put(keyId, keyPair);
                keyInfoCache.put(keyId, keyInfo);
                
            } catch (Exception e) {
                throw new IOException("Failed to load key from file: " + file.getName(), e);
            }
        }
    }
}