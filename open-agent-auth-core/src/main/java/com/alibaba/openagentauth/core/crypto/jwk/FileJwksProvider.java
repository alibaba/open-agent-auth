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
package com.alibaba.openagentauth.core.crypto.jwk;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.exception.crypto.FileJwksProviderException;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * File-based JWKS provider that loads keys from local file system.
 * <p>
 * This implementation loads public keys from JWKS files stored in the file system.
 * It supports both static loading and dynamic refresh capabilities.
 * </p>
 * <p>
 * <b>Supported Protocols:</b>
 * <ul>
 *   <li><b>file:</b> Load files from the local file system</li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Examples:</b>
 * <pre>{@code
 * // Load from file system
 * JwksProvider provider = new FileJwksProvider("file:/path/to/jwks.json");
 * }</pre>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 * @since 1.0
 */
public class FileJwksProvider implements JwksProvider {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(FileJwksProvider.class);

    /**
     * The list of file paths.
     */
    private final List<String> filePaths;

    /**
     * Whether to enable auto-refresh of file content.
     */
    private final boolean enableAutoRefresh;

    /**
     * The key store for managing JWKs.
     */
    private final KeyStore keyStore;

    /**
     * The last modified time for each file path.
     */
    private final java.util.Map<String, Long> fileLastModifiedTimes;

    /**
     * The scheduled executor service for async refresh tasks.
     */
    private final ScheduledExecutorService scheduler;

    /**
     * Flag to prevent overlapping refresh tasks.
     */
    private volatile boolean isRefreshing = false;

    /**
     * Creates a new FileJwksProvider with the specified file paths and key store.
     * Auto-refresh is enabled by default.
     *
     * @param filePaths the list of file paths (each must start with "file:")
     * @param keyStore  the key store for managing JWKs (must not be null)
     * @throws IllegalArgumentException if filePaths is null or empty, or keyStore is null
     */
    public FileJwksProvider(List<String> filePaths, KeyStore keyStore) {
        this(filePaths, true, keyStore);
    }

    /**
     * Creates a new FileJwksProvider with the specified file paths, auto-refresh setting, and key store.
     *
     * @param filePaths         the list of file paths (each must start with "file:")
     * @param enableAutoRefresh whether to enable auto-refresh of file content
     * @param keyStore          the key store for managing JWKs (must not be null)
     * @throws IllegalArgumentException if filePaths is null or empty, or keyStore is null
     */
    public FileJwksProvider(List<String> filePaths, boolean enableAutoRefresh, KeyStore keyStore) {
        ValidationUtils.validateNotNull(filePaths, "FilePaths");
        if (filePaths.isEmpty()) {
            throw new IllegalArgumentException("FilePaths cannot be empty");
        }
        ValidationUtils.validateNotNull(keyStore, "KeyStore");

        this.filePaths = filePaths;
        this.enableAutoRefresh = enableAutoRefresh;
        this.keyStore = keyStore;
        this.fileLastModifiedTimes = new ConcurrentHashMap<>();
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "FileProvider-Refresh-" + filePaths);
            thread.setDaemon(true);
            return thread;
        });
        logger.info("FileProvider initialized with filePaths: {}, autoRefresh: {}, keyStore: {}",
                filePaths, enableAutoRefresh, keyStore.getClass().getSimpleName());
    }

    @Override
    public JWKSource<SecurityContext> getJwkSource() {
        return (selector, context) -> {
            try {
                return getJwkSet().getKeys();
            } catch (IOException e) {
                throw new RuntimeException("Failed to get JWK keys", e);
            }
        };
    }

    @Override
    public JWKSet getJwkSet() throws IOException {
        // Try to load from keyStore first
        JWKSet jwkSet = loadJwkSetFromKeyStore();
        if (jwkSet != null && !jwkSet.getKeys().isEmpty()) {
            logger.debug("Returning JWK set from keyStore (keys: {})", jwkSet.getKeys().size());
            // Trigger async refresh task only if auto-refresh is enabled
            if (enableAutoRefresh) {
                scheduleAsyncRefresh();
            }
            return jwkSet;
        }

        // Load JWK set from files
        jwkSet = loadJwkSetFromFiles();

        // Store to keyStore
        storeJwkSetToKeyStore(jwkSet);

        // Initialize file modification times
        initializeFileModifiedTimes();

        logger.info("Loaded JWK set from: {} (keys: {})", filePaths, jwkSet.getKeys().size());
        return jwkSet;
    }

    @Override
    public void refresh() throws IOException {
        logger.info("Refreshing JWK set from: {}", filePaths);
        getJwkSet(); // Reload
        logger.info("JWK set refreshed successfully");
    }

    /**
     * Loads the JWK set from the configured file paths.
     *
     * @return the loaded JWK set
     */
    private JWKSet loadJwkSetFromFiles() {
        List<JWK> allJwks = new ArrayList<>();
        for (String filePath : filePaths) {
            try {
                Path actualFilePath = Paths.get(filePath);
                String content = Files.readString(actualFilePath);
                JWKSet jwkSet = JWKSet.parse(content);
                allJwks.addAll(jwkSet.getKeys());
                logger.info("Loaded JWK set from: {} (keys: {})", filePath, jwkSet.getKeys().size());
            } catch (Exception e) {
                logger.warn("Failed to load JWK set from: {}, skipping. Error: {}", filePath, e.getMessage());
            }
        }

        if (allJwks.isEmpty()) {
            throw new FileJwksProviderException("Failed to load any JWK set from: " + filePaths);
        }

        return new JWKSet(allJwks);
    }

    /**
     * Loads the JWK set from keyStore.
     *
     * @return the loaded JWK set, or null if not found or empty
     */
    private JWKSet loadJwkSetFromKeyStore() {
        try {
            List<String> keyIds = keyStore.listKeyIds();
            if (keyIds.isEmpty()) {
                logger.debug("No keys found in keyStore");
                return null;
            }

            List<JWK> jwkList = new ArrayList<>();
            for (String keyId : keyIds) {
                Optional<Object> jwkOpt = keyStore.retrieveJWK(keyId);
                jwkOpt.ifPresent(o -> jwkList.add((JWK) o));
            }

            if (jwkList.isEmpty()) {
                logger.debug("No JWKs found in keyStore");
                return null;
            }

            return new JWKSet(jwkList);
        } catch (KeyManagementException e) {
            logger.warn("Failed to load JWK set from keyStore: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Stores the JWK set to keyStore.
     *
     * @param jwkSet the JWK set to store
     */
    private void storeJwkSetToKeyStore(JWKSet jwkSet) {
        try {
            // Clear existing keys in keyStore
            keyStore.clear();

            // Store each JWK from the set
            Instant now = Instant.now();
            for (JWK jwk : jwkSet.getKeys()) {
                String keyId = jwk.getKeyID();
                if (keyId == null || keyId.isEmpty()) {
                    logger.warn("Skipping JWK without key ID: {}", jwk.getAlgorithm());
                    continue;
                }

                // Create KeyInfo for this key
                KeyAlgorithm algorithm = mapJwkAlgorithmToKeyAlgorithm(jwk.getAlgorithm().getName());
                KeyInfo keyInfo = KeyInfo.builder()
                        .keyId(keyId)
                        .algorithm(algorithm)
                        .createdAt(now)
                        .activatedAt(now)
                        .active(true)
                        .build();

                // Store JWK with metadata
                keyStore.storeJWK(keyId, jwk, keyInfo);
            }

            logger.info("Stored {} JWKs to keyStore", jwkSet.getKeys().size());
        } catch (KeyManagementException e) {
            logger.error("Failed to store JWK set to keyStore: {}", e.getMessage(), e);
        }
    }

    /**
     * Maps JWK algorithm name to KeyAlgorithm enum.
     *
     * @param jwkAlgorithm the JWK algorithm name
     * @return the corresponding KeyAlgorithm
     */
    private KeyAlgorithm mapJwkAlgorithmToKeyAlgorithm(String jwkAlgorithm) {
        if (jwkAlgorithm == null) {
            return KeyAlgorithm.RS256; // Default fallback
        }

        return switch (jwkAlgorithm) {
            case "RS256" -> KeyAlgorithm.RS256;
            case "RS384" -> KeyAlgorithm.RS384;
            case "RS512" -> KeyAlgorithm.RS512;
            case "ES256" -> KeyAlgorithm.ES256;
            case "ES384" -> KeyAlgorithm.ES384;
            case "ES512" -> KeyAlgorithm.ES512;
            default -> {
                logger.warn("Unknown JWK algorithm: {}, defaulting to RS256", jwkAlgorithm);
                yield KeyAlgorithm.RS256;
            }
        };
    }

    /**
     * Initializes the file modification times for all files.
     */
    private void initializeFileModifiedTimes() {
        for (String filePath : filePaths) {
            try {
                Path actualFilePath = Paths.get(filePath);
                long modifiedTime = Files.getLastModifiedTime(actualFilePath).toMillis();
                fileLastModifiedTimes.put(filePath, modifiedTime);
            } catch (IOException e) {
                logger.warn("Failed to get last modified time for file: {}", filePath, e);
            }
        }
    }

    /**
     * Updates the last modified time for a specific file.
     *
     * @param filePath the file path
     */
    private void updateFileModifiedTime(String filePath) {
        try {
            Path actualFilePath = Paths.get(filePath);
            long modifiedTime = Files.getLastModifiedTime(actualFilePath).toMillis();
            fileLastModifiedTimes.put(filePath, modifiedTime);
        } catch (IOException e) {
            logger.warn("Failed to get last modified time for file: {}", filePath, e);
        }
    }

    /**
     * Schedules an async refresh task to check for file changes.
     * Only schedules if auto-refresh is enabled.
     */
    private void scheduleAsyncRefresh() {
        if (!enableAutoRefresh) {
            logger.debug("Auto-refresh is disabled, skipping");
            return;
        }

        if (isRefreshing) {
            logger.debug("Refresh task already running, skipping");
            return;
        }

        scheduler.schedule(() -> {
            try {
                asyncRefresh();
            } catch (Exception e) {
                logger.error("Error during async refresh", e);
            }
        }, 1, TimeUnit.SECONDS);
    }

    /**
     * Performs async refresh by checking if any file has been modified.
     */
    private void asyncRefresh() {
        if (isRefreshing) {
            return;
        }

        isRefreshing = true;
        try {
            List<String> modifiedFiles = getModifiedFiles();
            if (modifiedFiles.isEmpty()) {
                logger.debug("No file modified, no refresh needed");
                return;
            }

            logger.info("Modified files detected: {}, reloading JWK set", modifiedFiles);
            reloadModifiedFiles(modifiedFiles);
        } catch (IOException e) {
            logger.error("Failed to check file modification time", e);
        } finally {
            isRefreshing = false;
        }
    }

    /**
     * Checks if any file has been modified and returns the list of modified files.
     *
     * @return list of modified file paths
     * @throws IOException if checking fails
     */
    private List<String> getModifiedFiles() throws IOException {
        List<String> modifiedFiles = new ArrayList<>();
        for (String filePath : filePaths) {
            Path actualFilePath = Paths.get(filePath);
            long currentModifiedTime = Files.getLastModifiedTime(actualFilePath).toMillis();
            Long lastModifiedTime = fileLastModifiedTimes.get(filePath);
            if (lastModifiedTime == null || currentModifiedTime > lastModifiedTime) {
                modifiedFiles.add(filePath);
            }
        }
        return modifiedFiles;
    }

    /**
     * Reloads JWK set from modified files and updates cache.
     *
     * @param modifiedFiles the list of modified file paths
     */
    private void reloadModifiedFiles(List<String> modifiedFiles) {
        try {
            // Load JWKs from modified files
            List<JWK> modifiedJwks = new ArrayList<>();
            for (String filePath : modifiedFiles) {
                try {
                    Path actualFilePath = Paths.get(filePath);
                    String content = Files.readString(actualFilePath);
                    JWKSet jwkSet = JWKSet.parse(content);
                    modifiedJwks.addAll(jwkSet.getKeys());
                    logger.info("Reloaded JWK set from modified file: {} (keys: {})", 
                            filePath, jwkSet.getKeys().size());
                    
                    // Update file modification time
                    updateFileModifiedTime(filePath);
                } catch (Exception e) {
                    logger.error("Failed to reload JWK set from modified file: {}", filePath, e);
                }
            }

            if (!modifiedJwks.isEmpty()) {
                // Update keyStore with modified JWKs
                updateKeyStoreWithModifiedJwks(modifiedJwks);
                
                logger.info("JWK set updated successfully from modified files: {} (total keys: {})",
                        modifiedFiles, modifiedJwks.size());
            }
        } catch (Exception e) {
            logger.error("Failed to reload JWK set from modified files: {}", modifiedFiles, e);
        }
    }

    /**
     * Updates keyStore with modified JWKs.
     * Removes old JWKs from the same files and adds new ones.
     *
     * @param modifiedJwks the list of modified JWKs
     */
    private void updateKeyStoreWithModifiedJwks(List<JWK> modifiedJwks) {
        try {
            Instant now = Instant.now();
            
            // Delete existing JWKs that are in the modified set (will be re-added)
            for (JWK jwk : modifiedJwks) {
                String keyId = jwk.getKeyID();
                if (keyId != null && !keyId.isEmpty()) {
                    keyStore.delete(keyId);
                }
            }
            
            // Add new JWKs
            for (JWK jwk : modifiedJwks) {
                String keyId = jwk.getKeyID();
                if (keyId == null || keyId.isEmpty()) {
                    logger.warn("Skipping JWK without key ID: {}", jwk.getAlgorithm());
                    continue;
                }

                // Create KeyInfo for this key
                KeyAlgorithm algorithm = mapJwkAlgorithmToKeyAlgorithm(jwk.getAlgorithm().getName());
                KeyInfo keyInfo = KeyInfo.builder()
                        .keyId(keyId)
                        .algorithm(algorithm)
                        .createdAt(now)
                        .activatedAt(now)
                        .active(true)
                        .build();

                // Store JWK with metadata
                keyStore.storeJWK(keyId, jwk, keyInfo);
            }

            logger.info("Updated {} JWKs in keyStore", modifiedJwks.size());
        } catch (KeyManagementException e) {
            logger.error("Failed to update keyStore with modified JWKs: {}", e.getMessage(), e);
        }
    }

}
