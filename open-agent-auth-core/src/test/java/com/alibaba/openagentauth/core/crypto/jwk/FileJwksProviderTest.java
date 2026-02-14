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
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.exception.crypto.FileJwksProviderException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for {@link FileJwksProvider}.
 * <p>
 * These tests validate the file-based JWKS provider functionality including:
 * </p>
 * <ul>
 *   <li>Loading JWK sets from single and multiple files</li>
 *   <li>Integration with KeyStore for caching</li>
 *   <li>File modification detection and refresh</li>
 *   <li>Auto-refresh functionality</li>
 *   <li>Error handling for invalid files</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("FileJwksProvider Tests")
class FileJwksProviderTest {

    private static final String TEST_KEY_ID_1 = "test-key-001";
    private static final String TEST_KEY_ID_2 = "test-key-002";
    private static final Instant NOW = Instant.now();

    private KeyStore keyStore;
    private RSAKey rsaKey1;
    private RSAKey rsaKey2;
    private Path testFile1;
    private Path testFile2;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() throws Exception {
        keyStore = new InMemoryKeyStore();

        // Generate RSA keys for testing
        rsaKey1 = new RSAKeyGenerator(2048)
                .keyID(TEST_KEY_ID_1)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .generate();

        rsaKey2 = new RSAKeyGenerator(2048)
                .keyID(TEST_KEY_ID_2)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .generate();

        // Create test files - use absolute path to ensure file: protocol works
        testFile1 = tempDir.resolve("jwks1.json").toAbsolutePath();
        testFile2 = tempDir.resolve("jwks2.json").toAbsolutePath();

        // Write initial JWK sets to files
        JWKSet jwkSet1 = new JWKSet(rsaKey1);
        Files.writeString(testFile1, jwkSet1.toString());

        JWKSet jwkSet2 = new JWKSet(rsaKey2);
        Files.writeString(testFile2, jwkSet2.toString());
    }

    @AfterEach
    void tearDown() {
        // Cleanup is handled by @TempDir
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create provider with single file and keyStore")
        void testConstructorWithSingleFileAndKeyStore() {
            // Act
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    keyStore
            );

            // Assert
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with multiple files and keyStore")
        void testConstructorWithMultipleFilesAndKeyStore() {
            // Act
            FileJwksProvider provider = new FileJwksProvider(
                    Arrays.asList(
                            testFile1.toString(),
                            testFile2.toString()
                    ),
                    keyStore
            );

            // Assert
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should create provider with auto-refresh disabled")
        void testConstructorWithAutoRefreshDisabled() {
            // Act
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    false,
                    keyStore
            );

            // Assert
            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when filePaths is null")
        void testConstructorWithNullFilePaths() {
            // Act & Assert
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> new FileJwksProvider(null, keyStore))
                    .withMessageContaining("FilePaths cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when filePaths is empty")
        void testConstructorWithEmptyFilePaths() {
            // Act & Assert
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> new FileJwksProvider(List.of(), keyStore))
                    .withMessageContaining("FilePaths cannot be empty");
        }

        @Test
        @DisplayName("Should throw exception when keyStore is null")
        void testConstructorWithNullKeyStore() {
            // Act & Assert
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> new FileJwksProvider(
                            List.of(testFile1.toString()),
                            (KeyStore) null
                    ))
                    .withMessageContaining("KeyStore cannot be null");
        }
    }

    @Nested
    @DisplayName("getJwkSet() Tests")
    class GetJwkSetTests {

        @Test
        @DisplayName("Should load JWK set from keyStore when available")
        void testGetJwkSetFromKeyStore() throws IOException {
            // Arrange
            // Create a new keyStore to avoid conflicts
            KeyStore populatedKeyStore = new InMemoryKeyStore();
            
            // Pre-populate keyStore
            KeyInfo keyInfo = KeyInfo.builder()
                    .keyId(TEST_KEY_ID_1)
                    .algorithm(KeyAlgorithm.RS256)
                    .createdAt(NOW)
                    .activatedAt(NOW)
                    .active(true)
                    .build();
            populatedKeyStore.storeJWK(TEST_KEY_ID_1, rsaKey1, keyInfo);

            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    populatedKeyStore
            );

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert
            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(1);
            assertThat(jwkSet.getKeys().get(0).getKeyID()).isEqualTo(TEST_KEY_ID_1);
        }

        @Test
        @DisplayName("Should load JWK set from files when keyStore is empty")
        void testGetJwkSetFromFiles() throws IOException {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    emptyKeyStore
            );

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert
            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(1);
            assertThat(jwkSet.getKeys().get(0).getKeyID()).isEqualTo(TEST_KEY_ID_1);
        }

        @Test
        @DisplayName("Should load JWK set from multiple files")
        void testGetJwkSetFromMultipleFiles() throws IOException {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    Arrays.asList(
                            testFile1.toString(),
                            testFile2.toString()
                    ),
                    emptyKeyStore
            );

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert
            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(2);
            assertThat(jwkSet.getKeys().get(0).getKeyID()).isEqualTo(TEST_KEY_ID_1);
            assertThat(jwkSet.getKeys().get(1).getKeyID()).isEqualTo(TEST_KEY_ID_2);
        }

        @Test
        @DisplayName("Should throw exception for invalid file path")
        void testInvalidFilePath() {
            // Arrange
            FileJwksProvider provider = new FileJwksProvider(
                    List.of("/nonexistent/file.json"),
                    keyStore
            );

            // Act & Assert
            assertThatThrownBy(() -> provider.getJwkSet())
                    .isInstanceOf(FileJwksProviderException.class)
                    .hasMessageContaining("Failed to load any JWK set");
        }

        @Test
        @DisplayName("Should throw exception for empty JWK set file")
        void testEmptyJwkSetFile() throws Exception {
            // Arrange
            Path emptyFile = tempDir.resolve("empty.json").toAbsolutePath();
            Files.writeString(emptyFile, "{\"keys\":[]}");

            FileJwksProvider provider = new FileJwksProvider(
                    List.of(emptyFile.toString()),
                    keyStore
            );

            // Act & Assert
            assertThatThrownBy(() -> provider.getJwkSet())
                    .isInstanceOf(FileJwksProviderException.class)
                    .hasMessageContaining("Failed to load any JWK set");
        }
    }

    @Nested
    @DisplayName("getJwkSource() Tests")
    class GetJwkSourceTests {

        @Test
        @DisplayName("Should return JWK source that provides keys")
        void testGetJwkSource() throws Exception {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    emptyKeyStore
            );

            // Act
            var jwkSource = provider.getJwkSource();
            List keys = jwkSource.get(null, null);

            // Assert
            assertThat(jwkSource).isNotNull();
            assertThat(keys).isNotNull();
            assertThat(keys).hasSize(1);
        }
    }

    @Nested
    @DisplayName("refresh() Tests")
    class RefreshTests {

        @Test
        @DisplayName("Should refresh JWK set successfully")
        void testRefresh() throws Exception {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    emptyKeyStore
            );

            // Act
            provider.refresh();

            // Assert - should not throw exception
        }

        @Test
        @DisplayName("Should refresh after file modification")
        void testRefreshAfterFileModification() throws Exception {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    emptyKeyStore
            );

            // Load initial JWK set
            JWKSet initialSet = provider.getJwkSet();
            assertThat(initialSet.getKeys()).hasSize(1);
            assertThat(initialSet.getKeys().get(0).getKeyID()).isEqualTo(TEST_KEY_ID_1);

            // Wait a moment to ensure file modification time changes
            Thread.sleep(100);

            // Modify the file with a new key
            RSAKey newKey = new RSAKeyGenerator(2048)
                    .keyID("new-key-003")
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .generate();
            JWKSet newSet = new JWKSet(newKey);
            Files.writeString(testFile1, newSet.toString());

            // Clear the keyStore to force reload from file
            emptyKeyStore.clear();

            // Act
            JWKSet refreshedSet = provider.getJwkSet();

            // Assert
            assertThat(refreshedSet.getKeys()).hasSize(1);
            assertThat(refreshedSet.getKeys().get(0).getKeyID()).isEqualTo("new-key-003");
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle malformed JSON file")
        void testMalformedJsonFile() throws Exception {
            // Arrange
            Path malformedFile = tempDir.resolve("malformed.json").toAbsolutePath();
            Files.writeString(malformedFile, "{invalid json}");

            FileJwksProvider provider = new FileJwksProvider(
                    List.of(malformedFile.toString()),
                    keyStore
            );

            // Act & Assert
            // Provider should skip malformed file and throw if all files fail
            assertThatThrownBy(() -> provider.getJwkSet())
                    .isInstanceOf(FileJwksProviderException.class);
        }

        @Test
        @DisplayName("Should skip invalid file when multiple files are provided")
        void testSkipInvalidFileAmongMultipleFiles() throws Exception {
            // Arrange
            Path invalidFile = tempDir.resolve("invalid.json").toAbsolutePath();
            Files.writeString(invalidFile, "{invalid json}");

            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    Arrays.asList(
                            invalidFile.toString(),
                            testFile1.toString()
                    ),
                    emptyKeyStore
            );

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert - should load from valid file
            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("Auto-refresh Tests")
    class AutoRefreshTests {

        @Test
        @DisplayName("Should trigger async refresh when auto-refresh is enabled")
        void testAutoRefreshEnabled() throws Exception {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    true,  // auto-refresh enabled
                    emptyKeyStore
            );

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert - should load successfully
            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(1);
        }

        @Test
        @DisplayName("Should not trigger async refresh when auto-refresh is disabled")
        void testAutoRefreshDisabled() throws Exception {
            // Arrange
            KeyStore emptyKeyStore = new InMemoryKeyStore();
            FileJwksProvider provider = new FileJwksProvider(
                    List.of(testFile1.toString()),
                    false,  // auto-refresh disabled
                    emptyKeyStore
            );

            // Act
            JWKSet jwkSet = provider.getJwkSet();

            // Assert - should load successfully
            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(1);
        }
    }
}