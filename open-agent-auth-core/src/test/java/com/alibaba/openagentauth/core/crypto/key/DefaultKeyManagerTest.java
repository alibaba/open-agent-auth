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
import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for DefaultKeyManager.
 * <p>
 * This test class verifies the functionality of the DefaultKeyManager implementation,
 * including key generation, retrieval, rotation, deletion, and thread safety.
 * </p>
 */
@DisplayName("DefaultKeyManager Tests")
class DefaultKeyManagerTest {

    private KeyManager keyManager;

    /**
     * Sets up the test environment before each test.
     */
    @BeforeEach
    void setUp() {
        keyManager = new DefaultKeyManager(new InMemoryKeyStore());
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when KeyStore is null")
        void shouldThrowExceptionWhenKeyStoreIsNull() {
            assertThatThrownBy(() -> new DefaultKeyManager(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("KeyStore cannot be null");
        }
    }

    @Nested
    @DisplayName("Key Generation Tests")
    class KeyGenerationTests {

        @Test
        @DisplayName("Should generate RSA key pair with RS256 algorithm")
        void shouldGenerateRsaKeyPairWithRS256Algorithm() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-001");

            assertThat(keyPair).isNotNull();
            assertThat(keyPair.getPrivate()).isNotNull();
            assertThat(keyPair.getPublic()).isNotNull();
            assertThat(keyManager.hasKey("test-key-001")).isTrue();
        }

        @Test
        @DisplayName("Should generate RSA key pair with RS384 algorithm")
        void shouldGenerateRsaKeyPairWithRS384Algorithm() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.RS384, "test-key-002");

            assertThat(keyPair).isNotNull();
            assertThat(keyPair.getPrivate()).isNotNull();
            assertThat(keyPair.getPublic()).isNotNull();
            assertThat(keyManager.hasKey("test-key-002")).isTrue();
        }

        @Test
        @DisplayName("Should generate RSA key pair with RS512 algorithm")
        void shouldGenerateRsaKeyPairWithRS512Algorithm() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.RS512, "test-key-003");

            assertThat(keyPair).isNotNull();
            assertThat(keyPair.getPrivate()).isNotNull();
            assertThat(keyPair.getPublic()).isNotNull();
            assertThat(keyManager.hasKey("test-key-003")).isTrue();
        }

        @Test
        @DisplayName("Should generate ECDSA key pair with ES256 algorithm")
        void shouldGenerateEcdsaKeyPairWithES256Algorithm() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.ES256, "test-key-004");

            assertThat(keyPair).isNotNull();
            assertThat(keyPair.getPrivate()).isNotNull();
            assertThat(keyPair.getPublic()).isNotNull();
            assertThat(keyManager.hasKey("test-key-004")).isTrue();
        }

        @Test
        @DisplayName("Should generate ECDSA key pair with ES384 algorithm")
        void shouldGenerateEcdsaKeyPairWithES384Algorithm() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.ES384, "test-key-005");

            assertThat(keyPair).isNotNull();
            assertThat(keyPair.getPrivate()).isNotNull();
            assertThat(keyPair.getPublic()).isNotNull();
            assertThat(keyManager.hasKey("test-key-005")).isTrue();
        }

        @Test
        @DisplayName("Should generate ECDSA key pair with ES512 algorithm")
        void shouldGenerateEcdsaKeyPairWithES512Algorithm() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.ES512, "test-key-006");

            assertThat(keyPair).isNotNull();
            assertThat(keyPair.getPrivate()).isNotNull();
            assertThat(keyPair.getPublic()).isNotNull();
            assertThat(keyManager.hasKey("test-key-006")).isTrue();
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() {
            assertThatThrownBy(() -> keyManager.generateKeyPair(null, "test-key-007"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Algorithm cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null")
        void shouldThrowExceptionWhenKeyIdIsNull() {
            assertThatThrownBy(() -> keyManager.generateKeyPair(KeyAlgorithm.RS256, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty")
        void shouldThrowExceptionWhenKeyIdIsEmpty() {
            assertThatThrownBy(() -> keyManager.generateKeyPair(KeyAlgorithm.RS256, ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is whitespace")
        void shouldThrowExceptionWhenKeyIdIsWhitespace() {
            assertThatThrownBy(() -> keyManager.generateKeyPair(KeyAlgorithm.RS256, "   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId already exists")
        void shouldThrowExceptionWhenKeyIdAlreadyExists() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-008");

            assertThatThrownBy(() -> keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-008"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("already exists");
        }
    }

    @Nested
    @DisplayName("Key Retrieval Tests")
    class KeyRetrievalTests {

        @Test
        @DisplayName("Should retrieve signing key successfully")
        void shouldRetrieveSigningKeySuccessfully() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-009");
            PrivateKey signingKey = keyManager.getSigningKey("test-key-009");

            assertThat(signingKey).isNotNull();
            assertThat(signingKey).isEqualTo(keyPair.getPrivate());
        }

        @Test
        @DisplayName("Should retrieve verification key successfully")
        void shouldRetrieveVerificationKeySuccessfully() throws KeyManagementException {
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-010");
            PublicKey verificationKey = keyManager.getVerificationKey("test-key-010");

            assertThat(verificationKey).isNotNull();
            assertThat(verificationKey).isEqualTo(keyPair.getPublic());
        }

        @Test
        @DisplayName("Should throw exception when signing key not found")
        void shouldThrowExceptionWhenSigningKeyNotFound() {
            assertThatThrownBy(() -> keyManager.getSigningKey("non-existent-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key not found");
        }

        @Test
        @DisplayName("Should throw exception when verification key not found")
        void shouldThrowExceptionWhenVerificationKeyNotFound() {
            assertThatThrownBy(() -> keyManager.getVerificationKey("non-existent-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key not found");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for signing key")
        void shouldThrowExceptionWhenKeyIdIsNullForSigningKey() {
            assertThatThrownBy(() -> keyManager.getSigningKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for verification key")
        void shouldThrowExceptionWhenKeyIdIsNullForVerificationKey() {
            assertThatThrownBy(() -> keyManager.getVerificationKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should retrieve RSA signing JWK successfully")
        void shouldRetrieveRsaSigningJwkSuccessfully() throws KeyManagementException, com.nimbusds.jose.JOSEException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-jwk-rsa-key");
            Object jwk = keyManager.getSigningJWK("test-jwk-rsa-key");

            assertThat(jwk).isNotNull();
            assertThat(jwk).isInstanceOf(RSAKey.class);
            RSAKey rsaKey = (RSAKey) jwk;
            assertThat(rsaKey.getKeyID()).isEqualTo("test-jwk-rsa-key");
            assertThat(rsaKey.toPrivateKey()).isNotNull();
            assertThat(rsaKey.toPublicKey()).isNotNull();
        }

        @Test
        @DisplayName("Should retrieve EC signing JWK successfully")
        void shouldRetrieveEcSigningJwkSuccessfully() throws KeyManagementException, com.nimbusds.jose.JOSEException {
            keyManager.generateKeyPair(KeyAlgorithm.ES256, "test-jwk-ec-key");
            Object jwk = keyManager.getSigningJWK("test-jwk-ec-key");

            assertThat(jwk).isNotNull();
            assertThat(jwk).isInstanceOf(ECKey.class);
            ECKey ecKey = (ECKey) jwk;
            assertThat(ecKey.getKeyID()).isEqualTo("test-jwk-ec-key");
            assertThat(ecKey.toPrivateKey()).isNotNull();
            assertThat(ecKey.toPublicKey()).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when JWK not found")
        void shouldThrowExceptionWhenJwkNotFound() {
            assertThatThrownBy(() -> keyManager.getSigningJWK("non-existent-jwk-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("JWK not found");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for signing JWK")
        void shouldThrowExceptionWhenKeyIdIsNullForSigningJwk() {
            assertThatThrownBy(() -> keyManager.getSigningJWK(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for signing JWK")
        void shouldThrowExceptionWhenKeyIdIsEmptyForSigningJwk() {
            assertThatThrownBy(() -> keyManager.getSigningJWK(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is whitespace for signing JWK")
        void shouldThrowExceptionWhenKeyIdIsWhitespaceForSigningJwk() {
            assertThatThrownBy(() -> keyManager.getSigningJWK("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Key Rotation Tests")
    class KeyRotationTests {

        @Test
        @DisplayName("Should rotate key successfully")
        void shouldRotateKeySuccessfully() throws KeyManagementException {
            KeyPair oldKeyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-011");
            
            keyManager.rotateKey("test-key-011");
            
            KeyPair newKeyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-011-rotated");
            PrivateKey newSigningKey = keyManager.getSigningKey("test-key-011");
            
            assertThat(newSigningKey).isNotNull();
            assertThat(newSigningKey).isNotEqualTo(oldKeyPair.getPrivate());
        }

        @Test
        @DisplayName("Should throw exception when rotating non-existent key")
        void shouldThrowExceptionWhenRotatingNonExistentKey() {
            assertThatThrownBy(() -> keyManager.rotateKey("non-existent-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key not found for rotation");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for rotation")
        void shouldThrowExceptionWhenKeyIdIsNullForRotation() {
            assertThatThrownBy(() -> keyManager.rotateKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for rotation")
        void shouldThrowExceptionWhenKeyIdIsEmptyForRotation() {
            assertThatThrownBy(() -> keyManager.rotateKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Key Deletion Tests")
    class KeyDeletionTests {

        @Test
        @DisplayName("Should delete key successfully")
        void shouldDeleteKeySuccessfully() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-012");
            assertThat(keyManager.hasKey("test-key-012")).isTrue();

            keyManager.deleteKey("test-key-012");
            assertThat(keyManager.hasKey("test-key-012")).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when deleting non-existent key")
        void shouldThrowExceptionWhenDeletingNonExistentKey() {
            assertThatThrownBy(() -> keyManager.deleteKey("non-existent-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key not found for deletion");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for deletion")
        void shouldThrowExceptionWhenKeyIdIsNullForDeletion() {
            assertThatThrownBy(() -> keyManager.deleteKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for deletion")
        void shouldThrowExceptionWhenKeyIdIsEmptyForDeletion() {
            assertThatThrownBy(() -> keyManager.deleteKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Key Existence Tests")
    class KeyExistenceTests {

        @Test
        @DisplayName("Should return true when key exists")
        void shouldReturnTrueWhenKeyExists() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-013");

            assertThat(keyManager.hasKey("test-key-013")).isTrue();
        }

        @Test
        @DisplayName("Should return false when key does not exist")
        void shouldReturnFalseWhenKeyDoesNotExist() {
            assertThat(keyManager.hasKey("non-existent-key")).isFalse();
        }

        @Test
        @DisplayName("Should return false when keyId is null")
        void shouldReturnFalseWhenKeyIdIsNull() {
            assertThat(keyManager.hasKey(null)).isFalse();
        }

        @Test
        @DisplayName("Should return false when keyId is empty")
        void shouldReturnFalseWhenKeyIdIsEmpty() {
            assertThat(keyManager.hasKey("")).isFalse();
        }

        @Test
        @DisplayName("Should return false when keyId is whitespace")
        void shouldReturnFalseWhenKeyIdIsWhitespace() {
            assertThat(keyManager.hasKey("   ")).isFalse();
        }
    }

    @Nested
    @DisplayName("Active Keys Tests")
    class ActiveKeysTests {

        @Test
        @DisplayName("Should return list of active keys")
        void shouldReturnListOfActiveKeys() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "test-key-014");
            keyManager.generateKeyPair(KeyAlgorithm.ES256, "test-key-015");
            keyManager.generateKeyPair(KeyAlgorithm.RS384, "test-key-016");

            List<KeyInfo> activeKeys = keyManager.getActiveKeys();

            assertThat(activeKeys).isNotNull();
            assertThat(activeKeys).hasSize(3);
            assertThat(activeKeys).allMatch(KeyInfo::isActive);
        }

        @Test
        @DisplayName("Should return empty list when no keys exist")
        void shouldReturnEmptyListWhenNoKeysExist() {
            List<KeyInfo> activeKeys = keyManager.getActiveKeys();

            assertThat(activeKeys).isNotNull();
            assertThat(activeKeys).isEmpty();
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent key generation")
        void shouldHandleConcurrentKeyGeneration() throws InterruptedException {
            int threadCount = 10;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        keyManager.generateKeyPair(KeyAlgorithm.RS256, "concurrent-key-" + index);
                        successCount.incrementAndGet();
                    } catch (KeyManagementException e) {
                        // Expected for duplicate key IDs
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isGreaterThanOrEqualTo(threadCount - 5);
            
            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent key retrieval")
        void shouldHandleConcurrentKeyRetrieval() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "concurrent-retrieve-key");
            
            int threadCount = 20;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executorService.submit(() -> {
                    try {
                        keyManager.getSigningKey("concurrent-retrieve-key");
                        successCount.incrementAndGet();
                    } catch (KeyManagementException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isEqualTo(threadCount);
            
            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full key lifecycle")
        void shouldCompleteFullKeyLifecycle() throws KeyManagementException {
            // Generate key
            KeyPair keyPair = keyManager.generateKeyPair(KeyAlgorithm.RS256, "lifecycle-key");
            assertThat(keyPair).isNotNull();
            assertThat(keyManager.hasKey("lifecycle-key")).isTrue();

            // Retrieve signing key
            PrivateKey signingKey = keyManager.getSigningKey("lifecycle-key");
            assertThat(signingKey).isEqualTo(keyPair.getPrivate());

            // Retrieve verification key
            PublicKey verificationKey = keyManager.getVerificationKey("lifecycle-key");
            assertThat(verificationKey).isEqualTo(keyPair.getPublic());

            // Get active keys
            List<KeyInfo> activeKeys = keyManager.getActiveKeys();
            assertThat(activeKeys).hasSize(1);

            // Delete key
            keyManager.deleteKey("lifecycle-key");
            assertThat(keyManager.hasKey("lifecycle-key")).isFalse();
        }

        @Test
        @DisplayName("Should handle multiple keys with different algorithms")
        void shouldHandleMultipleKeysWithDifferentAlgorithms() throws KeyManagementException {
            keyManager.generateKeyPair(KeyAlgorithm.RS256, "multi-key-1");
            keyManager.generateKeyPair(KeyAlgorithm.RS384, "multi-key-2");
            keyManager.generateKeyPair(KeyAlgorithm.RS512, "multi-key-3");
            keyManager.generateKeyPair(KeyAlgorithm.ES256, "multi-key-4");
            keyManager.generateKeyPair(KeyAlgorithm.ES384, "multi-key-5");
            keyManager.generateKeyPair(KeyAlgorithm.ES512, "multi-key-6");

            List<KeyInfo> activeKeys = keyManager.getActiveKeys();
            assertThat(activeKeys).hasSize(6);

            for (KeyInfo keyInfo : activeKeys) {
                assertThat(keyInfo.isActive()).isTrue();
                assertThat(keyInfo.getCreatedAt()).isNotNull();
                assertThat(keyInfo.getActivatedAt()).isNotNull();
            }
        }
    }

    @Nested
    @DisplayName("ResolveKey Tests")
    class ResolveKeyTests {

        @Test
        @DisplayName("Should fallback to getSigningJWK when no resolver chain exists")
        void shouldFallbackToGetSigningJWKWhenNoResolverChainExists() throws KeyManagementException, com.nimbusds.jose.JOSEException {
            KeyManager singleParamManager = new DefaultKeyManager(new InMemoryKeyStore());
            singleParamManager.generateKeyPair(KeyAlgorithm.RS256, "fallback-test-key");
            
            Object resolvedKey = singleParamManager.resolveKey("fallback-test-key");
            
            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(JWK.class);
            JWK jwk = (JWK) resolvedKey;
            assertThat(jwk.getKeyID()).isEqualTo("fallback-test-key");
        }

        @Test
        @DisplayName("Should resolve local key through resolver chain")
        void shouldResolveLocalKeyThroughResolverChain() throws KeyManagementException, com.nimbusds.jose.JOSEException {
            Map<String, KeyDefinition> keyDefinitions = new HashMap<>();
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("local-resolver-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .provider("local")
                    .build();
            keyDefinitions.put("local-verification", keyDefinition);
            
            KeyManager threeParamManager = new DefaultKeyManager(
                new InMemoryKeyStore(),
                Collections.emptyList(),
                keyDefinitions
            );
            
            threeParamManager.generateKeyPair(KeyAlgorithm.RS256, "local-resolver-key");
            
            Object resolvedKey = threeParamManager.resolveKey("local-resolver-key");
            
            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(JWK.class);
            JWK jwk = (JWK) resolvedKey;
            assertThat(jwk.getKeyID()).isEqualTo("local-resolver-key");
        }

        @Test
        @DisplayName("Should find KeyDefinition by keyId field")
        void shouldFindKeyDefinitionByKeyIdField() throws KeyManagementException, com.nimbusds.jose.JOSEException {
            Map<String, KeyDefinition> keyDefinitions = new HashMap<>();
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("wit-signing-key")
                    .algorithm(KeyAlgorithm.RS256)
                    .provider("local")
                    .build();
            keyDefinitions.put("wit-verification", keyDefinition);
            
            KeyManager manager = new DefaultKeyManager(
                new InMemoryKeyStore(),
                Collections.emptyList(),
                keyDefinitions
            );
            
            manager.generateKeyPair(KeyAlgorithm.RS256, "wit-signing-key");
            
            Object resolvedKey = manager.resolveKey("wit-signing-key");
            
            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(JWK.class);
            JWK jwk = (JWK) resolvedKey;
            assertThat(jwk.getKeyID()).isEqualTo("wit-signing-key");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is null")
        void shouldThrowIllegalArgumentExceptionWhenKeyIdIsNull() {
            KeyManager manager = new DefaultKeyManager(new InMemoryKeyStore());
            
            assertThatThrownBy(() -> manager.resolveKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is empty")
        void shouldThrowIllegalArgumentExceptionWhenKeyIdIsEmpty() {
            KeyManager manager = new DefaultKeyManager(new InMemoryKeyStore());
            
            assertThatThrownBy(() -> manager.resolveKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should not throw exception with null parameters in three-parameter constructor")
        void shouldNotThrowExceptionWithNullParametersInThreeParameterConstructor() {
            assertThatCode(() -> new DefaultKeyManager(
                new InMemoryKeyStore(),
                null,
                null
            )).doesNotThrowAnyException();
        }
    }
}
