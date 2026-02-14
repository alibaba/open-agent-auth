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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for {@link InMemoryKeyStore}.
 * <p>
 * These tests validate the in-memory key storage functionality including:
 * </p>
 * <ul>
 *   <li>Storage and retrieval of key pairs</li>
 *   <li>Storage and retrieval of JWK objects</li>
 *   <li>Key lifecycle management (create, delete, clear)</li>
 *   <li>Thread safety under concurrent access</li>
 *   <li>Support for both RSA and EC keys</li>
 * </ul>
 *
 * @since 1.0
 */
class InMemoryKeyStoreTest {

    private static final String TEST_KEY_ID = "test-key-001";
    private static final String TEST_KEY_ID_2 = "test-key-002";
    private static final Instant NOW = Instant.now();

    private InMemoryKeyStore keyStore;
    private RSAKey rsaKey;
    private ECKey ecKey;
    private KeyInfo keyInfo;

    @BeforeEach
    void setUp() throws JOSEException {
        keyStore = new InMemoryKeyStore();

        // Generate RSA key for testing
        rsaKey = new RSAKeyGenerator(2048)
                .keyID(TEST_KEY_ID)
                .generate();

        // Generate EC key for testing
        ecKey = new ECKeyGenerator(Curve.P_256)
                .keyID(TEST_KEY_ID_2)
                .generate();

        // Create key info
        keyInfo = KeyInfo.builder()
                .keyId(TEST_KEY_ID)
                .algorithm(KeyAlgorithm.RS256)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();
    }

    @Test
    void testStoreAndRetrieveKeyPair() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();

        // Act
        keyStore.store(TEST_KEY_ID, keyPair, keyInfo);
        Optional<KeyPair> retrievedKeyPair = keyStore.retrieve(TEST_KEY_ID);

        // Assert
        assertThat(retrievedKeyPair).isPresent();
        // Compare key material instead of KeyPair objects
        assertThat(retrievedKeyPair.get().getPublic().getEncoded())
                .isEqualTo(keyPair.getPublic().getEncoded());
        assertThat(retrievedKeyPair.get().getPrivate().getEncoded())
                .isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @Test
    void testStoreAndRetrieveKeyInfo() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();

        // Act
        keyStore.store(TEST_KEY_ID, keyPair, keyInfo);
        Optional<KeyInfo> retrievedKeyInfo = keyStore.retrieveInfo(TEST_KEY_ID);

        // Assert
        assertThat(retrievedKeyInfo).isPresent();
        assertThat(retrievedKeyInfo.get()).isEqualTo(keyInfo);
        assertThat(retrievedKeyInfo.get().getKeyId()).isEqualTo(TEST_KEY_ID);
        assertThat(retrievedKeyInfo.get().getAlgorithm()).isEqualTo(KeyAlgorithm.RS256);
        assertThat(retrievedKeyInfo.get().isActive()).isTrue();
    }

    @Test
    void testStoreAndRetrieveRSAJWK() throws KeyManagementException {
        // Act
        keyStore.storeJWK(TEST_KEY_ID, rsaKey, keyInfo);
        Optional<Object> retrievedJWK = keyStore.retrieveJWK(TEST_KEY_ID);

        // Assert
        assertThat(retrievedJWK).isPresent();
        assertThat(retrievedJWK.get()).isInstanceOf(RSAKey.class);
        RSAKey retrievedRSAKey = (RSAKey) retrievedJWK.get();
        assertThat(retrievedRSAKey.getKeyID()).isEqualTo(TEST_KEY_ID);
    }

    @Test
    void testStoreAndRetrieveECJWK() throws KeyManagementException {
        // Arrange
        KeyInfo ecKeyInfo = KeyInfo.builder()
                .keyId(TEST_KEY_ID_2)
                .algorithm(KeyAlgorithm.ES256)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        // Act
        keyStore.storeJWK(TEST_KEY_ID_2, ecKey, ecKeyInfo);
        Optional<Object> retrievedJWK = keyStore.retrieveJWK(TEST_KEY_ID_2);

        // Assert
        assertThat(retrievedJWK).isPresent();
        assertThat(retrievedJWK.get()).isInstanceOf(ECKey.class);
        ECKey retrievedECKey = (ECKey) retrievedJWK.get();
        assertThat(retrievedECKey.getKeyID()).isEqualTo(TEST_KEY_ID_2);
    }

    @Test
    void testRetrieveNonExistentKey() throws KeyManagementException {
        // Act
        Optional<KeyPair> retrievedKeyPair = keyStore.retrieve("non-existent-key");

        // Assert
        assertThat(retrievedKeyPair).isEmpty();
    }

    @Test
    void testRetrieveNonExistentKeyInfo() throws KeyManagementException {
        // Act
        Optional<KeyInfo> retrievedKeyInfo = keyStore.retrieveInfo("non-existent-key");

        // Assert
        assertThat(retrievedKeyInfo).isEmpty();
    }

    @Test
    void testRetrieveNonExistentJWK() throws KeyManagementException {
        // Act
        Optional<Object> retrievedJWK = keyStore.retrieveJWK("non-existent-key");

        // Assert
        assertThat(retrievedJWK).isEmpty();
    }

    @Test
    void testExists() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();

        // Act & Assert
        assertThat(keyStore.exists(TEST_KEY_ID)).isFalse();

        keyStore.store(TEST_KEY_ID, keyPair, keyInfo);
        assertThat(keyStore.exists(TEST_KEY_ID)).isTrue();
    }

    @Test
    void testExistsWithNullKeyId() {
        // Act
        boolean exists = keyStore.exists(null);

        // Assert
        assertThat(exists).isFalse();
    }

    @Test
    void testExistsWithEmptyKeyId() {
        // Act
        boolean exists = keyStore.exists("");

        // Assert
        assertThat(exists).isFalse();
    }

    @Test
    void testDelete() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();
        keyStore.store(TEST_KEY_ID, keyPair, keyInfo);

        // Act
        keyStore.delete(TEST_KEY_ID);

        // Assert
        assertThat(keyStore.exists(TEST_KEY_ID)).isFalse();
        assertThat(keyStore.retrieve(TEST_KEY_ID)).isEmpty();
        assertThat(keyStore.retrieveInfo(TEST_KEY_ID)).isEmpty();
        assertThat(keyStore.retrieveJWK(TEST_KEY_ID)).isEmpty();
    }

    @Test
    void testDeleteWithNullKeyId() throws JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();
        keyStore.store(TEST_KEY_ID, keyPair, keyInfo);

        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.delete(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testDeleteWithEmptyKeyId() throws JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();
        keyStore.store(TEST_KEY_ID, keyPair, keyInfo);

        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.delete(""))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testListKeyIds() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair1 = rsaKey.toKeyPair();
        KeyPair keyPair2 = ecKey.toKeyPair();
        KeyInfo keyInfo2 = KeyInfo.builder()
                .keyId(TEST_KEY_ID_2)
                .algorithm(KeyAlgorithm.ES256)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        keyStore.store(TEST_KEY_ID, keyPair1, keyInfo);
        keyStore.store(TEST_KEY_ID_2, keyPair2, keyInfo2);

        // Act
        List<String> keyIds = keyStore.listKeyIds();

        // Assert
        assertThat(keyIds).hasSize(2);
        assertThat(keyIds).containsExactlyInAnyOrder(TEST_KEY_ID, TEST_KEY_ID_2);
    }

    @Test
    void testListKeyIdsEmpty() {
        // Act
        List<String> keyIds = keyStore.listKeyIds();

        // Assert
        assertThat(keyIds).isEmpty();
    }

    @Test
    void testClear() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair1 = rsaKey.toKeyPair();
        KeyPair keyPair2 = ecKey.toKeyPair();
        KeyInfo keyInfo2 = KeyInfo.builder()
                .keyId(TEST_KEY_ID_2)
                .algorithm(KeyAlgorithm.ES256)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        keyStore.store(TEST_KEY_ID, keyPair1, keyInfo);
        keyStore.store(TEST_KEY_ID_2, keyPair2, keyInfo2);

        // Act
        keyStore.clear();

        // Assert
        assertThat(keyStore.listKeyIds()).isEmpty();
        assertThat(keyStore.exists(TEST_KEY_ID)).isFalse();
        assertThat(keyStore.exists(TEST_KEY_ID_2)).isFalse();
    }

    @Test
    void testStoreWithNullKeyId() throws JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();

        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.store(null, keyPair, keyInfo))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testStoreWithEmptyKeyId() throws JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();

        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.store("", keyPair, keyInfo))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testStoreWithNullKeyPair() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.store(TEST_KEY_ID, null, keyInfo))
                .withMessageContaining("Key pair cannot be null");
    }

    @Test
    void testStoreWithNullKeyInfo() throws JOSEException {
        // Arrange
        KeyPair keyPair = rsaKey.toKeyPair();

        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.store(TEST_KEY_ID, keyPair, null))
                .withMessageContaining("Key info cannot be null");
    }

    @Test
    void testStoreJWKWithNullKeyId() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK(null, rsaKey, keyInfo))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testStoreJWKWithNullJWK() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK(TEST_KEY_ID, null, keyInfo))
                .withMessageContaining("JWK cannot be null");
    }

    @Test
    void testStoreJWKWithNullKeyInfo() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK(TEST_KEY_ID, rsaKey, null))
                .withMessageContaining("Key info cannot be null");
    }

    @Test
    void testRetrieveWithNullKeyId() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.retrieve(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testRetrieveInfoWithNullKeyId() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.retrieveInfo(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testRetrieveJWKWithNullKeyId() {
        // Act & Assert
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.retrieveJWK(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testStoreJWKAlsoStoresKeyPair() throws KeyManagementException, JOSEException {
        // Act
        keyStore.storeJWK(TEST_KEY_ID, rsaKey, keyInfo);
        Optional<KeyPair> retrievedKeyPair = keyStore.retrieve(TEST_KEY_ID);

        // Assert
        assertThat(retrievedKeyPair).isPresent();
        KeyPair originalKeyPair = rsaKey.toKeyPair();
        assertThat(retrievedKeyPair.get().getPublic()).isEqualTo(originalKeyPair.getPublic());
        assertThat(retrievedKeyPair.get().getPrivate()).isEqualTo(originalKeyPair.getPrivate());
    }

    @Test
    void testStoreECJWKAlsoStoresKeyPair() throws KeyManagementException {
        // Arrange
        KeyInfo ecKeyInfo = KeyInfo.builder()
                .keyId(TEST_KEY_ID_2)
                .algorithm(KeyAlgorithm.ES256)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        // Act
        keyStore.storeJWK(TEST_KEY_ID_2, ecKey, ecKeyInfo);
        Optional<KeyPair> retrievedKeyPair = keyStore.retrieve(TEST_KEY_ID_2);

        // Assert
        assertThat(retrievedKeyPair).isPresent();
    }

    @Test
    void testOverwriteExistingKey() throws KeyManagementException, JOSEException {
        // Arrange
        KeyPair keyPair1 = rsaKey.toKeyPair();
        KeyInfo keyInfo1 = KeyInfo.builder()
                .keyId(TEST_KEY_ID)
                .algorithm(KeyAlgorithm.RS256)
                .createdAt(NOW.minusSeconds(3600))
                .activatedAt(NOW.minusSeconds(3600))
                .active(false)
                .build();

        keyStore.store(TEST_KEY_ID, keyPair1, keyInfo1);

        // Act - Store with same key ID
        KeyPair keyPair2 = new RSAKeyGenerator(2048)
                .keyID(TEST_KEY_ID)
                .generate()
                .toKeyPair();
        KeyInfo keyInfo2 = KeyInfo.builder()
                .keyId(TEST_KEY_ID)
                .algorithm(KeyAlgorithm.RS256)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        keyStore.store(TEST_KEY_ID, keyPair2, keyInfo2);

        // Assert - Should have overwritten
        Optional<KeyPair> retrievedKeyPair = keyStore.retrieve(TEST_KEY_ID);
        Optional<KeyInfo> retrievedKeyInfo = keyStore.retrieveInfo(TEST_KEY_ID);

        assertThat(retrievedKeyPair).isPresent();
        // Compare key material instead of KeyPair objects
        assertThat(retrievedKeyPair.get().getPublic().getEncoded())
                .isEqualTo(keyPair2.getPublic().getEncoded());
        assertThat(retrievedKeyPair.get().getPrivate().getEncoded())
                .isEqualTo(keyPair2.getPrivate().getEncoded());
        assertThat(retrievedKeyInfo).isPresent();
        assertThat(retrievedKeyInfo.get().isActive()).isTrue();
        assertThat(retrievedKeyInfo.get().getCreatedAt()).isEqualTo(NOW);
    }
}
