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
package com.alibaba.openagentauth.core.crypto.jwe;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for NimbusJweEncoder.
 */
class NimbusJweEncoderTest {

    private RSAKey rsaPublicKey;
    private ECKey ecPublicKey;
    private OctetSequenceKey symmetricKey;
    private NimbusJweEncoder rsaEncoder;
    private NimbusJweEncoder ecEncoder;
    private NimbusJweEncoder dirEncoder;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate RSA key pair
        rsaPublicKey = new RSAKeyGenerator(2048)
                .keyID("rsa-key-001")
                .generate()
                .toPublicJWK();

        // Generate EC key pair
        ecPublicKey = new ECKeyGenerator(Curve.P_256)
                .keyID("ec-key-001")
                .generate()
                .toPublicJWK();

        // Generate symmetric key
        symmetricKey = new OctetSequenceKeyGenerator(256)
                .keyID("symmetric-key-001")
                .generate();

        // Create encoders
        rsaEncoder = new NimbusJweEncoder(rsaPublicKey, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        ecEncoder = new NimbusJweEncoder(ecPublicKey, JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM);
        dirEncoder = new NimbusJweEncoder(symmetricKey, JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
    }

    @Test
    @DisplayName("Should encrypt string with RSA-OAEP-256")
    void testEncryptString_WithRsaOaep256_ShouldSucceed() throws JOSEException {
        // Arrange
        String plaintext = "test data";

        // Act
        String encrypted = rsaEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        assertTrue(encrypted.contains("."));
    }

    @Test
    @DisplayName("Should encrypt bytes with RSA-OAEP-256")
    void testEncryptBytes_WithRsaOaep256_ShouldSucceed() throws JOSEException {
        // Arrange
        byte[] plaintext = "test data".getBytes();

        // Act
        String encrypted = rsaEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertTrue(encrypted.contains("."));
    }

    @Test
    @DisplayName("Should encrypt string with ECDH-ES")
    void testEncryptString_WithEcdhEs_ShouldSucceed() throws JOSEException {
        // Arrange
        String plaintext = "test data";

        // Act
        String encrypted = ecEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        assertTrue(encrypted.contains("."));
    }

    @Test
    @DisplayName("Should encrypt string with DIR algorithm")
    void testEncryptString_WithDirAlgorithm_ShouldSucceed() throws JOSEException {
        // Arrange
        String plaintext = "test data";

        // Act
        String encrypted = dirEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        assertTrue(encrypted.contains("."));
    }

    @Test
    @DisplayName("Should throw exception when plaintext string is null")
    void testEncryptString_WhenNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> rsaEncoder.encrypt((String) null));
    }

    @Test
    @DisplayName("Should throw exception when plaintext bytes is null")
    void testEncryptBytes_WhenNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> rsaEncoder.encrypt((byte[]) null));
    }

    @Test
    @DisplayName("Should throw exception when encryption JWK is null")
    void testConstructor_WhenJwkIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, 
                () -> new NimbusJweEncoder(null, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM));
    }

    @Test
    @DisplayName("Should throw exception when JWE algorithm is null")
    void testConstructor_WhenAlgorithmIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, 
                () -> new NimbusJweEncoder(rsaPublicKey, null, EncryptionMethod.A256GCM));
    }

    @Test
    @DisplayName("Should throw exception when encryption method is null")
    void testConstructor_WhenMethodIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, 
                () -> new NimbusJweEncoder(rsaPublicKey, JWEAlgorithm.RSA_OAEP_256, null));
    }

    @Test
    @DisplayName("Should throw exception when using OctetSequenceKey with non-DIR algorithm")
    void testConstructor_WhenOctetSequenceKeyWithNonDirAlgorithm_ShouldThrowException() {
        // Act & Assert
        assertThrows(JOSEException.class, 
                () -> new NimbusJweEncoder(symmetricKey, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).encrypt("test"));
    }

    @Test
    @DisplayName("Should throw exception for unsupported key type")
    void testEncrypt_WhenUnsupportedKeyType_ShouldThrowException() {
        // Arrange
        JWK mockJwk = mock(JWK.class);
        when(mockJwk.getKeyType()).thenReturn(KeyType.parse("unsupported"));
        NimbusJweEncoder encoder = new NimbusJweEncoder(mockJwk, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);

        // Act & Assert
        assertThrows(JOSEException.class, () -> encoder.encrypt("test"));
    }

    @Test
    @DisplayName("Should produce different ciphertext for same plaintext")
    void testEncrypt_SamePlaintext_ShouldProduceDifferentCiphertext() throws JOSEException {
        // Arrange
        String plaintext = "test data";

        // Act
        String encrypted1 = rsaEncoder.encrypt(plaintext);
        String encrypted2 = rsaEncoder.encrypt(plaintext);

        // Assert
        assertNotEquals(encrypted1, encrypted2, "Same plaintext should produce different ciphertext due to random IV");
    }

    @Test
    @DisplayName("Should handle empty string")
    void testEncrypt_WhenEmptyString_ShouldSucceed() throws JOSEException {
        // Arrange
        String plaintext = "";

        // Act
        String encrypted = rsaEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertTrue(encrypted.contains("."));
    }

    @Test
    @DisplayName("Should handle special characters")
    void testEncrypt_WhenSpecialCharacters_ShouldSucceed() throws JOSEException {
        // Arrange
        String plaintext = "测试数据 ñ 中文 🎉";

        // Act
        String encrypted = rsaEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertTrue(encrypted.contains("."));
    }

    @Test
    @DisplayName("Should handle large data")
    void testEncrypt_WhenLargeData_ShouldSucceed() throws JOSEException {
        // Arrange
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("test data ");
        }
        String plaintext = sb.toString();

        // Act
        String encrypted = rsaEncoder.encrypt(plaintext);

        // Assert
        assertNotNull(encrypted);
        assertTrue(encrypted.contains("."));
    }
}
