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
package com.alibaba.openagentauth.core.crypto.signature;

import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.exception.crypto.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DefaultSigner}.
 * <p>
 * Tests the signer's behavior including:
 * <ul>
 *   <li>Successful signing with RSA algorithms (RS256, RS384, RS512)</li>
 *   <li>Successful signing with ECDSA algorithms (ES256, ES384, ES512)</li>
 *   <li>Error handling for null parameters</li>
 *   <li>Error handling for empty data</li>
 *   <li>Error handling for key/algorithm mismatch</li>
 *   <li>Getter methods for signing key and algorithm</li>
 * </ul>
 * </p>
 */
@DisplayName("DefaultSigner Tests")
class DefaultSignerTest {

    private KeyPair rsaKeyPair;
    private KeyPair ecKeyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        // Generate RSA key pair
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
        rsaKeyGen.initialize(2048);
        rsaKeyPair = rsaKeyGen.generateKeyPair();

        // Generate EC key pair
        KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
        ecKeyGen.initialize(256);
        ecKeyPair = ecKeyGen.generateKeyPair();
    }

    @Nested
    @DisplayName("RSA Signature Tests")
    class RsaSignatureTests {

        @Test
        @DisplayName("Should sign data successfully with RS256")
        void shouldSignDataSuccessfullyWithRS256() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should sign data successfully with RS384")
        void shouldSignDataSuccessfullyWithRS384() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS384);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should sign data successfully with RS512")
        void shouldSignDataSuccessfullyWithRS512() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS512);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should produce different signatures for different data")
        void shouldProduceDifferentSignaturesForDifferentData() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            byte[] data1 = "data1".getBytes();
            byte[] data2 = "data2".getBytes();

            byte[] signature1 = signer.sign(data1);
            byte[] signature2 = signer.sign(data2);

            assertThat(signature1).isNotEqualTo(signature2);
        }

        @Test
        @DisplayName("Should produce consistent signatures for same data")
        void shouldProduceConsistentSignaturesForSameData() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();

            byte[] signature1 = signer.sign(data);
            byte[] signature2 = signer.sign(data);

            assertThat(signature1).isEqualTo(signature2);
        }
    }

    @Nested
    @DisplayName("ECDSA Signature Tests")
    class EcdsaSignatureTests {

        @Test
        @DisplayName("Should sign data successfully with ES256")
        void shouldSignDataSuccessfullyWithES256() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should sign data successfully with ES384")
        void shouldSignDataSuccessfullyWithES384() throws NoSuchAlgorithmException, SignatureException {
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
            ecKeyGen.initialize(384);
            KeyPair ec384KeyPair = ecKeyGen.generateKeyPair();

            Signer signer = new DefaultSigner(ec384KeyPair.getPrivate(), KeyAlgorithm.ES384);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should sign data successfully with ES512")
        void shouldSignDataSuccessfullyWithES512() throws NoSuchAlgorithmException, SignatureException {
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
            ecKeyGen.initialize(521);
            KeyPair ec521KeyPair = ecKeyGen.generateKeyPair();

            Signer signer = new DefaultSigner(ec521KeyPair.getPrivate(), KeyAlgorithm.ES512);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should produce different signatures for different data")
        void shouldProduceDifferentSignaturesForDifferentData() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);
            byte[] data1 = "data1".getBytes();
            byte[] data2 = "data2".getBytes();

            byte[] signature1 = signer.sign(data1);
            byte[] signature2 = signer.sign(data2);

            assertThat(signature1).isNotEqualTo(signature2);
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when private key is null")
        void shouldThrowExceptionWhenPrivateKeyIsNull() {
            assertThatThrownBy(() -> new DefaultSigner(null, KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Private key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() {
            assertThatThrownBy(() -> new DefaultSigner(rsaKeyPair.getPrivate(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when signing null data")
        void shouldThrowExceptionWhenSigningNullData() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            assertThatThrownBy(() -> signer.sign(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when signing empty data")
        void shouldThrowExceptionWhenSigningEmptyData() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            assertThatThrownBy(() -> signer.sign(new byte[0]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when RSA algorithm is used with EC key")
        void shouldThrowExceptionWhenRsaAlgorithmUsedWithEcKey() {
            assertThatThrownBy(() -> new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Failed to create signer")
                    .hasCauseInstanceOf(com.nimbusds.jose.JOSEException.class);
        }

        @Test
        @DisplayName("Should throw exception when EC algorithm is used with RSA key")
        void shouldThrowExceptionWhenEcAlgorithmUsedWithRsaKey() {
            assertThatThrownBy(() -> new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.ES256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Failed to create signer")
                    .hasCauseInstanceOf(com.nimbusds.jose.JOSEException.class);
        }
    }

    @Nested
    @DisplayName("Getter Methods Tests")
    class GetterMethodsTests {

        @Test
        @DisplayName("Should return correct signing key")
        void shouldReturnCorrectSigningKey() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            assertThat(signer.getSigningKey()).isEqualTo(rsaKeyPair.getPrivate());
        }

        @Test
        @DisplayName("Should return correct algorithm")
        void shouldReturnCorrectAlgorithm() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should return correct algorithm for ECDSA")
        void shouldReturnCorrectAlgorithmForECDSA() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);

            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.ES256);
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should be thread-safe for concurrent signing operations")
        void shouldBeThreadSafeForConcurrentSigningOperations() throws InterruptedException, SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();

            Thread thread1 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        byte[] signature = signer.sign(data);
                        assertThat(signature).isNotNull();
                    }
                } catch (SignatureException e) {
                    throw new RuntimeException(e);
                }
            });

            Thread thread2 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        byte[] signature = signer.sign(data);
                        assertThat(signature).isNotNull();
                    }
                } catch (SignatureException e) {
                    throw new RuntimeException(e);
                }
            });

            thread1.start();
            thread2.start();
            thread1.join();
            thread2.join();
        }
    }
}
