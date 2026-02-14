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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link DefaultVerifier}.
 * <p>
 * Tests the verifier's behavior including:
 * <ul>
 *   <li>Successful verification with RSA algorithms (RS256, RS384, RS512)</li>
 *   <li>Successful verification with ECDSA algorithms (ES256, ES384, ES512)</li>
 *   <li>Failed verification with invalid signatures</li>
 *   <li>Error handling for null parameters</li>
 *   <li>Error handling for empty data and signatures</li>
 *   <li>Error handling for key/algorithm mismatch</li>
 *   <li>Getter methods for verification key and algorithm</li>
 *   <li>Integration with Signer for end-to-end testing</li>
 * </ul>
 * </p>
 */
@DisplayName("DefaultVerifier Tests")
class DefaultVerifierTest {

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
    @DisplayName("RSA Verification Tests")
    class RsaVerificationTests {

        @Test
        @DisplayName("Should verify valid signature with RS256")
        void shouldVerifyValidSignatureWithRS256() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should verify valid signature with RS384")
        void shouldVerifyValidSignatureWithRS384() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS384);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS384);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should verify valid signature with RS512")
        void shouldVerifyValidSignatureWithRS512() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS512);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS512);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should reject invalid signature")
        void shouldRejectInvalidSignature() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            // Modify the signature to make it invalid
            signature[0] ^= 0xFF;

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should reject signature for different data")
        void shouldRejectSignatureForDifferentData() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data1 = "data1".getBytes();
            byte[] data2 = "data2".getBytes();
            byte[] signature = signer.sign(data1);

            boolean isValid = verifier.verify(data2, signature);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should reject signature from different key")
        void shouldRejectSignatureFromDifferentKey() throws NoSuchAlgorithmException, SignatureException {
            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyGen.initialize(2048);
            KeyPair otherKeyPair = rsaKeyGen.generateKeyPair();

            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(otherKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isFalse();
        }
    }

    @Nested
    @DisplayName("ECDSA Verification Tests")
    class EcdsaVerificationTests {

        @Test
        @DisplayName("Should verify valid signature with ES256")
        void shouldVerifyValidSignatureWithES256() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);
            Verifier verifier = new DefaultVerifier(ecKeyPair.getPublic(), KeyAlgorithm.ES256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should verify valid signature with ES384")
        void shouldVerifyValidSignatureWithES384() throws NoSuchAlgorithmException, SignatureException {
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
            ecKeyGen.initialize(384);
            KeyPair ec384KeyPair = ecKeyGen.generateKeyPair();

            Signer signer = new DefaultSigner(ec384KeyPair.getPrivate(), KeyAlgorithm.ES384);
            Verifier verifier = new DefaultVerifier(ec384KeyPair.getPublic(), KeyAlgorithm.ES384);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should verify valid signature with ES512")
        void shouldVerifyValidSignatureWithES512() throws NoSuchAlgorithmException, SignatureException {
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
            ecKeyGen.initialize(521);
            KeyPair ec521KeyPair = ecKeyGen.generateKeyPair();

            Signer signer = new DefaultSigner(ec521KeyPair.getPrivate(), KeyAlgorithm.ES512);
            Verifier verifier = new DefaultVerifier(ec521KeyPair.getPublic(), KeyAlgorithm.ES512);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should reject invalid ECDSA signature")
        void shouldRejectInvalidEcdsaSignature() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);
            Verifier verifier = new DefaultVerifier(ecKeyPair.getPublic(), KeyAlgorithm.ES256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            // Create a signature for different data to make it invalid
            byte[] otherData = "other data".getBytes();
            byte[] invalidSignature = signer.sign(otherData);

            boolean isValid = verifier.verify(data, invalidSignature);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should reject ECDSA signature for different data")
        void shouldRejectEcdsaSignatureForDifferentData() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);
            Verifier verifier = new DefaultVerifier(ecKeyPair.getPublic(), KeyAlgorithm.ES256);
            byte[] data1 = "data1".getBytes();
            byte[] data2 = "data2".getBytes();
            byte[] signature = signer.sign(data1);

            boolean isValid = verifier.verify(data2, signature);

            assertThat(isValid).isFalse();
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should throw exception when public key is null")
        void shouldThrowExceptionWhenPublicKeyIsNull() {
            assertThatThrownBy(() -> new DefaultVerifier(null, KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Public key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when algorithm is null")
        void shouldThrowExceptionWhenAlgorithmIsNull() {
            assertThatThrownBy(() -> new DefaultVerifier(rsaKeyPair.getPublic(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when verifying null data")
        void shouldThrowExceptionWhenVerifyingNullData() throws SignatureException {
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] signature = new byte[256];

            assertThatThrownBy(() -> verifier.verify(null, signature))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying empty data")
        void shouldThrowExceptionWhenVerifyingEmptyData() throws SignatureException {
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] signature = new byte[256];

            assertThatThrownBy(() -> verifier.verify(new byte[0], signature))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying null signature")
        void shouldThrowExceptionWhenVerifyingNullSignature() throws SignatureException {
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();

            assertThatThrownBy(() -> verifier.verify(data, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Signature cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying empty signature")
        void shouldThrowExceptionWhenVerifyingEmptySignature() throws SignatureException {
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();

            assertThatThrownBy(() -> verifier.verify(data, new byte[0]))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Signature cannot be null or empty");
        }

    }

    @Nested
    @DisplayName("Getter Methods Tests")
    class GetterMethodsTests {

        @Test
        @DisplayName("Should return correct verification key")
        void shouldReturnCorrectVerificationKey() throws SignatureException {
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(verifier.getVerificationKey()).isEqualTo(rsaKeyPair.getPublic());
        }

        @Test
        @DisplayName("Should return correct algorithm")
        void shouldReturnCorrectAlgorithm() throws SignatureException {
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(verifier.getAlgorithm()).isEqualTo(KeyAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should return correct algorithm for ECDSA")
        void shouldReturnCorrectAlgorithmForECDSA() throws SignatureException {
            Verifier verifier = new DefaultVerifier(ecKeyPair.getPublic(), KeyAlgorithm.ES256);

            assertThat(verifier.getAlgorithm()).isEqualTo(KeyAlgorithm.ES256);
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should be thread-safe for concurrent verification operations")
        void shouldBeThreadSafeForConcurrentVerificationOperations() throws InterruptedException, SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);

            Thread thread1 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        boolean isValid = verifier.verify(data, signature);
                        assertThat(isValid).isTrue();
                    }
                } catch (SignatureException e) {
                    throw new RuntimeException(e);
                }
            });

            Thread thread2 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        boolean isValid = verifier.verify(data, signature);
                        assertThat(isValid).isTrue();
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

    @Nested
    @DisplayName("End-to-End Integration Tests")
    class EndToEndIntegrationTests {

        @Test
        @DisplayName("Should successfully sign and verify with RSA256")
        void shouldSuccessfullySignAndVerifyWithRSA256() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            byte[] data = "important message".getBytes();
            byte[] signature = signer.sign(data);
            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should successfully sign and verify with ES256")
        void shouldSuccessfullySignAndVerifyWithES256() throws SignatureException {
            Signer signer = new DefaultSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);
            Verifier verifier = new DefaultVerifier(ecKeyPair.getPublic(), KeyAlgorithm.ES256);

            byte[] data = "important message".getBytes();
            byte[] signature = signer.sign(data);
            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should handle large data")
        void shouldHandleLargeData() throws SignatureException {
            Signer signer = new DefaultSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = new DefaultVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            byte[] largeData = new byte[10000];
            for (int i = 0; i < largeData.length; i++) {
                largeData[i] = (byte) (i % 256);
            }

            byte[] signature = signer.sign(largeData);
            boolean isValid = verifier.verify(largeData, signature);

            assertThat(isValid).isTrue();
        }
    }
}
