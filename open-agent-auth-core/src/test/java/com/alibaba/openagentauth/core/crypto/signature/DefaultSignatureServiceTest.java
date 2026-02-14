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
 * Unit tests for {@link DefaultSignatureService}.
 * <p>
 * Tests the signature service's behavior including:
 * <ul>
 *   <li>Creating signers and verifiers with different algorithms</li>
 *   <li>One-time signing and verification operations</li>
 *   <li>Error handling for null parameters</li>
 *   <li>Error handling for empty data and signatures</li>
 *   <li>Integration testing with Signer and Verifier</li>
 * </ul>
 * </p>
 */
@DisplayName("DefaultSignatureService Tests")
class DefaultSignatureServiceTest {

    private DefaultSignatureService signatureService;
    private KeyPair rsaKeyPair;
    private KeyPair ecKeyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        signatureService = new DefaultSignatureService();

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
    @DisplayName("Signer Creation Tests")
    class SignerCreationTests {

        @Test
        @DisplayName("Should create signer with RSA key and RS256 algorithm")
        void shouldCreateSignerWithRsaKeyAndRS256Algorithm() {
            Signer signer = signatureService.createSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            assertThat(signer).isNotNull();
            assertThat(signer.getSigningKey()).isEqualTo(rsaKeyPair.getPrivate());
            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should create signer with RSA key and RS384 algorithm")
        void shouldCreateSignerWithRsaKeyAndRS384Algorithm() {
            Signer signer = signatureService.createSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS384);

            assertThat(signer).isNotNull();
            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.RS384);
        }

        @Test
        @DisplayName("Should create signer with RSA key and RS512 algorithm")
        void shouldCreateSignerWithRsaKeyAndRS512Algorithm() {
            Signer signer = signatureService.createSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS512);

            assertThat(signer).isNotNull();
            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.RS512);
        }

        @Test
        @DisplayName("Should create signer with EC key and ES256 algorithm")
        void shouldCreateSignerWithEcKeyAndES256Algorithm() {
            Signer signer = signatureService.createSigner(ecKeyPair.getPrivate(), KeyAlgorithm.ES256);

            assertThat(signer).isNotNull();
            assertThat(signer.getSigningKey()).isEqualTo(ecKeyPair.getPrivate());
            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.ES256);
        }

        @Test
        @DisplayName("Should create signer with EC key and ES384 algorithm")
        void shouldCreateSignerWithEcKeyAndES384Algorithm() throws NoSuchAlgorithmException {
            KeyPairGenerator ecKeyGen = KeyPairGenerator.getInstance("EC");
            ecKeyGen.initialize(384);
            KeyPair ec384KeyPair = ecKeyGen.generateKeyPair();

            Signer signer = signatureService.createSigner(ec384KeyPair.getPrivate(), KeyAlgorithm.ES384);

            assertThat(signer).isNotNull();
            assertThat(signer.getAlgorithm()).isEqualTo(KeyAlgorithm.ES384);
        }

        @Test
        @DisplayName("Should throw exception when creating signer with null private key")
        void shouldThrowExceptionWhenCreatingSignerWithNullPrivateKey() {
            assertThatThrownBy(() -> signatureService.createSigner(null, KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Private key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when creating signer with null algorithm")
        void shouldThrowExceptionWhenCreatingSignerWithNullAlgorithm() {
            assertThatThrownBy(() -> signatureService.createSigner(rsaKeyPair.getPrivate(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }
    }

    @Nested
    @DisplayName("Verifier Creation Tests")
    class VerifierCreationTests {

        @Test
        @DisplayName("Should create verifier with RSA key and RS256 algorithm")
        void shouldCreateVerifierWithRsaKeyAndRS256Algorithm() {
            Verifier verifier = signatureService.createVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(verifier).isNotNull();
            assertThat(verifier.getVerificationKey()).isEqualTo(rsaKeyPair.getPublic());
            assertThat(verifier.getAlgorithm()).isEqualTo(KeyAlgorithm.RS256);
        }

        @Test
        @DisplayName("Should create verifier with RSA key and RS384 algorithm")
        void shouldCreateVerifierWithRsaKeyAndRS384Algorithm() {
            Verifier verifier = signatureService.createVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS384);

            assertThat(verifier).isNotNull();
            assertThat(verifier.getAlgorithm()).isEqualTo(KeyAlgorithm.RS384);
        }

        @Test
        @DisplayName("Should create verifier with RSA key and RS512 algorithm")
        void shouldCreateVerifierWithRsaKeyAndRS512Algorithm() {
            Verifier verifier = signatureService.createVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS512);

            assertThat(verifier).isNotNull();
            assertThat(verifier.getAlgorithm()).isEqualTo(KeyAlgorithm.RS512);
        }

        @Test
        @DisplayName("Should create verifier with EC key and ES256 algorithm")
        void shouldCreateVerifierWithEcKeyAndES256Algorithm() {
            Verifier verifier = signatureService.createVerifier(ecKeyPair.getPublic(), KeyAlgorithm.ES256);

            assertThat(verifier).isNotNull();
            assertThat(verifier.getVerificationKey()).isEqualTo(ecKeyPair.getPublic());
            assertThat(verifier.getAlgorithm()).isEqualTo(KeyAlgorithm.ES256);
        }

        @Test
        @DisplayName("Should throw exception when creating verifier with null public key")
        void shouldThrowExceptionWhenCreatingVerifierWithNullPublicKey() {
            assertThatThrownBy(() -> signatureService.createVerifier(null, KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Public key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when creating verifier with null algorithm")
        void shouldThrowExceptionWhenCreatingVerifierWithNullAlgorithm() {
            assertThatThrownBy(() -> signatureService.createVerifier(rsaKeyPair.getPublic(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }
    }

    @Nested
    @DisplayName("One-Time Signing Tests")
    class OneTimeSigningTests {

        @Test
        @DisplayName("Should sign data with RSA256")
        void shouldSignDataWithRSA256() throws SignatureException {
            byte[] data = "test data".getBytes();
            byte[] signature = signatureService.sign(data, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should sign data with ES256")
        void shouldSignDataWithES256() throws SignatureException {
            byte[] data = "test data".getBytes();
            byte[] signature = signatureService.sign(data, ecKeyPair.getPrivate(), KeyAlgorithm.ES256);

            assertThat(signature).isNotNull();
            assertThat(signature.length).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should throw exception when signing null data")
        void shouldThrowExceptionWhenSigningNullData() {
            assertThatThrownBy(() -> signatureService.sign(null, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when signing empty data")
        void shouldThrowExceptionWhenSigningEmptyData() {
            assertThatThrownBy(() -> signatureService.sign(new byte[0], rsaKeyPair.getPrivate(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when signing with null private key")
        void shouldThrowExceptionWhenSigningWithNullPrivateKey() {
            byte[] data = "test data".getBytes();

            assertThatThrownBy(() -> signatureService.sign(data, null, KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Private key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when signing with null algorithm")
        void shouldThrowExceptionWhenSigningWithNullAlgorithm() {
            byte[] data = "test data".getBytes();

            assertThatThrownBy(() -> signatureService.sign(data, rsaKeyPair.getPrivate(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }
    }

    @Nested
    @DisplayName("One-Time Verification Tests")
    class OneTimeVerificationTests {

        @Test
        @DisplayName("Should verify valid signature with RSA256")
        void shouldVerifyValidSignatureWithRSA256() throws SignatureException {
            byte[] data = "test data".getBytes();
            byte[] signature = signatureService.sign(data, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            boolean isValid = signatureService.verify(data, signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should verify valid signature with ES256")
        void shouldVerifyValidSignatureWithES256() throws SignatureException {
            byte[] data = "test data".getBytes();
            byte[] signature = signatureService.sign(data, ecKeyPair.getPrivate(), KeyAlgorithm.ES256);

            boolean isValid = signatureService.verify(data, signature, ecKeyPair.getPublic(), KeyAlgorithm.ES256);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should reject invalid signature")
        void shouldRejectInvalidSignature() throws SignatureException {
            byte[] data = "test data".getBytes();
            byte[] signature = signatureService.sign(data, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            // Modify the signature to make it invalid
            signature[0] ^= 0xFF;

            boolean isValid = signatureService.verify(data, signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(isValid).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when verifying null data")
        void shouldThrowExceptionWhenVerifyingNullData() {
            byte[] signature = new byte[256];

            assertThatThrownBy(() -> signatureService.verify(null, signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying empty data")
        void shouldThrowExceptionWhenVerifyingEmptyData() {
            byte[] signature = new byte[256];

            assertThatThrownBy(() -> signatureService.verify(new byte[0], signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Data cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying null signature")
        void shouldThrowExceptionWhenVerifyingNullSignature() {
            byte[] data = "test data".getBytes();

            assertThatThrownBy(() -> signatureService.verify(data, null, rsaKeyPair.getPublic(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Signature cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying empty signature")
        void shouldThrowExceptionWhenVerifyingEmptySignature() {
            byte[] data = "test data".getBytes();

            assertThatThrownBy(() -> signatureService.verify(data, new byte[0], rsaKeyPair.getPublic(), KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Signature cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when verifying with null public key")
        void shouldThrowExceptionWhenVerifyingWithNullPublicKey() {
            byte[] data = "test data".getBytes();
            byte[] signature = new byte[256];

            assertThatThrownBy(() -> signatureService.verify(data, signature, null, KeyAlgorithm.RS256))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Public key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when verifying with null algorithm")
        void shouldThrowExceptionWhenVerifyingWithNullAlgorithm() {
            byte[] data = "test data".getBytes();
            byte[] signature = new byte[256];

            assertThatThrownBy(() -> signatureService.verify(data, signature, rsaKeyPair.getPublic(), null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Algorithm cannot be null");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should successfully sign and verify with RSA256")
        void shouldSuccessfullySignAndVerifyWithRSA256() throws SignatureException {
            byte[] data = "important message".getBytes();

            // Sign using service
            byte[] signature = signatureService.sign(data, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);

            // Verify using service
            boolean isValid = signatureService.verify(data, signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should successfully sign and verify with ES256")
        void shouldSuccessfullySignAndVerifyWithES256() throws SignatureException {
            byte[] data = "important message".getBytes();

            // Sign using service
            byte[] signature = signatureService.sign(data, ecKeyPair.getPrivate(), KeyAlgorithm.ES256);

            // Verify using service
            boolean isValid = signatureService.verify(data, signature, ecKeyPair.getPublic(), KeyAlgorithm.ES256);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should support using created signer and verifier")
        void shouldSupportUsingCreatedSignerAndVerifier() throws SignatureException {
            // Create signer and verifier using service
            Signer signer = signatureService.createSigner(rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            Verifier verifier = signatureService.createVerifier(rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            byte[] data = "test data".getBytes();
            byte[] signature = signer.sign(data);
            boolean isValid = verifier.verify(data, signature);

            assertThat(isValid).isTrue();
        }

        @Test
        @DisplayName("Should handle large data")
        void shouldHandleLargeData() throws SignatureException {
            byte[] largeData = new byte[10000];
            for (int i = 0; i < largeData.length; i++) {
                largeData[i] = (byte) (i % 256);
            }

            byte[] signature = signatureService.sign(largeData, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
            boolean isValid = signatureService.verify(largeData, signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256);

            assertThat(isValid).isTrue();
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should be thread-safe for concurrent operations")
        void shouldBeThreadSafeForConcurrentOperations() throws InterruptedException, SignatureException {
            byte[] data = "test data".getBytes();

            Thread thread1 = new Thread(() -> {
                try {
                    for (int i = 0; i < 100; i++) {
                        byte[] signature = signatureService.sign(data, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
                        assertThat(signature).isNotNull();
                    }
                } catch (SignatureException e) {
                    throw new RuntimeException(e);
                }
            });

            Thread thread2 = new Thread(() -> {
                try {
                    byte[] signature = signatureService.sign(data, rsaKeyPair.getPrivate(), KeyAlgorithm.RS256);
                    for (int i = 0; i < 100; i++) {
                        boolean isValid = signatureService.verify(data, signature, rsaKeyPair.getPublic(), KeyAlgorithm.RS256);
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
}
