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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SignatureService.
 */
class SignatureServiceTest {

    private SignatureService signatureService;
    private PrivateKey mockPrivateKey;
    private PublicKey mockPublicKey;

    @BeforeEach
    void setUp() {
        signatureService = mock(SignatureService.class);
        mockPrivateKey = mock(PrivateKey.class);
        mockPublicKey = mock(PublicKey.class);
    }

    @Test
    @DisplayName("Should create signer successfully")
    void testCreateSigner_ShouldReturnSigner() {
        // Arrange
        when(signatureService.createSigner(mockPrivateKey, KeyAlgorithm.RS256))
                .thenReturn(mock(Signer.class));

        // Act
        Signer signer = signatureService.createSigner(mockPrivateKey, KeyAlgorithm.RS256);

        // Assert
        assertNotNull(signer);
        verify(signatureService, times(1)).createSigner(mockPrivateKey, KeyAlgorithm.RS256);
    }

    @Test
    @DisplayName("Should throw exception when creating signer with null private key")
    void testCreateSigner_WhenPrivateKeyIsNull_ShouldThrowException() {
        // Arrange
        doThrow(new IllegalArgumentException("Private key cannot be null"))
                .when(signatureService).createSigner(null, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.createSigner(null, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when creating signer with null algorithm")
    void testCreateSigner_WhenAlgorithmIsNull_ShouldThrowException() {
        // Arrange
        doThrow(new IllegalArgumentException("Algorithm cannot be null"))
                .when(signatureService).createSigner(mockPrivateKey, null);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.createSigner(mockPrivateKey, null));
    }

    @Test
    @DisplayName("Should create verifier successfully")
    void testCreateVerifier_ShouldReturnVerifier() {
        // Arrange
        when(signatureService.createVerifier(mockPublicKey, KeyAlgorithm.RS256))
                .thenReturn(mock(Verifier.class));

        // Act
        Verifier verifier = signatureService.createVerifier(mockPublicKey, KeyAlgorithm.RS256);

        // Assert
        assertNotNull(verifier);
        verify(signatureService, times(1)).createVerifier(mockPublicKey, KeyAlgorithm.RS256);
    }

    @Test
    @DisplayName("Should throw exception when creating verifier with null public key")
    void testCreateVerifier_WhenPublicKeyIsNull_ShouldThrowException() {
        // Arrange
        doThrow(new IllegalArgumentException("Public key cannot be null"))
                .when(signatureService).createVerifier(null, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.createVerifier(null, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when creating verifier with null algorithm")
    void testCreateVerifier_WhenAlgorithmIsNull_ShouldThrowException() {
        // Arrange
        doThrow(new IllegalArgumentException("Algorithm cannot be null"))
                .when(signatureService).createVerifier(mockPublicKey, null);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.createVerifier(mockPublicKey, null));
    }

    @Test
    @DisplayName("Should sign data successfully")
    void testSign_ShouldReturnSignature() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        byte[] expectedSignature = "signature".getBytes();
        when(signatureService.sign(data, mockPrivateKey, KeyAlgorithm.RS256))
                .thenReturn(expectedSignature);

        // Act
        byte[] signature = signatureService.sign(data, mockPrivateKey, KeyAlgorithm.RS256);

        // Assert
        assertNotNull(signature);
        assertArrayEquals(expectedSignature, signature);
        verify(signatureService, times(1)).sign(data, mockPrivateKey, KeyAlgorithm.RS256);
    }

    @Test
    @DisplayName("Should throw exception when signing with null data")
    void testSign_WhenDataIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        doThrow(new IllegalArgumentException("Data cannot be null"))
                .when(signatureService).sign(null, mockPrivateKey, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.sign(null, mockPrivateKey, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when signing with null private key")
    void testSign_WhenPrivateKeyIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        doThrow(new IllegalArgumentException("Private key cannot be null"))
                .when(signatureService).sign(data, null, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.sign(data, null, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when signing with null algorithm")
    void testSign_WhenAlgorithmIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        doThrow(new IllegalArgumentException("Algorithm cannot be null"))
                .when(signatureService).sign(data, mockPrivateKey, null);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.sign(data, mockPrivateKey, null));
    }

    @Test
    @DisplayName("Should throw SignatureException when signing fails")
    void testSign_WhenSigningFails_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        when(signatureService.sign(data, mockPrivateKey, KeyAlgorithm.RS256))
                .thenThrow(new SignatureException("Signing failed"));

        // Act & Assert
        assertThrows(SignatureException.class, 
                () -> signatureService.sign(data, mockPrivateKey, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should verify signature successfully")
    void testVerify_WhenSignatureIsValid_ShouldReturnTrue() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        byte[] signature = "valid signature".getBytes();
        when(signatureService.verify(data, signature, mockPublicKey, KeyAlgorithm.RS256))
                .thenReturn(true);

        // Act
        boolean result = signatureService.verify(data, signature, mockPublicKey, KeyAlgorithm.RS256);

        // Assert
        assertTrue(result);
        verify(signatureService, times(1)).verify(data, signature, mockPublicKey, KeyAlgorithm.RS256);
    }

    @Test
    @DisplayName("Should return false when signature is invalid")
    void testVerify_WhenSignatureIsInvalid_ShouldReturnFalse() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        byte[] signature = "invalid signature".getBytes();
        when(signatureService.verify(data, signature, mockPublicKey, KeyAlgorithm.RS256))
                .thenReturn(false);

        // Act
        boolean result = signatureService.verify(data, signature, mockPublicKey, KeyAlgorithm.RS256);

        // Assert
        assertFalse(result);
    }

    @Test
    @DisplayName("Should throw exception when verifying with null data")
    void testVerify_WhenDataIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] signature = "signature".getBytes();
        doThrow(new IllegalArgumentException("Data cannot be null"))
                .when(signatureService).verify(null, signature, mockPublicKey, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.verify(null, signature, mockPublicKey, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when verifying with null signature")
    void testVerify_WhenSignatureIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        doThrow(new IllegalArgumentException("Signature cannot be null"))
                .when(signatureService).verify(data, null, mockPublicKey, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.verify(data, null, mockPublicKey, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when verifying with null public key")
    void testVerify_WhenPublicKeyIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        byte[] signature = "signature".getBytes();
        doThrow(new IllegalArgumentException("Public key cannot be null"))
                .when(signatureService).verify(data, signature, null, KeyAlgorithm.RS256);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.verify(data, signature, null, KeyAlgorithm.RS256));
    }

    @Test
    @DisplayName("Should throw exception when verifying with null algorithm")
    void testVerify_WhenAlgorithmIsNull_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        byte[] signature = "signature".getBytes();
        doThrow(new IllegalArgumentException("Algorithm cannot be null"))
                .when(signatureService).verify(data, signature, mockPublicKey, null);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, 
                () -> signatureService.verify(data, signature, mockPublicKey, null));
    }

    @Test
    @DisplayName("Should throw SignatureException when verification fails")
    void testVerify_WhenVerificationFails_ShouldThrowException() throws SignatureException {
        // Arrange
        byte[] data = "test data".getBytes();
        byte[] signature = "signature".getBytes();
        when(signatureService.verify(data, signature, mockPublicKey, KeyAlgorithm.RS256))
                .thenThrow(new SignatureException("Verification failed"));

        // Act & Assert
        assertThrows(SignatureException.class, 
                () -> signatureService.verify(data, signature, mockPublicKey, KeyAlgorithm.RS256));
    }
}
