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
package com.alibaba.openagentauth.core.protocol.vc.jwe;

import com.alibaba.openagentauth.core.crypto.jwe.JweDecoder;
import com.alibaba.openagentauth.core.exception.crypto.PromptDecryptionException;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PromptDecryptionService.
 */
class PromptDecryptionServiceTest {

    private JweDecoder mockDecoder;
    private PromptDecryptionService decryptionService;

    @BeforeEach
    void setUp() {
        mockDecoder = mock(JweDecoder.class);
        decryptionService = new PromptDecryptionService(mockDecoder, true);
    }

    @Test
    @DisplayName("Should decrypt JWE prompt when enabled")
    void testDecryptPrompt_WhenEnabledAndJweFormat_ShouldDecrypt() throws JOSEException {
        // Arrange
        String encryptedJwe = "header.encryptedKey.iv.ciphertext.tag";
        String expectedPlaintext = "test prompt";
        when(mockDecoder.decryptToString(encryptedJwe)).thenReturn(expectedPlaintext);

        // Act
        String result = decryptionService.decryptPrompt(encryptedJwe);

        // Assert
        assertEquals(expectedPlaintext, result);
        verify(mockDecoder, times(1)).decryptToString(encryptedJwe);
    }

    @Test
    @DisplayName("Should return input unchanged when encryption disabled")
    void testDecryptPrompt_WhenDisabled_ShouldReturnInputUnchanged() throws JOSEException {
        // Arrange
        String input = "test prompt";
        PromptDecryptionService disabledService = new PromptDecryptionService(mockDecoder, false);

        // Act
        String result = disabledService.decryptPrompt(input);

        // Assert
        assertEquals(input, result);
        verify(mockDecoder, never()).decryptToString(anyString());
    }

    @Test
    @DisplayName("Should return input unchanged when not in JWE format")
    void testDecryptPrompt_WhenNotJweFormat_ShouldReturnInputUnchanged() throws JOSEException {
        // Arrange
        String plaintext = "test prompt";

        // Act
        String result = decryptionService.decryptPrompt(plaintext);

        // Assert
        assertEquals(plaintext, result);
        verify(mockDecoder, never()).decryptToString(anyString());
    }

    @Test
    @DisplayName("Should decrypt valid JWE with 4 dots")
    void testDecryptPrompt_WhenValidJweWith4Dots_ShouldDecrypt() throws JOSEException {
        // Arrange
        String encryptedJwe = "a.b.c.d.e";
        String expectedPlaintext = "decrypted";
        when(mockDecoder.decryptToString(encryptedJwe)).thenReturn(expectedPlaintext);

        // Act
        String result = decryptionService.decryptPrompt(encryptedJwe);

        // Assert
        assertEquals(expectedPlaintext, result);
    }

    @Test
    @DisplayName("Should return input unchanged when JWE has less than 4 dots")
    void testDecryptPrompt_WhenJweWithLessThan4Dots_ShouldReturnInputUnchanged() {
        // Arrange
        String invalidJwe = "a.b.c";

        // Act
        String result = decryptionService.decryptPrompt(invalidJwe);

        // Assert
        assertEquals(invalidJwe, result);
    }

    @Test
    @DisplayName("Should return input unchanged when JWE has more than 4 dots")
    void testDecryptPrompt_WhenJweWithMoreThan4Dots_ShouldReturnInputUnchanged() {
        // Arrange
        String invalidJwe = "a.b.c.d.e.f";

        // Act
        String result = decryptionService.decryptPrompt(invalidJwe);

        // Assert
        assertEquals(invalidJwe, result);
    }

    @Test
    @DisplayName("Should throw exception when input is null")
    void testDecryptPrompt_WhenNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> decryptionService.decryptPrompt(null));
    }

    @Test
    @DisplayName("Should throw PromptDecryptionException when decryption fails")
    void testDecryptPrompt_WhenDecryptionFails_ShouldThrowException() throws JOSEException {
        // Arrange
        String encryptedJwe = "header.encryptedKey.iv.ciphertext.tag";
        when(mockDecoder.decryptToString(encryptedJwe)).thenThrow(new JOSEException("Decryption failed"));

        // Act & Assert
        PromptDecryptionException exception = assertThrows(
            PromptDecryptionException.class,
            () -> decryptionService.decryptPrompt(encryptedJwe)
        );
        assertTrue(exception.getMessage().contains("Failed to decrypt prompt"));
    }

    @Test
    @DisplayName("Should return correct enabled status")
    void testIsEnabled_ShouldReturnCorrectStatus() {
        // Arrange
        PromptDecryptionService enabledService = new PromptDecryptionService(mockDecoder, true);
        PromptDecryptionService disabledService = new PromptDecryptionService(mockDecoder, false);

        // Act & Assert
        assertTrue(enabledService.isEnabled());
        assertFalse(disabledService.isEnabled());
    }

    @Test
    @DisplayName("Should throw exception when decoder is null")
    void testConstructor_WhenDecoderIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> new PromptDecryptionService(null, true));
    }

    @Test
    @DisplayName("Should return input unchanged when empty string")
    void testDecryptPrompt_WhenEmptyString_ShouldReturnInputUnchanged() {
        // Arrange
        String emptyString = "";

        // Act
        String result = decryptionService.decryptPrompt(emptyString);

        // Assert
        assertEquals(emptyString, result);
    }
}
