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

import com.alibaba.openagentauth.core.crypto.jwe.JweEncoder;
import com.alibaba.openagentauth.core.exception.crypto.PromptEncryptionException;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PromptEncryptionService.
 */
class PromptEncryptionServiceTest {

    private JweEncoder mockEncoder;
    private PromptEncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        mockEncoder = mock(JweEncoder.class);
        encryptionService = new PromptEncryptionService(mockEncoder, true);
    }

    @Test
    @DisplayName("Should encrypt prompt when enabled")
    void testEncryptPrompt_WhenEnabled_ShouldEncrypt() throws JOSEException {
        // Arrange
        String plaintext = "test prompt";
        String expectedEncrypted = "encrypted.jwe.token";
        when(mockEncoder.encrypt(plaintext)).thenReturn(expectedEncrypted);

        // Act
        String result = encryptionService.encryptPrompt(plaintext);

        // Assert
        assertEquals(expectedEncrypted, result);
        verify(mockEncoder, times(1)).encrypt(plaintext);
    }

    @Test
    @DisplayName("Should return plaintext when encryption disabled")
    void testEncryptPrompt_WhenDisabled_ShouldReturnPlaintext() throws JOSEException {
        // Arrange
        String plaintext = "test prompt";
        PromptEncryptionService disabledService = new PromptEncryptionService(mockEncoder, false);

        // Act
        String result = disabledService.encryptPrompt(plaintext);

        // Assert
        assertEquals(plaintext, result);
        verify(mockEncoder, never()).encrypt(anyString());
    }

    @Test
    @DisplayName("Should throw exception when prompt is null")
    void testEncryptPrompt_WhenNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> encryptionService.encryptPrompt(null));
    }

    @Test
    @DisplayName("Should throw PromptEncryptionException when encryption fails")
    void testEncryptPrompt_WhenEncryptionFails_ShouldThrowException() throws JOSEException {
        // Arrange
        String plaintext = "test prompt";
        when(mockEncoder.encrypt(plaintext)).thenThrow(new JOSEException("Encryption failed"));

        // Act & Assert
        PromptEncryptionException exception = assertThrows(
            PromptEncryptionException.class,
            () -> encryptionService.encryptPrompt(plaintext)
        );
        assertTrue(exception.getMessage().contains("Failed to encrypt prompt"));
    }

    @Test
    @DisplayName("Should return correct enabled status")
    void testIsEnabled_ShouldReturnCorrectStatus() {
        // Arrange
        PromptEncryptionService enabledService = new PromptEncryptionService(mockEncoder, true);
        PromptEncryptionService disabledService = new PromptEncryptionService(mockEncoder, false);

        // Act & Assert
        assertTrue(enabledService.isEnabled());
        assertFalse(disabledService.isEnabled());
    }

    @Test
    @DisplayName("Should throw exception when encoder is null")
    void testConstructor_WhenEncoderIsNull_ShouldThrowException() {
        // Act & Assert
        assertThrows(NullPointerException.class, () -> new PromptEncryptionService(null, true));
    }
}
