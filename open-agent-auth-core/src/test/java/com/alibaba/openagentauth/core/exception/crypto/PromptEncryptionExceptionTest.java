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
package com.alibaba.openagentauth.core.exception.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for PromptEncryptionException.
 * <p>
 * This test class validates the exception creation, message formatting,
 * and exception chaining for PromptEncryptionException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Prompt Encryption Exception Test")
class PromptEncryptionExceptionTest {

    @Test
    @DisplayName("Should create PromptEncryptionException with message")
    void shouldCreatePromptEncryptionExceptionWithMessage() {
        String message = "Invalid encryption key";
        PromptEncryptionException exception = new PromptEncryptionException(message);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0304");
        assertThat(exception.getFormattedMessage()).isEqualTo("Prompt encryption operation failed: Invalid encryption key");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create PromptEncryptionException with message and cause")
    void shouldCreatePromptEncryptionExceptionWithMessageAndCause() {
        String message = "Encryption algorithm not supported";
        Throwable cause = new RuntimeException("AES-256-GCM not available");
        PromptEncryptionException exception = new PromptEncryptionException(message, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0304");
        assertThat(exception.getFormattedMessage()).isEqualTo("Prompt encryption operation failed: Encryption algorithm not supported");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should create PromptEncryptionException with cause only")
    void shouldCreatePromptEncryptionExceptionWithCauseOnly() {
        Throwable cause = new RuntimeException("Cryptographic operation failed");
        PromptEncryptionException exception = new PromptEncryptionException(cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0304");
        assertThat(exception.getFormattedMessage()).isEqualTo("Prompt encryption operation failed: Cryptographic operation failed");
        assertThat(exception.getErrorParams()).containsExactly(cause.getMessage());
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception details in toString")
    void shouldContainExceptionDetailsInToString() {
        PromptEncryptionException exception = new PromptEncryptionException("Test error");
        
        assertThat(exception.toString()).contains("PromptEncryptionException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0304'");
        assertThat(exception.toString()).contains("Prompt encryption operation failed: Test error");
    }

    @Test
    @DisplayName("Should preserve exception chain when created with cause")
    void shouldPreserveExceptionChainWhenCreatedWithCause() {
        Throwable rootCause = new RuntimeException("Key store error");
        Throwable cause = new RuntimeException("Key retrieval failed", rootCause);
        PromptEncryptionException exception = new PromptEncryptionException(cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        PromptEncryptionException exception = new PromptEncryptionException("Encryption failed");
        
        // Error code format: OPEN_AGENT_AUTH_10_03ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_03");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}