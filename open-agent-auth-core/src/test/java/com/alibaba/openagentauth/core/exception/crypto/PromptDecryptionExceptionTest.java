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
 * Test class for PromptDecryptionException.
 * <p>
 * This test class validates the exception creation, message formatting,
 * and exception chaining for PromptDecryptionException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Prompt Decryption Exception Test")
class PromptDecryptionExceptionTest {

    @Test
    @DisplayName("Should create PromptDecryptionException with message")
    void shouldCreatePromptDecryptionExceptionWithMessage() {
        String message = "Invalid decryption key";
        PromptDecryptionException exception = new PromptDecryptionException(message);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0305");
        assertThat(exception.getFormattedMessage()).isEqualTo("Prompt decryption operation failed: Invalid decryption key");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create PromptDecryptionException with message and cause")
    void shouldCreatePromptDecryptionExceptionWithMessageAndCause() {
        String message = "Corrupted JWE token";
        Throwable cause = new RuntimeException("Invalid JSON structure");
        PromptDecryptionException exception = new PromptDecryptionException(message, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0305");
        assertThat(exception.getFormattedMessage()).isEqualTo("Prompt decryption operation failed: Corrupted JWE token");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should create PromptDecryptionException with cause only")
    void shouldCreatePromptDecryptionExceptionWithCauseOnly() {
        Throwable cause = new RuntimeException("Decryption algorithm not supported");
        PromptDecryptionException exception = new PromptDecryptionException(cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0305");
        assertThat(exception.getFormattedMessage()).isEqualTo("Prompt decryption operation failed: Decryption algorithm not supported");
        assertThat(exception.getErrorParams()).containsExactly(cause.getMessage());
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception details in toString")
    void shouldContainExceptionDetailsInToString() {
        PromptDecryptionException exception = new PromptDecryptionException("Test error");
        
        assertThat(exception.toString()).contains("PromptDecryptionException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0305'");
        assertThat(exception.toString()).contains("Prompt decryption operation failed: Test error");
    }

    @Test
    @DisplayName("Should preserve exception chain when created with cause")
    void shouldPreserveExceptionChainWhenCreatedWithCause() {
        Throwable rootCause = new RuntimeException("Key expired");
        Throwable cause = new RuntimeException("Key validation failed", rootCause);
        PromptDecryptionException exception = new PromptDecryptionException(cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        PromptDecryptionException exception = new PromptDecryptionException("Decryption failed");
        
        // Error code format: OPEN_AGENT_AUTH_10_03ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_03");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}