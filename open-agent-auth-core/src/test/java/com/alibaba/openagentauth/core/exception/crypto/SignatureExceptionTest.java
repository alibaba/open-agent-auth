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
 * Test class for SignatureException.
 * <p>
 * This test class validates the exception creation, message formatting,
 * and exception chaining for SignatureException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Signature Exception Test")
class SignatureExceptionTest {

    @Test
    @DisplayName("Should create SignatureException with message")
    void shouldCreateSignatureExceptionWithMessage() {
        String message = "Invalid signature format";
        SignatureException exception = new SignatureException(message);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Signature operation failed: Invalid signature format");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create SignatureException with message and cause")
    void shouldCreateSignatureExceptionWithMessageAndCause() {
        String message = "Signature verification failed";
        Throwable cause = new RuntimeException("Key mismatch");
        SignatureException exception = new SignatureException(message, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Signature operation failed: Signature verification failed");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception details in toString")
    void shouldContainExceptionDetailsInToString() {
        SignatureException exception = new SignatureException("Test error");
        
        assertThat(exception.toString()).contains("SignatureException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0301'");
        assertThat(exception.toString()).contains("Signature operation failed: Test error");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new RuntimeException("Root cause");
        Throwable cause = new RuntimeException("Intermediate cause", rootCause);
        SignatureException exception = new SignatureException("Test error", cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        SignatureException exception = new SignatureException("Signature verification failed");
        
        // Error code format: OPEN_AGENT_AUTH_10_03ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_03");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}