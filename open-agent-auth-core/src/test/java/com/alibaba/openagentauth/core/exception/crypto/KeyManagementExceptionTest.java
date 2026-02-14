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
 * Test class for KeyManagementException.
 * <p>
 * This test class validates the exception creation, message formatting,
 * and exception chaining for KeyManagementException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Key Management Exception Test")
class KeyManagementExceptionTest {

    @Test
    @DisplayName("Should create KeyManagementException with message")
    void shouldCreateKeyManagementExceptionWithMessage() {
        String message = "Key not found";
        KeyManagementException exception = new KeyManagementException(message);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Key management operation failed: Key not found");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create KeyManagementException with message and cause")
    void shouldCreateKeyManagementExceptionWithMessageAndCause() {
        String message = "Key generation failed";
        Throwable cause = new RuntimeException("Insufficient entropy");
        KeyManagementException exception = new KeyManagementException(message, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Key management operation failed: Key generation failed");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception details in toString")
    void shouldContainExceptionDetailsInToString() {
        KeyManagementException exception = new KeyManagementException("Test error");
        
        assertThat(exception.toString()).contains("KeyManagementException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0302'");
        assertThat(exception.toString()).contains("Key management operation failed: Test error");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new RuntimeException("Storage unavailable");
        Throwable cause = new RuntimeException("Key store error", rootCause);
        KeyManagementException exception = new KeyManagementException("Test error", cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        KeyManagementException exception = new KeyManagementException("Key generation failed");
        
        // Error code format: OPEN_AGENT_AUTH_10_03ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_03");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}