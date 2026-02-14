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
 * Test class for FileJwksProviderException.
 * <p>
 * This test class validates the exception creation, message formatting,
 * and exception chaining for FileJwksProviderException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("File JWKS Provider Exception Test")
class FileJwksProviderExceptionTest {

    @Test
    @DisplayName("Should create FileJwksProviderException with message")
    void shouldCreateFileJwksProviderExceptionWithMessage() {
        String message = "JWKS file not found";
        FileJwksProviderException exception = new FileJwksProviderException(message);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0303");
        assertThat(exception.getFormattedMessage()).isEqualTo("File JWKS provider operation failed: JWKS file not found");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create FileJwksProviderException with message and cause")
    void shouldCreateFileJwksProviderExceptionWithMessageAndCause() {
        String message = "Invalid JWKS file format";
        Throwable cause = new RuntimeException("Malformed JSON");
        FileJwksProviderException exception = new FileJwksProviderException(message, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0303");
        assertThat(exception.getFormattedMessage()).isEqualTo("File JWKS provider operation failed: Invalid JWKS file format");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception details in toString")
    void shouldContainExceptionDetailsInToString() {
        FileJwksProviderException exception = new FileJwksProviderException("Test error");
        
        assertThat(exception.toString()).contains("FileJwksProviderException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0303'");
        assertThat(exception.toString()).contains("File JWKS provider operation failed: Test error");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new RuntimeException("File system error");
        Throwable cause = new RuntimeException("Cannot read file", rootCause);
        FileJwksProviderException exception = new FileJwksProviderException("Test error", cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        FileJwksProviderException exception = new FileJwksProviderException("File not found");
        
        // Error code format: OPEN_AGENT_AUTH_10_03ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_03");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}