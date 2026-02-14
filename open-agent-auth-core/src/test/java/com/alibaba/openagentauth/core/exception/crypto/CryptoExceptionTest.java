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
 * Test class for Crypto exceptions.
 * <p>
 * This test class validates the error codes and message formatting
 * for SignatureException and KeyManagementException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Crypto Exception Test")
class CryptoExceptionTest {

    @Test
    @DisplayName("Test SignatureException with single parameter")
    void testSignatureExceptionWithSingleParameter() {
        SignatureException exception = new SignatureException("Invalid signature format");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Signature operation failed: Invalid signature format");
        assertThat(exception.getErrorParams()).containsExactly("Invalid signature format");
    }

    @Test
    @DisplayName("Test SignatureException with message and cause")
    void testSignatureExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Verification failed");
        SignatureException exception = new SignatureException("Invalid signature format", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Signature operation failed: Invalid signature format");
        assertThat(exception.getErrorParams()).containsExactly("Invalid signature format");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test SignatureException error code properties")
    void testSignatureExceptionErrorCodeProperties() {
        SignatureException exception = new SignatureException("Test message");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(exception.toString()).contains("SignatureException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0301'");
    }

    @Test
    @DisplayName("Test KeyManagementException with single parameter")
    void testKeyManagementExceptionWithSingleParameter() {
        KeyManagementException exception = new KeyManagementException("Key not found");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Key management operation failed: Key not found");
        assertThat(exception.getErrorParams()).containsExactly("Key not found");
    }

    @Test
    @DisplayName("Test KeyManagementException with message and cause")
    void testKeyManagementExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Key generation failed");
        KeyManagementException exception = new KeyManagementException("Key not found", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Key management operation failed: Key not found");
        assertThat(exception.getErrorParams()).containsExactly("Key not found");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test KeyManagementException error code properties")
    void testKeyManagementExceptionErrorCodeProperties() {
        KeyManagementException exception = new KeyManagementException("Test message");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
        assertThat(exception.toString()).contains("KeyManagementException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0302'");
    }

    @Test
    @DisplayName("Test CryptoErrorCode error code format")
    void testCryptoErrorCodeFormat() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
    }

    @Test
    @DisplayName("Test CryptoErrorCode domain code")
    void testCryptoErrorCodeDomainCode() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getDomainCode()).isEqualTo("03");
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getDomainCode()).isEqualTo("03");
    }

    @Test
    @DisplayName("Test CryptoErrorCode sub code")
    void testCryptoErrorCodeSubCode() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getSubCode()).isEqualTo("01");
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Test CryptoErrorCode system code")
    void testCryptoErrorCodeSystemCode() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test CryptoErrorCode error names")
    void testCryptoErrorCodeErrorNames() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getErrorName()).isEqualTo("SignatureFailed");
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getErrorName()).isEqualTo("KeyManagementFailed");
    }

    @Test
    @DisplayName("Test CryptoErrorCode HTTP status")
    void testCryptoErrorCodeHttpStatus() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getHttpStatus().value()).isEqualTo(500);
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Test CryptoErrorCode domain code constant")
    void testCryptoErrorCodeDomainCodeConstant() {
        assertThat(CryptoErrorCode.DOMAIN_CODE).isEqualTo("03");
    }
}
