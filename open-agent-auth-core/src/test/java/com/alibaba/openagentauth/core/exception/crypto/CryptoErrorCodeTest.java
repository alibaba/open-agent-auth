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
 * Test class for CryptoErrorCode enum.
 * <p>
 * This test class validates the error code structure, message templates,
 * and HTTP status codes for all Crypto error codes.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Crypto Error Code Test")
class CryptoErrorCodeTest {

    @Test
    @DisplayName("Should verify SIGNATURE_FAILED error code properties")
    void shouldVerifySignatureFailedErrorCodeProperties() {
        CryptoErrorCode errorCode = CryptoErrorCode.SIGNATURE_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0301");
        assertThat(errorCode.getDomainCode()).isEqualTo("03");
        assertThat(errorCode.getSubCode()).isEqualTo("01");
        assertThat(errorCode.getSystemCode()).isEqualTo("10");
        assertThat(errorCode.getErrorName()).isEqualTo("SignatureFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Signature operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify KEY_MANAGEMENT_FAILED error code properties")
    void shouldVerifyKeyManagementFailedErrorCodeProperties() {
        CryptoErrorCode errorCode = CryptoErrorCode.KEY_MANAGEMENT_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0302");
        assertThat(errorCode.getDomainCode()).isEqualTo("03");
        assertThat(errorCode.getSubCode()).isEqualTo("02");
        assertThat(errorCode.getErrorName()).isEqualTo("KeyManagementFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Key management operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify FILE_JWKS_PROVIDER_FAILED error code properties")
    void shouldVerifyFileJwksProviderFailedErrorCodeProperties() {
        CryptoErrorCode errorCode = CryptoErrorCode.FILE_JWKS_PROVIDER_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0303");
        assertThat(errorCode.getDomainCode()).isEqualTo("03");
        assertThat(errorCode.getSubCode()).isEqualTo("03");
        assertThat(errorCode.getErrorName()).isEqualTo("FileJwksProviderFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("File JWKS provider operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify PROMPT_ENCRYPTION_FAILED error code properties")
    void shouldVerifyPromptEncryptionFailedErrorCodeProperties() {
        CryptoErrorCode errorCode = CryptoErrorCode.PROMPT_ENCRYPTION_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0304");
        assertThat(errorCode.getDomainCode()).isEqualTo("03");
        assertThat(errorCode.getSubCode()).isEqualTo("04");
        assertThat(errorCode.getErrorName()).isEqualTo("PromptEncryptionFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Prompt encryption operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify PROMPT_DECRYPTION_FAILED error code properties")
    void shouldVerifyPromptDecryptionFailedErrorCodeProperties() {
        CryptoErrorCode errorCode = CryptoErrorCode.PROMPT_DECRYPTION_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0305");
        assertThat(errorCode.getDomainCode()).isEqualTo("03");
        assertThat(errorCode.getSubCode()).isEqualTo("05");
        assertThat(errorCode.getErrorName()).isEqualTo("PromptDecryptionFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Prompt decryption operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify all error codes have correct domain code")
    void shouldVerifyAllErrorCodesHaveCorrectDomainCode() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getDomainCode()).isEqualTo("03");
        }
    }

    @Test
    @DisplayName("Should verify all error codes have correct system code")
    void shouldVerifyAllErrorCodesHaveCorrectSystemCode() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getSystemCode()).isEqualTo("10");
        }
    }

    @Test
    @DisplayName("Should verify domain code constant")
    void shouldVerifyDomainCodeConstant() {
        assertThat(CryptoErrorCode.DOMAIN_CODE).isEqualTo("03");
    }

    @Test
    @DisplayName("Should verify unique sub codes")
    void shouldVerifyUniqueSubCodes() {
        assertThat(CryptoErrorCode.SIGNATURE_FAILED.getSubCode()).isEqualTo("01");
        assertThat(CryptoErrorCode.KEY_MANAGEMENT_FAILED.getSubCode()).isEqualTo("02");
        assertThat(CryptoErrorCode.FILE_JWKS_PROVIDER_FAILED.getSubCode()).isEqualTo("03");
        assertThat(CryptoErrorCode.PROMPT_ENCRYPTION_FAILED.getSubCode()).isEqualTo("04");
        assertThat(CryptoErrorCode.PROMPT_DECRYPTION_FAILED.getSubCode()).isEqualTo("05");
    }

    @Test
    @DisplayName("Should verify error code format consistency")
    void shouldVerifyErrorCodeFormatConsistency() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getErrorCode()).matches("OPEN_AGENT_AUTH_10_03\\d{2}");
            assertThat(errorCode.getErrorCode()).hasSize(23);
        }
    }

    @Test
    @DisplayName("Should verify all error codes have HTTP status 500")
    void shouldVerifyAllErrorCodesHaveHttpStatus500() {
        for (CryptoErrorCode errorCode : CryptoErrorCode.values()) {
            assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
        }
    }
}