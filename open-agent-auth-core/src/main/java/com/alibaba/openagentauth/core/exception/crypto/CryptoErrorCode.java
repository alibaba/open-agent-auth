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

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for Crypto domain.
 * <p>
 * This enum defines error codes for cryptographic operations in the Core module.
 * All crypto error codes follow the format: OPEN_AGENT_AUTH_10_03ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_03ZZ
 * </p>
 * <ul>
 *   <li><b>10</b>: Core system code</li>
 *   <li><b>03</b>: Crypto domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Crypto domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum CryptoErrorCode implements CoreErrorCode {
    
    /**
     * Signature operation failed.
     * Corresponds to {@link SignatureException}.
     * Template: {0}
     */
    SIGNATURE_FAILED("01", "SignatureFailed", "Signature operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
    
    /**
     * Key management operation failed.
     * Corresponds to {@link KeyManagementException}.
     * Template: {0}
     */
    KEY_MANAGEMENT_FAILED("02", "KeyManagementFailed", "Key management operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
    
    /**
     * File JWKS provider operation failed.
     * Corresponds to {@link FileJwksProviderException}.
     * Template: {0}
     */
    FILE_JWKS_PROVIDER_FAILED("03", "FileJwksProviderFailed", "File JWKS provider operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
    
    /**
     * Prompt encryption operation failed.
     * Corresponds to {@link PromptEncryptionException}.
     * Template: {0}
     */
    PROMPT_ENCRYPTION_FAILED("04", "PromptEncryptionFailed", "Prompt encryption operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
    
    /**
     * Prompt decryption operation failed.
     * Corresponds to {@link PromptDecryptionException}.
     * Template: {0}
     */
    PROMPT_DECRYPTION_FAILED("05", "PromptDecryptionFailed", "Prompt decryption operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR);
    
    /**
     * Domain code for Crypto.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_CRYPTO;
    
    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;
    
    CryptoErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
        this.subCode = subCode;
        this.errorName = errorName;
        this.messageTemplate = messageTemplate;
        this.httpStatus = httpStatus;
    }
    
    @Override
    public String getDomainCode() {
        return DOMAIN_CODE;
    }
    
    @Override
    public String getSubCode() {
        return subCode;
    }
    
    @Override
    public String getErrorName() {
        return errorName;
    }
    
    @Override
    public String getMessageTemplate() {
        return messageTemplate;
    }
    
    @Override
    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}