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

/**
 * Exception thrown when prompt decryption fails.
 * <p>
 * This exception indicates an error occurred during the decryption of
 * JWE-encrypted user prompts. Common causes include:
 * </p>
 * <ul>
 *   <li>Invalid decryption key</li>
 *   <li>Corrupted or malformed JWE token</li>
 *   <li>Cryptographic operation failures</li>
 *   <li>Expired or invalid encryption algorithm</li>
 * </ul>
 *
 * @see PromptEncryptionException
 * @since 1.0
 */
public class PromptDecryptionException extends CryptoException {

    /**
     * Constructs a new prompt decryption exception with the specified detail message.
     *
     * @param message the detail message
     */
    public PromptDecryptionException(String message) {
        super(CryptoErrorCode.PROMPT_DECRYPTION_FAILED, message);
    }

    /**
     * Constructs a new prompt decryption exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public PromptDecryptionException(String message, Throwable cause) {
        super(CryptoErrorCode.PROMPT_DECRYPTION_FAILED, cause, message);
    }

    /**
     * Constructs a new prompt decryption exception with the specified cause.
     *
     * @param cause the cause
     */
    public PromptDecryptionException(Throwable cause) {
        super(CryptoErrorCode.PROMPT_DECRYPTION_FAILED, cause, cause.getMessage());
    }
}
