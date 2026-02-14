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
 * Exception thrown when prompt encryption fails.
 * <p>
 * This exception indicates an error occurred during the encryption of
 * user prompts using JWE (JSON Web Encryption). Common causes include:
 * </p>
 * <ul>
 *   <li>Invalid encryption key</li>
 *   <li>Unsupported encryption algorithm</li>
 *   <li>Cryptographic operation failures</li>
 *   <li>Invalid input data</li>
 * </ul>
 *
 * @see PromptDecryptionException
 * @since 1.0
 */
public class PromptEncryptionException extends CryptoException {

    /**
     * Constructs a new prompt encryption exception with the specified detail message.
     *
     * @param message the detail message
     */
    public PromptEncryptionException(String message) {
        super(CryptoErrorCode.PROMPT_ENCRYPTION_FAILED, message);
    }

    /**
     * Constructs a new prompt encryption exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public PromptEncryptionException(String message, Throwable cause) {
        super(CryptoErrorCode.PROMPT_ENCRYPTION_FAILED, cause, message);
    }

    /**
     * Constructs a new prompt encryption exception with the specified cause.
     *
     * @param cause the cause
     */
    public PromptEncryptionException(Throwable cause) {
        super(CryptoErrorCode.PROMPT_ENCRYPTION_FAILED, cause, cause.getMessage());
    }
}
