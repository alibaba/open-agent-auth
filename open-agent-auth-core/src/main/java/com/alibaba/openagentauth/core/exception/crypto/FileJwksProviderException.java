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

import com.alibaba.openagentauth.core.crypto.jwk.FileJwksProvider;

/**
 * Exception thrown when a file-based JWKS provider operation fails.
 * <p>
 * This exception indicates that an error occurred while loading, parsing, or refreshing
 * JWKS (JSON Web Key Set) from a local file system. It provides detailed information
 * about the failure to help diagnose and resolve issues related to file-based key management.
 * </p>
 * <p>
 * <b>Common Causes:</b></p>
 * <ul>
 *   <li>File not found or inaccessible</li>
 *   <li>Invalid file format or corrupted JWKS content</li>
 *   <li>File read permission denied</li>
 *   <li>File refresh or monitoring failure</li>
 *   <li>Malformed JSON content in JWKS file</li>
 * </ul>
 *
 * @see FileJwksProvider
 * @since 1.0
 */
public class FileJwksProviderException extends CryptoException {

    /**
     * The error code for this exception.
     */
    private static final CryptoErrorCode ERROR_CODE = CryptoErrorCode.FILE_JWKS_PROVIDER_FAILED;

    /**
     * Constructs a new file JWKS provider exception with the specified detail message.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     */
    public FileJwksProviderException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new file JWKS provider exception with the specified detail message and cause.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     * @param cause the cause
     */
    public FileJwksProviderException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
