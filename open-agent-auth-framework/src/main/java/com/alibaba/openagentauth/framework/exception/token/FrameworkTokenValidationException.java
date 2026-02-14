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
package com.alibaba.openagentauth.framework.exception.token;

/**
 * Exception thrown when token validation fails in framework orchestration layer.
 * <p>
 * This exception indicates that the token validation process failed in the framework
 * orchestration layer due to invalid token signature, expired token, or validation errors.
 * </p>
 *
 * @since 1.0
 */
public class FrameworkTokenValidationException extends TokenException {

    /**
     * The error code for this exception.
     */
    private static final TokenErrorCode ERROR_CODE = TokenErrorCode.TOKEN_VALIDATION_FAILED;

    /**
     * Constructs a new framework token validation exception with the specified detail message.
     *
     * @param message the detail message
     */
    public FrameworkTokenValidationException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new framework token validation exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public FrameworkTokenValidationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
