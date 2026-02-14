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

import com.alibaba.openagentauth.framework.exception.FrameworkException;

/**
 * Base exception for all Token domain exceptions (Token Generation & Validation).
 * <p>
 * This exception serves as the root for all exceptions in the Token domain.
 * All token-related exceptions should extend from this class.
 * </p>
 * <p>
 * <b>Domain Code:</b> 02
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_02_02ZZ
 * </p>
 *
 * @since 1.0
 */
public abstract class TokenException extends FrameworkException {

    /**
     * Constructs a new Token exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected TokenException(TokenErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
    }

    /**
     * Constructs a new Token exception with the specified error code, cause, and parameters.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected TokenException(TokenErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
    }
}
