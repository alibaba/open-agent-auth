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

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;

/**
 * Error codes for Token domain (Token Generation & Validation).
 * <p>
 * This enum defines error codes for token-related operations in the Framework module.
 * All Token error codes follow the format: OPEN_AGENT_AUTH_02_02ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_02_02ZZ
 * </p>
 * <ul>
 *   <li><b>02</b>: Framework system code</li>
 *   <li><b>02</b>: Token domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Token domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum TokenErrorCode implements FrameworkErrorCode {

    /**
     * Token generation failed.
     * Corresponds to {@link FrameworkTokenGenerationException}.
     * Template: {0}
     */
    TOKEN_GENERATION_FAILED("01", "FrameworkTokenGenerationFailed", "Framework token generation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),

    /**
     * Token validation failed.
     * Corresponds to {@link FrameworkTokenValidationException}.
     * Template: {0}
     */
    TOKEN_VALIDATION_FAILED("02", "FrameworkTokenValidationFailed", "Framework token validation failed: {0}", HttpStatus.UNAUTHORIZED);

    /**
     * Domain code for Token.
     */
    public static final String DOMAIN_CODE = FrameworkErrorCode.DOMAIN_CODE_TOKEN;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;

    TokenErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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
