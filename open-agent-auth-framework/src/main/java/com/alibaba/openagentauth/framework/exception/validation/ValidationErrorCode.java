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
package com.alibaba.openagentauth.framework.exception.validation;

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;

/**
 * Error codes for Validation domain (Request Validation).
 * <p>
 * This enum defines error codes for validation-related operations in the Framework module.
 * All Validation error codes follow the format: OPEN_AGENT_AUTH_02_03ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_02_03ZZ
 * </p>
 * <ul>
 *   <li><b>02</b>: Framework system code</li>
 *   <li><b>03</b>: Validation domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Validation domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum ValidationErrorCode implements FrameworkErrorCode {

    /**
     * Request validation failed.
     * Corresponds to {@link FrameworkValidationException}.
     * Template: {0}
     */
    VALIDATION_FAILED("01", "FrameworkValidationFailed", "Framework validation failed: {0}", HttpStatus.BAD_REQUEST),

    /**
     * Authorization context preparation failed.
     * Corresponds to {@link FrameworkAuthorizationContextException}.
     * Template: {0}
     */
    AUTHORIZATION_CONTEXT_PREPARATION_FAILED("02", "FrameworkAuthContextPreparationFailed", "Framework authorization context preparation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR);

    /**
     * Domain code for Validation.
     */
    public static final String DOMAIN_CODE = FrameworkErrorCode.DOMAIN_CODE_VALIDATION;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;

    ValidationErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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
