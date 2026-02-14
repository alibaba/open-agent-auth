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
package com.alibaba.openagentauth.core.exception.binding;

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for Binding domain.
 * <p>
 * This enum defines error codes for binding-related operations in the Core module.
 * All Binding error codes follow the format: OPEN_AGENT_AUTH_10_07ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_07ZZ
 * </p>
 * <ul>
 *   <li><b>10</b>: Core system code</li>
 *   <li><b>07</b>: Binding domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Binding domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum BindingErrorCode implements CoreErrorCode {

    /**
     * Binding not found.
     * Template: Binding instance not found: {0}
     */
    BINDING_NOT_FOUND("01", "BindingNotFound", "Binding instance not found: {0}", HttpStatus.NOT_FOUND),

    /**
     * Binding has expired.
     * Template: Binding instance has expired: {0}
     */
    BINDING_EXPIRED("02", "BindingExpired", "Binding instance has expired: {0}", HttpStatus.NOT_FOUND),

    /**
     * Binding validation failed.
     * Template: Binding validation failed: {0}
     */
    BINDING_VALIDATION_FAILED("03", "BindingValidationFailed", "Binding validation failed: {0}", HttpStatus.BAD_REQUEST),

    /**
     * Binding already exists.
     * Template: Binding instance already exists: {0}
     */
    BINDING_ALREADY_EXISTS("04", "BindingAlreadyExists", "Binding instance already exists: {0}", HttpStatus.CONFLICT);

    /**
     * Domain code for Binding.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_BINDING;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;

    BindingErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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