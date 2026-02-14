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
package com.alibaba.openagentauth.core.exception.policy;

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for Policy domain.
 * <p>
 * This enum defines error codes for policy-related operations in the Core module.
 * All Policy error codes follow the format: OPEN_AGENT_AUTH_10_05ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_05ZZ
 * </p>
 * <ul>
 *   <li><b>10</b>: Core system code</li>
 *   <li><b>05</b>: Policy domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Policy domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum PolicyErrorCode implements CoreErrorCode {

    /**
     * Policy not found.
     * Corresponds to {@link PolicyNotFoundException}.
     * Template: {0}
     */
    POLICY_NOT_FOUND("01", "PolicyNotFound", "Policy not found: {0}", HttpStatus.NOT_FOUND),

    /**
     * Policy evaluation failed.
     * Corresponds to {@link PolicyEvaluationException}.
     * Template: {0}
     */
    POLICY_EVALUATION_FAILED("02", "PolicyEvaluationFailed", "Policy evaluation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),

    /**
     * Policy validation failed.
     * Corresponds to {@link PolicyValidationException}.
     * Template: {0}
     */
    POLICY_VALIDATION_FAILED("03", "PolicyValidationFailed", "Policy validation failed: {0}", HttpStatus.BAD_REQUEST),

    /**
     * Policy registration failed.
     * Corresponds to {@link PolicyRegistrationException}.
     * Template: {0}
     */
    POLICY_REGISTRATION_FAILED("04", "PolicyRegistrationFailed", "Policy registration failed: {0}", HttpStatus.BAD_REQUEST);

    /**
     * Domain code for Policy.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_POLICY;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;

    PolicyErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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