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
package com.alibaba.openagentauth.core.exception.workload;

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for Workload domain.
 * <p>
 * This enum defines error codes for workload-related operations in the Core module.
 * All workload error codes follow the format: OPEN_AGENT_AUTH_10_06ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_06ZZ
 * </p>
 * <ul>
 *   <li><b>10</b>: Core system code</li>
 *   <li><b>06</b>: Workload domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Workload domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum WorkloadErrorCode implements CoreErrorCode {
    
    /**
     * Verifiable Credential verification failed.
     * Corresponds to {@link VcVerificationException}.
     * Template: {0}: {1}
     */
    VC_VERIFICATION_FAILED("01", "VcVerificationFailed", "VC verification failed: {0} (Code: {1})", HttpStatus.BAD_REQUEST),
    
    /**
     * Workload creation failed.
     * Corresponds to {@link WorkloadCreationException}.
     * Template: {0}
     */
    WORKLOAD_CREATION_FAILED("02", "WorkloadCreationFailed", "Workload creation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
    
    /**
     * Workload not found.
     * Corresponds to {@link WorkloadNotFoundException}.
     * Template: {0}
     */
    WORKLOAD_NOT_FOUND("03", "WorkloadNotFound", "Workload not found: {0}", HttpStatus.NOT_FOUND);
    
    /**
     * Domain code for Workload.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_WORKLOAD;
    
    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;
    
    WorkloadErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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