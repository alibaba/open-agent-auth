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
package com.alibaba.openagentauth.core.exception.audit;

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for Audit domain.
 * <p>
 * This enum defines error codes for audit-related operations in the Core module.
 * All audit error codes follow the format: OPEN_AGENT_AUTH_10_02ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_02ZZ
 * </p>
 * <ul>
 *   <li><b>10</b>: Core system code</li>
 *   <li><b>02</b>: Audit domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within Audit domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum AuditErrorCode implements CoreErrorCode {
    
    /**
     * Audit storage operation failed.
     * Corresponds to {@link AuditStorageException}.
     * Template: {0}
     */
    AUDIT_STORAGE_FAILED("01", "AuditStorageFailed", "Audit storage operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
    
    /**
     * Audit processing operation failed.
     * Corresponds to {@link AuditProcessingException}.
     * Template: {0}
     */
    AUDIT_PROCESSING_FAILED("02", "AuditProcessingFailed", "Audit processing operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR);
    
    /**
     * Domain code for Audit.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_AUDIT;
    
    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;
    
    AuditErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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