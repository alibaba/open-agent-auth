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
package com.alibaba.openagentauth.framework.exception.oauth2;

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;

/**
 * Error codes for OAuth2 domain (OAuth2 Protocol).
 * <p>
 * This enum defines error codes for OAuth2-related operations in the Framework module.
 * All OAuth2 error codes follow the format: OPEN_AGENT_AUTH_02_04ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_02_04ZZ
 * </p>
 * <ul>
 *   <li><b>02</b>: Framework system code</li>
 *   <li><b>04</b>: OAuth2 domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within OAuth2 domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum OAuth2ErrorCode implements FrameworkErrorCode {

    /**
     * PAR (Pushed Authorization Request) processing failed.
     * Corresponds to {@link FrameworkParProcessingException}.
     * Template: {0}
     */
    PAR_PROCESSING_FAILED("01", "FrameworkParProcessingFailed", "Framework PAR processing failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR);

    /**
     * Domain code for OAuth2.
     */
    public static final String DOMAIN_CODE = FrameworkErrorCode.DOMAIN_CODE_OAUTH2;

    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;

    OAuth2ErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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
