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
package com.alibaba.openagentauth.core.exception.oidc;

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for OIDC (OpenID Connect) domain.
 * <p>
 * This enum defines error codes for OIDC-related operations in the Core module.
 * All OIDC error codes follow the format: OPEN_AGENT_AUTH_01_01ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_01_01ZZ
 * </p>
 * <ul>
 *   <li><b>01</b>: Core system code</li>
 *   <li><b>01</b>: OIDC domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within OIDC domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum OidcErrorCode implements CoreErrorCode {
    
    /**
     * Authentication failed.
     * Corresponds to {@link AuthenticationException}.
     * Template: {0}: {1}
     */
    AUTHENTICATION_FAILED("01", "AuthenticationFailed", "Authentication failed: {0}", HttpStatus.UNAUTHORIZED),
    
    /**
     * ID token format error.
     * Corresponds to {@link IdTokenException}.
     * Template: {0}
     */
    ID_TOKEN_FORMAT_ERROR("02", "IdTokenFormatError", "ID token format error: {0}", HttpStatus.BAD_REQUEST);
    
    /**
     * Domain code for OIDC.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_OIDC;
    
    private final String subCode;
    private final String errorName;
    private final String messageTemplate;
    private final HttpStatus httpStatus;
    
    OidcErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
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