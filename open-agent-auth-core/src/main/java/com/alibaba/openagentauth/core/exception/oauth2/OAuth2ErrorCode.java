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
package com.alibaba.openagentauth.core.exception.oauth2;

import com.alibaba.openagentauth.core.exception.CoreErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;

/**
 * Error codes for OAuth 2.0 domain.
 * <p>
 * This enum defines error codes for OAuth 2.0-related operations in the Core module.
 * All OAuth 2.0 error codes follow the format: OPEN_AGENT_AUTH_10_04ZZ
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_04ZZ
 * </p>
 * <ul>
 *   <li><b>10</b>: Core system code</li>
 *   <li><b>04</b>: OAuth 2.0 domain code</li>
 *   <li><b>ZZ</b>: Error code (unique within OAuth 2.0 domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public enum OAuth2ErrorCode implements CoreErrorCode {

    /**
     * Dynamic Client Registration (DCR) error.
     * Corresponds to {@link DcrException}.
     * Template: {0}
     */
    DCR_ERROR("01", "DcrError", "Dynamic Client Registration error: {0}", HttpStatus.BAD_REQUEST),

    /**
     * Pushed Authorization Request (PAR) error.
     * Corresponds to {@link ParException}.
     * Template: {0}
     */
    PAR_ERROR("02", "ParError", "Pushed Authorization Request error {0}: {1}", HttpStatus.BAD_REQUEST),

    /**
     * OAuth 2.0 Token error.
     * Corresponds to {@link OAuth2TokenException}.
     * Template: {0}
     */
    TOKEN_ERROR("03", "TokenError", "OAuth 2.0 Token error: {0}", HttpStatus.BAD_REQUEST),

    /**
     * OAuth 2.0 Authorization error.
     * Corresponds to {@link OAuth2AuthorizationException}.
     * Template: {0}
     */
    AUTHORIZATION_ERROR("04", "AuthorizationError", "OAuth 2.0 Authorization error: {0}", HttpStatus.BAD_REQUEST),

    /**
     * Client assertion error.
     * Corresponds to {@link ClientAssertionException}.
     * Template: {0}
     */
    CLIENT_ASSERTION_ERROR("05", "ClientAssertionError", "Client assertion error: {0}", HttpStatus.BAD_REQUEST);

    /**
     * Domain code for OAuth 2.0.
     */
    public static final String DOMAIN_CODE = CoreErrorCode.DOMAIN_CODE_OAUTH2;

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