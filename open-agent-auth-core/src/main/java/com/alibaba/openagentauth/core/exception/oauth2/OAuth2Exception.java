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

import com.alibaba.openagentauth.core.exception.CoreException;

/**
 * Base exception for all OAuth 2.0 domain exceptions.
 * <p>
 * This exception serves as the root for all exceptions in the OAuth 2.0 domain.
 * All OAuth 2.0-related exceptions should extend from this class.
 * </p>
 * <p>
 * <b>Domain Code:</b> 04
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_04ZZ
 * </p>
 *
 * @since 1.0
 */
public abstract class OAuth2Exception extends CoreException {

    /**
     * The OAuth 2.0 RFC error code (e.g., invalid_request, invalid_client, unauthorized_client).
     */
    private final OAuth2RfcErrorCode rfcErrorCode;

    /**
     * Constructs a new OAuth 2.0 exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected OAuth2Exception(OAuth2ErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.rfcErrorCode = null;
    }

    /**
     * Constructs a new OAuth 2.0 exception with the specified error code, RFC error code, and parameters.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorCode    the error code
     * @param errorParams  the error parameters (varargs)
     */
    protected OAuth2Exception(OAuth2RfcErrorCode rfcErrorCode, OAuth2ErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.rfcErrorCode = rfcErrorCode;
    }

    /**
     * Constructs a new OAuth 2.0 exception with the specified error code, cause, and parameters.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected OAuth2Exception(OAuth2ErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.rfcErrorCode = null;
    }

    /**
     * Constructs a new OAuth 2.0 exception with the specified error code, RFC error code, cause, and parameters.
     *
     * @param rfcErrorCode the OAuth 2.0 RFC error code
     * @param errorCode    the error code
     * @param cause        the cause
     * @param errorParams  the error parameters (varargs)
     */
    protected OAuth2Exception(OAuth2RfcErrorCode rfcErrorCode, OAuth2ErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.rfcErrorCode = rfcErrorCode;
    }

    /**
     * Gets the OAuth 2.0 RFC error code.
     * <p>
     * This method returns the RFC-compliant OAuth 2.0 error code (e.g., invalid_request, invalid_client, unauthorized_client).
     * For the OPEN AGENT AUTH system error code, use {@link #getErrorCode()}.
     * </p>
     *
     * @return the OAuth 2.0 RFC error code, or null if not available
     */
    public String getRfcErrorCode() {
        return rfcErrorCode != null ? rfcErrorCode.getValue() : null;
    }

}