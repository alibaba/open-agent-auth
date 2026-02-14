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

import com.alibaba.openagentauth.core.exception.CoreException;

/**
 * Base exception for all OIDC (OpenID Connect) domain exceptions.
 * <p>
 * This exception serves as the root for all exceptions in the OIDC domain.
 * All OIDC-related exceptions should extend from this class.
 * </p>
 * <p>
 * <b>Domain Code:</b> 01
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_01ZZ
 * </p>
 *
 * @since 1.0
 */
public abstract class OidcException extends CoreException {

    /**
     * The OIDC RFC error code (e.g., invalid_request, login_required, invalid_id_token).
     */
    private final OidcRfcErrorCode rfcErrorCode;

    /**
     * Constructs a new OIDC exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected OidcException(OidcErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.rfcErrorCode = null;
    }

    /**
     * Constructs a new OIDC exception with the specified error code, RFC error code, and parameters.
     *
     * @param rfcErrorCode the OIDC RFC error code
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected OidcException(OidcRfcErrorCode rfcErrorCode, OidcErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.rfcErrorCode = rfcErrorCode;
    }
    
    /**
     * Constructs a new OIDC exception with the specified error code, cause, and parameters.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected OidcException(OidcErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.rfcErrorCode = null;
    }

    /**
     * Constructs a new OIDC exception with the specified error code, RFC error code, cause, and parameters.
     *
     * @param rfcErrorCode the OIDC RFC error code
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected OidcException(OidcRfcErrorCode rfcErrorCode, OidcErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.rfcErrorCode = rfcErrorCode;
    }

    /**
     * Gets the OIDC RFC error code.
     * <p>
     * This method returns the RFC-compliant OIDC error code (e.g., invalid_request, login_required, invalid_id_token).
     * For the OPEN AGENT AUTH system error code, use {@link #getErrorCode()}.
     * </p>
     *
     * @return the OIDC RFC error code, or null if not available
     */
    public String getRfcErrorCode() {
        return rfcErrorCode != null ? rfcErrorCode.getValue() : null;
    }
}