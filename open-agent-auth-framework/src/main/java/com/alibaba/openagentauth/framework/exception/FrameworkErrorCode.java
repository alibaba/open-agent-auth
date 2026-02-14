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
package com.alibaba.openagentauth.framework.exception;

import com.alibaba.openagentauth.core.exception.ErrorCode;

/**
 * Interface for Framework module error codes.
 * <p>
 * This interface extends the base ErrorCode interface and defines the
 * system code constant for the Framework module. All Framework module
 * error code implementations should implement this interface.
 * </p>
 * <p>
 * <b>System Code:</b> 11
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_11_YYZZ
 * </p>
 * <p>
 * <b>Domain Codes:</b></p>
 * <ul>
 *   <li><b>01</b>: Auth (Authentication & Authorization)</li>
 *   <li><b>02</b>: Token (Token Generation & Validation)</li>
 *   <li><b>03</b>: Validation (Request Validation)</li>
 *   <li><b>04</b>: OAuth2 (OAuth2 Protocol)</li>
 * </ul>
 *
 * <p><b>Note:</b> When adding a new domain, use the next available domain code.
 * Domain codes are managed centrally to avoid conflicts.</p>
 *
 * @since 1.0
 */
public interface FrameworkErrorCode extends ErrorCode {

    /**
     * System code for Framework module.
     */
    String SYSTEM_CODE = "11";

    /**
     * Domain code for Auth (Authentication & Authorization).
     */
    String DOMAIN_CODE_AUTH = "01";

    /**
     * Domain code for Token (Token Generation & Validation).
     */
    String DOMAIN_CODE_TOKEN = "02";

    /**
     * Domain code for Validation (Request Validation).
     */
    String DOMAIN_CODE_VALIDATION = "03";

    /**
     * Domain code for OAuth2 (OAuth2 Protocol).
     */
    String DOMAIN_CODE_OAUTH2 = "04";

    @Override
    default String getSystemCode() {
        return SYSTEM_CODE;
    }
}