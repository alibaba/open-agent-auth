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
package com.alibaba.openagentauth.core.exception;

/**
 * Interface for Core module error codes.
 * <p>
 * This interface extends the base ErrorCode interface and defines the
 * system code constant for the Core module. All Core module error code
 * implementations should implement this interface.
 * </p>
 * <p>
 * <b>System Code:</b> 10
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_YYZZ
 * </p>
 * <p>
 * <b>Domain Codes:</b></p>
 * <ul>
 *   <li><b>01</b>: OIDC (OpenID Connect)</li>
 *   <li><b>02</b>: Audit</li>
 *   <li><b>03</b>: Crypto</li>
 *   <li><b>04</b>: OAuth 2.0</li>
 *   <li><b>05</b>: Policy</li>
 *   <li><b>06</b>: Workload</li>
 *   <li><b>07</b>: Binding</li>
 * </ul>
 *
 * <p><b>Note:</b> When adding a new domain, use the next available domain code.
 * Domain codes are managed centrally to avoid conflicts.</p>
 *
 * @since 1.0
 */
public interface CoreErrorCode extends ErrorCode {

    /**
     * System code for Core module.
     */
    String SYSTEM_CODE = "10";

    /**
     * Domain code for OIDC (OpenID Connect).
     */
    String DOMAIN_CODE_OIDC = "01";

    /**
     * Domain code for Audit.
     */
    String DOMAIN_CODE_AUDIT = "02";

    /**
     * Domain code for Crypto.
     */
    String DOMAIN_CODE_CRYPTO = "03";

    /**
     * Domain code for OAuth 2.0.
     */
    String DOMAIN_CODE_OAUTH2 = "04";

    /**
     * Domain code for Policy.
     */
    String DOMAIN_CODE_POLICY = "05";

    /**
     * Domain code for Workload.
     */
    String DOMAIN_CODE_WORKLOAD = "06";

    /**
     * Domain code for Binding.
     */
    String DOMAIN_CODE_BINDING = "07";

    @Override
    default String getSystemCode() {
        return SYSTEM_CODE;
    }
}