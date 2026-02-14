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

/**
 * Exception thrown when Verifiable Credential verification fails.
 * <p>
 * This exception indicates that an error occurred during VC validation during the verification process.
 * It provides detailed information about the failure to help diagnose and resolve issues.
 * </p>
 * <p>
 * <b>Common Causes:</b></p>
 * <ul>
 *   <li>Invalid signature</li>
 *   <li>Expired credential</li>
 *   <li>Invalid issuer</li>
 *   <li>Missing required claims</li>
 *   <li>Invalid credential type</li>
 * </ul>
 *
 * @since 1.0
 */
public class VcVerificationException extends WorkloadException {

    /**
     * The error code for this exception.
     */
    private static final WorkloadErrorCode ERROR_CODE = WorkloadErrorCode.VC_VERIFICATION_FAILED;

    /**
     * The VC RFC error code (e.g., VC-INVALID-ISSUER, VC-EXPIRED).
     */
    private final String vcErrorCode;

    /**
     * Constructs a new VC verification exception with the specified detail message.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     */
    public VcVerificationException(String message) {
        super(ERROR_CODE, message, null);
        this.vcErrorCode = null;
    }

    /**
     * Constructs a new VC verification exception with the specified detail message and error code.
     * <p>
     * The message and code are mapped to template parameters:
     * - {0}: message
     * - {1}: code
     * </p>
     *
     * @param message the detail message
     * @param code the VC RFC error code
     */
    public VcVerificationException(String message, String code) {
        super(ERROR_CODE, message, code);
        this.vcErrorCode = code;
    }

    /**
     * Constructs a new VC verification exception with the specified detail message and cause.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     * @param cause the cause
     */
    public VcVerificationException(String message, Throwable cause) {
        this(message, null, cause);
    }

    /**
     * Constructs a new VC verification exception with the specified detail message, error code, and cause.
     * <p>
     * The message and code are mapped to template parameters:
     * - {0}: message
     * - {1}: code
     * </p>
     *
     * @param message the detail message
     * @param code the VC RFC error code
     * @param cause the cause
     */
    public VcVerificationException(String message, String code, Throwable cause) {
        super(ERROR_CODE, cause, message, code);
        this.vcErrorCode = code;
    }

    /**
     * Gets the VC RFC error code.
     * <p>
     * This method returns the RFC-compliant VC error code (e.g., VC-INVALID-ISSUER, VC-EXPIRED).
     * For the OPEN AGENT AUTH system error code, use {@link #getErrorCode()}.
     * </p>
     *
     * @return the VC RFC error code, or null if not available
     */
    public String getVcErrorCode() {
        return vcErrorCode;
    }
}