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

/**
 * Exception thrown when an audit storage operation fails.
 * <p>
 * This exception indicates that an error occurred during storage,
 * retrieval, deletion, or any other audit storage operation.
 * It provides detailed information about the failure to help diagnose
 * and resolve issues.
 * </p>
 * <p>
 * <b>Common Causes:</b></p>
 * <ul>
 *   <li>Database connection failure</li>
 *   <li>Storage quota exceeded</li>
 *   <li>Invalid audit record format</li>
 *   <li>Storage service unavailable</li>
 *   <li>Permission denied</li>
 * </ul>
 *
 * @since 1.0
 */
public class AuditStorageException extends AuditException {

    /**
     * The error code for this exception.
     */
    private static final AuditErrorCode ERROR_CODE = AuditErrorCode.AUDIT_STORAGE_FAILED;

    /**
     * Constructs a new audit storage exception with the specified detail message.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     */
    public AuditStorageException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new audit storage exception with the specified detail message and cause.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     * @param cause the cause
     */
    public AuditStorageException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}