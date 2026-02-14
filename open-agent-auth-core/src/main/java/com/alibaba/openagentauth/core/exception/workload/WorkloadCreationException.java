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
 * Exception thrown when workload creation fails.
 * <p>
 * This exception indicates that an error occurred during workload creation.
 * It provides detailed information about the failure to help diagnose and resolve issues.
 * </p>
 * <p>
 * <b>Common Causes:</b></p>
 * <ul>
 *   <li>Key generation failure</li>
 *   <li>Workload registration failure</li>
 *   <li>Invalid workload configuration</li>
 *   <li>Resource allocation failure</li>
 * </ul>
 *
 * @since 1.0
 */
public class WorkloadCreationException extends WorkloadException {

    /**
     * The error code for this exception.
     */
    private static final WorkloadErrorCode ERROR_CODE = WorkloadErrorCode.WORKLOAD_CREATION_FAILED;

    /**
     * Constructs a new workload creation exception with the specified detail message.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     */
    public WorkloadCreationException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new workload creation exception with the specified detail message and cause.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     * @param cause the cause
     */
    public WorkloadCreationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}