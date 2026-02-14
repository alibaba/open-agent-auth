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
 * Exception thrown when a workload is not found.
 * <p>
 * This exception indicates that a requested workload could not be found in the system.
 * It provides detailed information about the failure to help diagnose and resolve issues.
 * </p>
 * <p>
 * <b>Common Causes:</b></p>
 * <ul>
 *   <li>Invalid workload ID</li>
 *   <li>Workload has been deleted</li>
 *   <li>Workload has expired</li>
 *   <li>Workload not yet created</li>
 * </ul>
 *
 * @since 1.0
 */
public class WorkloadNotFoundException extends WorkloadException {

    /**
     * The error code for this exception.
     */
    private static final WorkloadErrorCode ERROR_CODE = WorkloadErrorCode.WORKLOAD_NOT_FOUND;

    /**
     * Constructs a new workload not found exception with the specified detail message.
     * <p>
     * The message is mapped to the template parameter {0}.
     * </p>
     *
     * @param message the detail message
     */
    public WorkloadNotFoundException(String message) {
        super(ERROR_CODE, message);
    }
}