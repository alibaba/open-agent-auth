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
package com.alibaba.openagentauth.framework.exception.oauth2;

/**
 * Exception thrown when PAR (Pushed Authorization Request) processing fails in framework orchestration layer.
 * <p>
 * This exception indicates that the PAR processing failed in the framework orchestration layer,
 * such as invalid PAR request, processing errors, or service failures.
 * </p>
 *
 * @since 1.0
 */
public class FrameworkParProcessingException extends OAuth2Exception {

    /**
     * The error code for this exception.
     */
    private static final OAuth2ErrorCode ERROR_CODE = OAuth2ErrorCode.PAR_PROCESSING_FAILED;

    /**
     * Constructs a new framework PAR processing exception with the specified detail message.
     *
     * @param message the detail message
     */
    public FrameworkParProcessingException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new framework PAR processing exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public FrameworkParProcessingException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
