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

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Base exception for all Open Agent Auth exceptions.
 * <p>
 * This is the root exception class for the entire Open Agent Auth framework.
 * All exceptions, whether in the core module or framework module, should extend
 * from this base class to ensure consistent error handling and reporting.
 * </p>
 * <p>
 * <b>Key Features:</b></p>
 * <ul>
 *   <li>Provides a unified exception hierarchy</li>
 *   <li>Supports structured error information through error codes</li>
 *   <li>Enables consistent error message formatting</li>
 *   <li>Facilitates error tracking and debugging</li>
 * </ul>
 *
 * @since 1.0
 */
public abstract class OpenAgentAuthException extends RuntimeException {
    
    /**
     * The error code associated with this exception.
     */
    private final String errorCode;

    /**
     * The error parameters used for message formatting.
     */
    private final List<Object> errorParams;

    /**
     * The context information associated with this exception.
     */
    private final Map<String, Object> context;

    /**
     * The formatted error message.
     */
    private final String formattedMessage;

    /**
     * Constructs a new Open Agent Auth exception with the specified error code and message.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     */
    protected OpenAgentAuthException(String errorCode, String formattedMessage) {
        super(formattedMessage);
        this.errorCode = errorCode;
        this.errorParams = null;
        this.context = null;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Constructs a new Open Agent Auth exception with the specified error code, message, and cause.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     * @param cause the cause
     */
    protected OpenAgentAuthException(String errorCode, String formattedMessage, Throwable cause) {
        super(formattedMessage, cause);
        this.errorCode = errorCode;
        this.errorParams = null;
        this.context = null;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Constructs a new Open Agent Auth exception with the specified error code, message,
     * error parameters, and context.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     * @param errorParams the error parameters
     * @param context the context information
     */
    protected OpenAgentAuthException(String errorCode, String formattedMessage,
                                     List<Object> errorParams, Map<String, Object> context) {
        super(formattedMessage);
        this.errorCode = errorCode;
        this.errorParams = errorParams != null ? Collections.unmodifiableList(errorParams) : null;
        this.context = context;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Constructs a new Open Agent Auth exception with the specified error code, message,
     * error parameters, context, and cause.
     *
     * @param errorCode the error code
     * @param formattedMessage the formatted error message
     * @param errorParams the error parameters
     * @param context the context information
     * @param cause the cause
     */
    protected OpenAgentAuthException(String errorCode, String formattedMessage,
                                     List<Object> errorParams, Map<String, Object> context,
                                     Throwable cause) {
        super(formattedMessage, cause);
        this.errorCode = errorCode;
        this.errorParams = errorParams != null ? Collections.unmodifiableList(errorParams) : null;
        this.context = context;
        this.formattedMessage = formattedMessage;
    }

    /**
     * Gets the error code.
     *
     * @return the error code
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Gets the error parameters.
     *
     * @return the error parameters (unmodifiable list), or null if not set
     */
    public List<Object> getErrorParams() {
        return errorParams;
    }

    /**
     * Gets the context information.
     *
     * @return the context information, or null if not set
     */
    public Map<String, Object> getContext() {
        return context;
    }

    /**
     * Gets the formatted error message.
     *
     * @return the formatted error message
     */
    public String getFormattedMessage() {
        return formattedMessage;
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "{" +
                "errorCode='" + errorCode + '\'' +
                ", formattedMessage='" + formattedMessage + '\'' +
                '}';
    }
}
