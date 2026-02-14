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
 * Interface for error codes used in the Open Agent Auth framework.
 * <p>
 * This interface defines the contract for error codes that provide structured
 * error information across the framework. Error codes follow a hierarchical
 * structure that mirrors the exception hierarchy.
 * </p>
 * <p>
 * <b>Error Code Format:</b></p>
 * <pre>
 * OPEN_AGENT_AUTH_XX_YYZZ
 * </pre>
 * <p>
 * Where:
 * </p>
 * <ul>
 *   <li><b>XX</b>: System code (01 for core, 02 for framework)</li>
 *   <li><b>YY</b>: Domain code (unique within a system)</li>
 *   <li><b>ZZ</b>: Error code (unique within a system+domain)</li>
 * </ul>
 * <p>
 * <b>Example:</b></p>
 * <pre>
 * OPEN_AGENT_AUTH_01_0101 - Core module, OIDC domain, authentication error
 * OPEN_AGENT_AUTH_02_0101 - Framework module, auth domain, authentication error
 * </pre>
 *
 * @since 1.0
 */
public interface ErrorCode {

    /**
     * Gets the system code (2 digits).
     *
     * @return the system code
     */
    String getSystemCode();

    /**
     * Gets the domain code (2 digits).
     *
     * @return the domain code
     */
    String getDomainCode();

    /**
     * Gets the sub code (2 digits).
     *
     * @return the sub code
     */
    String getSubCode();

    /**
     * Gets the full error code.
     * <p>
     * The error code follows the format: OPEN_AGENT_AUTH_<system>_<domain><sub>
     * </p>
     *
     * @return the full error code
     */
    default String getErrorCode() {
        return "OPEN_AGENT_AUTH_" + getSystemCode() + "_" + getDomainCode() + getSubCode();
    }

    /**
     * Gets the error name.
     * <p>
     * A descriptive name for the error, typically in UPPER_SNAKE_CASE.
     * </p>
     *
     * @return the error name
     */
    String getErrorName();

    /**
     * Gets the message template.
     * <p>
     * A template string that can be formatted with error parameters.
     * Placeholders should use the format {0}, {1}, {2}, etc. (index-based).
     * </p>
     *
     * @return the message template
     */
    String getMessageTemplate();

    /**
     * Gets the HTTP status code for this error.
     *
     * @return the HTTP status code
     */
    HttpStatus getHttpStatus();

    /**
     * Formats the message using the template with the provided parameters.
     * <p>
     * Uses index-based placeholders {0}, {1}, {2}, etc. to substitute parameters.
     * </p>
     *
     * @param params the parameters to substitute in the template (varargs)
     * @return the formatted message
     */
    default String formatMessage(Object... params) {
        String message = getMessageTemplate();
        if (params == null || params.length == 0) {
            return message;
        }

        for (int i = 0; i < params.length; i++) {
            String placeholder = "{" + i + "}";
            String value = params[i] != null ? params[i].toString() : "null";
            message = message.replace(placeholder, value);
        }

        return message;
    }
}
