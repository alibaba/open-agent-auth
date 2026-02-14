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
package com.alibaba.openagentauth.core.exception.policy;

/**
 * Exception thrown when policy validation fails.
 * <p>
 * This exception is raised when a policy fails validation during registration
 * or evaluation. Validation failures can occur due to:
 * <ul>
 *   <li>Invalid Rego syntax</li>
 *   <li>Semantic errors in the policy</li>
 *   <li>Security constraint violations</li>
 *   <li>Missing required fields</li>
 *   <li>Policy complexity violations</li>
 * </ul>
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization, the Authorization Server
 * MUST validate policies before registration and issuance of access tokens.
 * </p>
 *
 * @see PolicyException
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class PolicyValidationException extends PolicyException {

    /**
     * The error code for this exception.
     */
    private static final PolicyErrorCode ERROR_CODE = PolicyErrorCode.POLICY_VALIDATION_FAILED;

    /**
     * Validation error type.
     * <p>
     * Indicates the category of validation error that occurred.
     * </p>
     */
    private final ValidationErrorType errorType;

    /**
     * Line number where the error occurred, if applicable.
     */
    private final Integer lineNumber;

    /**
     * Column number where the error occurred, if applicable.
     */
    private final Integer columnNumber;

    /**
     * Enumeration of validation error types.
     */
    public enum ValidationErrorType {
        /**
         * Invalid Rego syntax.
         */
        SYNTAX_ERROR,

        /**
         * Semantic error in the policy.
         */
        SEMANTIC_ERROR,

        /**
         * Policy violates security constraints.
         */
        SECURITY_VIOLATION,

        /**
         * Missing required field.
         */
        MISSING_REQUIRED_FIELD,

        /**
         * Policy exceeds complexity limits.
         */
        COMPLEXITY_VIOLATION,

        /**
         * Policy uses unsupported features.
         */
        UNSUPPORTED_FEATURE,

        /**
         * Generic validation error.
         */
        VALIDATION_ERROR
    }

    /**
     * Creates a new PolicyValidationException with the specified message.
     *
     * @param message the error message
     */
    public PolicyValidationException(String message) {
        super(ERROR_CODE, message);
        this.errorType = ValidationErrorType.VALIDATION_ERROR;
        this.lineNumber = null;
        this.columnNumber = null;
    }

    /**
     * Creates a new PolicyValidationException with the specified message and cause.
     *
     * @param message the error message
     * @param cause the cause
     */
    public PolicyValidationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
        this.errorType = ValidationErrorType.VALIDATION_ERROR;
        this.lineNumber = null;
        this.columnNumber = null;
    }

    /**
     * Creates a new PolicyValidationException with the specified message and error type.
     *
     * @param message the error message
     * @param errorType the validation error type
     */
    public PolicyValidationException(String message, ValidationErrorType errorType) {
        super(ERROR_CODE, message);
        this.errorType = errorType;
        this.lineNumber = null;
        this.columnNumber = null;
    }

    /**
     * Creates a new PolicyValidationException with the specified message, error type, and location.
     *
     * @param message the error message
     * @param errorType the validation error type
     * @param lineNumber the line number where the error occurred
     * @param columnNumber the column number where the error occurred
     */
    public PolicyValidationException(String message, ValidationErrorType errorType,
                                      Integer lineNumber, Integer columnNumber) {
        super(ERROR_CODE, message);
        this.errorType = errorType;
        this.lineNumber = lineNumber;
        this.columnNumber = columnNumber;
    }

    /**
     * Gets the validation error type.
     *
     * @return the error type
     */
    public ValidationErrorType getErrorType() {
        return errorType;
    }

    /**
     * Gets the line number where the error occurred.
     *
     * @return the line number, or null if not available
     */
    public Integer getLineNumber() {
        return lineNumber;
    }

    /**
     * Gets the column number where the error occurred.
     *
     * @return the column number, or null if not available
     */
    public Integer getColumnNumber() {
        return columnNumber;
    }

    /**
     * Creates a new PolicyValidationException for a syntax error.
     *
     * @param message    the error message
     * @param lineNumber the line number where the error occurred
     * @return a new PolicyValidationException
     */
    public static PolicyValidationException syntaxError(String message, int lineNumber) {
        return new PolicyValidationException(message, ValidationErrorType.SYNTAX_ERROR,
                lineNumber, null);
    }

    /**
     * Creates a new PolicyValidationException for a semantic error.
     *
     * @param message the error message
     * @return a new PolicyValidationException
     */
    public static PolicyValidationException semanticError(String message) {
        return new PolicyValidationException(message, ValidationErrorType.SEMANTIC_ERROR);
    }

    /**
     * Creates a new PolicyValidationException for a security violation.
     *
     * @param message the error message
     * @return a new PolicyValidationException
     */
    public static PolicyValidationException securityViolation(String message) {
        return new PolicyValidationException(message, ValidationErrorType.SECURITY_VIOLATION);
    }

    /**
     * Creates a new PolicyValidationException for a missing required field.
     *
     * @param fieldName the name of the missing field
     * @return a new PolicyValidationException
     */
    public static PolicyValidationException missingRequiredField(String fieldName) {
        return new PolicyValidationException(
                "Missing required field: " + fieldName,
                ValidationErrorType.MISSING_REQUIRED_FIELD
        );
    }
}
