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
 * Exception thrown when policy registration fails.
 * <p>
 * This exception is raised when an error occurs during policy registration.
 * Registration failures can occur due to:
 * <ul>
 *   <li>Policy validation failures</li>
 *   <li>Duplicate policy ID</li>
 *   <li>Storage errors</li>
 *   <li>Registration quota exceeded</li>
 *   <li>Insufficient permissions</li>
 * </ul>
 * </p>
 *
 * @see PolicyException
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class PolicyRegistrationException extends PolicyException {

    /**
     * The error code for this exception.
     */
    private static final PolicyErrorCode ERROR_CODE = PolicyErrorCode.POLICY_REGISTRATION_FAILED;

    /**
     * Registration error type.
     */
    private final RegistrationErrorType errorType;

    /**
     * Enumeration of registration error types.
     */
    public enum RegistrationErrorType {
        /**
         * Policy validation failed.
         */
        VALIDATION_FAILED,

        /**
         * Policy with the same ID already exists.
         */
        DUPLICATE_POLICY,

        /**
         * Storage error (database, file system, etc.).
         */
        STORAGE_ERROR,

        /**
         * Registration quota exceeded.
         */
        QUOTA_EXCEEDED,

        /**
         * Insufficient permissions.
         */
        PERMISSION_DENIED,

        /**
         * Generic registration error.
         */
        REGISTRATION_ERROR
    }

    /**
     * Creates a new PolicyRegistrationException with the specified message.
     *
     * @param message the error message
     */
    public PolicyRegistrationException(String message) {
        super(ERROR_CODE, message);
        this.errorType = RegistrationErrorType.REGISTRATION_ERROR;
    }

    /**
     * Creates a new PolicyRegistrationException with the specified message and cause.
     *
     * @param message the error message
     * @param cause the cause
     */
    public PolicyRegistrationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
        this.errorType = RegistrationErrorType.REGISTRATION_ERROR;
    }

    /**
     * Creates a new PolicyRegistrationException with the specified message and error type.
     *
     * @param message the error message
     * @param errorType the registration error type
     */
    public PolicyRegistrationException(String message, RegistrationErrorType errorType) {
        super(ERROR_CODE, message);
        this.errorType = errorType;
    }

    /**
     * Creates a new PolicyRegistrationException with the specified message, cause, and error type.
     *
     * @param message the error message
     * @param cause the cause
     * @param errorType the registration error type
     */
    public PolicyRegistrationException(String message, Throwable cause, RegistrationErrorType errorType) {
        super(ERROR_CODE, cause, message);
        this.errorType = errorType;
    }

    /**
     * Creates a new PolicyRegistrationException for a validation failure.
     *
     * @param message the validation error message
     * @return a new PolicyRegistrationException
     */
    public static PolicyRegistrationException validationFailed(String message) {
        return new PolicyRegistrationException(
                "Policy validation failed: " + message,
                RegistrationErrorType.VALIDATION_FAILED
        );
    }

    /**
     * Creates a new PolicyRegistrationException for a duplicate policy.
     *
     * @param policyId the duplicate policy ID
     * @return a new PolicyRegistrationException
     */
    public static PolicyRegistrationException duplicatePolicy(String policyId) {
        return new PolicyRegistrationException(
                "Policy already exists: " + policyId,
                RegistrationErrorType.DUPLICATE_POLICY
        );
    }

    /**
     * Creates a new PolicyRegistrationException for a storage error.
     *
     * @param message   the error message
     * @param cause     the underlying cause
     * @return a new PolicyRegistrationException
     */
    public static PolicyRegistrationException storageError(String message, Throwable cause) {
        return new PolicyRegistrationException(
                "Storage error: " + message,
                cause,
                RegistrationErrorType.STORAGE_ERROR
        );
    }

    /**
     * Gets the registration error type.
     *
     * @return the error type
     */
    public RegistrationErrorType getErrorType() {
        return errorType;
    }
}
