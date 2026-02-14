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
 * Exception thrown when policy evaluation fails.
 * <p>
 * This exception is raised when an error occurs during policy evaluation
 * at runtime. This can happen due to:
 * <ul>
 *   <li>Runtime errors in the Rego policy</li>
 *   <li>Missing input data</li>
 *   <li>Division by zero or other arithmetic errors</li>
 *   <li>Function call failures</li>
 *   <li>Timeout during evaluation</li>
 * </ul>
 * </p>
 *
 * @see PolicyException
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class PolicyEvaluationException extends PolicyException {

    /**
     * The error code for this exception.
     */
    private static final PolicyErrorCode ERROR_CODE = PolicyErrorCode.POLICY_EVALUATION_FAILED;

    /**
     * The input data that caused the evaluation failure, if available.
     */
    private final Object inputData;

    /**
     * Creates a new PolicyEvaluationException with the specified message.
     *
     * @param message the error message
     */
    public PolicyEvaluationException(String message) {
        super(ERROR_CODE, message);
        this.inputData = null;
    }

    /**
     * Creates a new PolicyEvaluationException with the specified message and cause.
     *
     * @param message the error message
     * @param cause the cause
     */
    public PolicyEvaluationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
        this.inputData = null;
    }

    /**
     * Creates a new PolicyEvaluationException with the specified message, cause, and input data.
     *
     * @param message the error message
     * @param cause the cause
     * @param inputData the input data that caused the failure
     */
    public PolicyEvaluationException(String message, Throwable cause, Object inputData) {
        super(ERROR_CODE, cause, message);
        this.inputData = inputData;
    }

    /**
     * Gets the input data that caused the evaluation failure.
     *
     * @return the input data, or null if not available
     */
    public Object getInputData() {
        return inputData;
    }
}
