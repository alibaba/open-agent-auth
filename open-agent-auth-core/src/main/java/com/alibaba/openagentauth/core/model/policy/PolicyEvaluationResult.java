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
package com.alibaba.openagentauth.core.model.policy;

import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;

import java.util.Map;

/**
 * Represents the result of a policy evaluation.
 * <p>
 * This class encapsulates the outcome of a policy evaluation operation,
 * including the allow/deny decision, reasoning, error messages, and any
 * additional output from the evaluation engine.
 * </p>
 * <p>
 * <b>Core Components:</b></p>
 * <ul>
 *   <li><b>allowed:</b> Whether the operation is permitted</li>
 *   <li><b>reasoning:</b> Explanation for the decision</li>
 *   <li><b>errorMessage:</b> Error message if evaluation failed</li>
 *   <li><b>output:</b> Additional structured output from evaluation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Immutability:</b> All fields are final, ensuring thread safety</li>
 *   <li><b>Validation:</b> Clear success/failure state via isSuccess()</li>
 *   <li><b>Extensibility:</b> Output map can contain engine-specific data</li>
 * </ul>
 * </p>
 *
 * @see PolicyEvaluator
 * @see <a href="https://www.openpolicyagent.org/docs/latest/">Open Policy Agent</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
public class PolicyEvaluationResult {

    /**
     * Whether the policy allows the operation.
     */
    private final boolean allowed;

    /**
     * Detailed reasoning or explanation for the decision.
     */
    private final String reasoning;

    /**
     * Error message if evaluation failed.
     */
    private final String errorMessage;

    /**
     * Additional output from the policy evaluation.
     */
    private final Map<String, Object> output;

    /**
     * Creates a new PolicyEvaluationResult.
     *
     * @param allowed       whether the operation is allowed
     * @param reasoning     the reasoning for the decision
     * @param errorMessage  error message if evaluation failed
     * @param output        additional output from evaluation
     */
    public PolicyEvaluationResult(boolean allowed, String reasoning,
                                   String errorMessage, Map<String, Object> output) {
        this.allowed = allowed;
        this.reasoning = reasoning;
        this.errorMessage = errorMessage;
        this.output = output;
    }

    /**
     * Gets whether the operation is allowed.
     *
     * @return true if allowed, false otherwise
     */
    public boolean isAllowed() {
        return allowed;
    }

    /**
     * Gets the reasoning for the decision.
     *
     * @return the reasoning, or null if not available
     */
    public String getReasoning() {
        return reasoning;
    }

    /**
     * Gets the error message if evaluation failed.
     *
     * @return the error message, or null if no error
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Gets the additional output from evaluation.
     *
     * @return the output map, or null if not available
     */
    public Map<String, Object> getOutput() {
        return output;
    }

    /**
     * Checks if the evaluation succeeded without errors.
     *
     * @return true if successful, false otherwise
     */
    public boolean isSuccess() {
        return errorMessage == null;
    }
}
