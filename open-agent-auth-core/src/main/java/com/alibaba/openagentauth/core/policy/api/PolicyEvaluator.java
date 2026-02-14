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
package com.alibaba.openagentauth.core.policy.api;

import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;

import java.util.Map;

/**
 * Interface for policy evaluation operations.
 * <p>
 * The PolicyEvaluator is responsible for evaluating policies against input data
 * to determine authorization decisions. It implements the policy evaluation engine
 * that interprets Rego policies and produces allow/deny decisions.
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li>Evaluate policies against input data</li>
 *   <li>Return allow/deny decisions</li>
 *   <li>Provide detailed evaluation results</li>
 *   <li>Handle evaluation errors gracefully</li>
 * </ul>
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Interface Segregation:</b> This interface focuses solely on evaluation</li>
 *   <li><b>Single Responsibility:</b> Only handles policy evaluation logic</li>
 *   <li><b>Extensibility:</b> Supports multiple evaluation engines (OPA, CEL, etc.)</li>
 *   <li><b>Performance:</b> Implementations should cache compiled policies</li>
 * </ul>
 * </p>
 * <p>
 * <b>Evaluation Process:</b></p>
 * <ol>
 *   <li>Retrieve the policy by ID from the registry</li>
 *   <li>Compile or load the policy</li>
 *   <li>Evaluate the policy against the input data</li>
 *   <li>Return the allow/deny decision</li>
 * </ol>
 * </p>
 *
 * @see <a href="https://www.openpolicyagent.org/docs/latest/">Open Policy Agent</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
public interface PolicyEvaluator {

    /**
     * Evaluates a policy against input data.
     * <p>
     * This method evaluates the policy with the specified ID against the provided
     * input data and returns a boolean decision.
     * </p>
     * <p>
     * The input data is typically a JSON-like structure containing the operation
     * context, user information, and other relevant data needed for evaluation.
     * </p>
     *
     * @param policyId  the policy ID to evaluate
     * @param inputData the input data for evaluation
     * @return true if the policy allows the operation, false otherwise
     */
    boolean evaluate(String policyId, Map<String, Object> inputData);

    /**
     * Evaluates a policy against input data with detailed results.
     * <p>
     * This method evaluates the policy and returns detailed information about
     * the evaluation, including the decision, reasoning, and any errors.
     * </p>
     *
     * @param policyId  the policy ID to evaluate
     * @param inputData the input data for evaluation
     * @return the evaluation result containing the decision and details
     */
    PolicyEvaluationResult evaluateWithDetails(String policyId, Map<String, Object> inputData);

}
