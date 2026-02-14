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
package com.alibaba.openagentauth.core.validation.layer;

import com.alibaba.openagentauth.core.model.context.AgentOperationAuthorization;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Layer 5 validator for policy evaluation and authorization decision.
 * <p>
 * This validator evaluates the OPA policy to determine if the requested operation
 * should be allowed. It extracts the policy ID from the AOAT, constructs
 * the evaluation context, and delegates to the policy evaluator.
 * </p>
 * <p>
 * <b>Policy Evaluation Flow:</b>
 * <ol>
 *   <li>Extract policy ID from AOAT (agent_operation_authorization.policy_id)</li>
 *   <li>Extract policy context from request (HTTP method, URI, headers, body)</li>
 *   <li>Build evaluation input with user identity, workload identity, and request context</li>
 *   <li>Evaluate the policy using the policy evaluator</li>
 *   <li>Return authorization decision</li>
 * </ol>
 * </p>
 * <p>
 * <b>Protocol References:</b>
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a> - Agent Operation Authorization</li>
 *   <li><a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a></li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @see PolicyEvaluator
 * @since 1.0
 */
public class PolicyEvaluationValidator implements LayerValidator {

    /**
     * The logger for policy evaluation validator.
     */
    private static final Logger logger = LoggerFactory.getLogger(PolicyEvaluationValidator.class);

    /**
     * The delegated policy evaluator.
     */
    private final PolicyEvaluator policyEvaluator;

    /**
     * Creates a new policy evaluation validator.
     *
     * @param policyEvaluator the policy evaluator to delegate to
     * @throws IllegalArgumentException if policyEvaluator is null
     */
    public PolicyEvaluationValidator(PolicyEvaluator policyEvaluator) {
        ValidationUtils.validateNotNull(policyEvaluator, "PolicyEvaluator");
        this.policyEvaluator = policyEvaluator;
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 5: Policy Evaluation");

        // Check if AOAT is present
        if (context.getAgentOaToken() == null) {
            logger.error("AOAT is missing from validation context");
            return LayerValidationResult.failure(
                "AOAT is required for policy evaluation"
            );
        }

        AgentOperationAuthToken aoat = context.getAgentOaToken();

        // Extract policy ID from AOAT
        String policyId = extractPolicyId(aoat);
        if (ValidationUtils.isNullOrEmpty(policyId)) {
            logger.error("AOAT is missing policy ID");
            return LayerValidationResult.failure(
                "AOAT is missing policy ID in agent_operation_authorization",
                "Layer 5 Policy Evaluation"
            );
        }

        // Build evaluation input
        Map<String, Object> input = buildEvaluationInput(context, aoat);

        try {
            // Delegate to the policy evaluator
            PolicyEvaluationResult result = policyEvaluator.evaluateWithDetails(policyId, input);
            
            if (result.isAllowed()) {
                logger.debug("Layer 5: Policy evaluation passed - operation allowed");
                return LayerValidationResult.success(
                    "Layer 5: Policy evaluation completed successfully - operation allowed"
                );
            } else {
                logger.error("Layer 5: Policy evaluation failed - operation denied: {}", result.getReasoning());
                return LayerValidationResult.failure(
                    "Operation denied by policy: " + result.getReasoning(),
                    "Layer 5 Policy Evaluation"
                );
            }
        } catch (Exception e) {
            logger.error("Error evaluating policy", e);
            return LayerValidationResult.failure(
                "Policy evaluation failed: " + e.getMessage(),
                "Layer 5 Policy Evaluation"
            );
        }
    }

    /**
     * Extracts the policy ID from the AOAT.
     *
     * @param aoat the Agent Operation Authorization Token
     * @return the policy ID, or null if not present
     */
    private String extractPolicyId(AgentOperationAuthToken aoat) {
        AgentOperationAuthorization authorization = aoat.getAuthorization();
        if (authorization == null) {
            return null;
        }
        return authorization.getPolicyId();
    }

    /**
     * Builds the evaluation input for policy evaluation.
     * <p>
     * The input includes:
     * <ul>
     *   <li>user: User identity from AOAT</li>
     *   <li>agent: Agent identity from AOAT</li>
     *   <li>request: HTTP request context (method, URI, headers, body)</li>
     *   <li>timestamp: Request timestamp</li>
     * </ul>
     * </p>
     *
     * @param context the validation context
     * @param aoat the Agent Operation Authorization Token
     * @return the evaluation input map
     */
    private Map<String, Object> buildEvaluationInput(ValidationContext context, AgentOperationAuthToken aoat) {
        Map<String, Object> input = new HashMap<>();

        // Add user identity
        Map<String, String> user = new HashMap<>();
        user.put("id", aoat.getSubject());
        user.put("issuer", aoat.getIssuer());
        input.put("user", user);

        // Add agent identity
        if (aoat.getAgentIdentity() != null) {
            Map<String, String> agent = new HashMap<>();
            agent.put("id", aoat.getAgentIdentity().getId());
            agent.put("issuer", aoat.getAgentIdentity().getIssuer());
            agent.put("issuedTo", aoat.getAgentIdentity().getIssuedTo());
            input.put("agent", agent);
        }

        // Add request context
        Map<String, Object> request = new HashMap<>();
        request.put("method", context.getHttpMethod());
        request.put("uri", context.getHttpUri());
        request.put("headers", context.getHttpHeaders());
        request.put("body", context.getHttpBody());
        input.put("request", request);

        // Add timestamp
        if (context.getRequestTimestamp() != null) {
            input.put("timestamp", context.getRequestTimestamp().getTime() / 1000); // Convert to seconds
        }

        // Add additional attributes if present
        if (context.getAttributes() != null) {
            input.putAll(context.getAttributes());
        }

        return input;
    }

    @Override
    public String getName() {
        return "Layer 5: Policy Evaluation Validator";
    }

    @Override
    public double getOrder() {
        return 5.0;
    }
}