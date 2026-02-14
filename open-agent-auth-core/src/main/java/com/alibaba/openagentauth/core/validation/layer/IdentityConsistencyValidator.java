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

import com.alibaba.openagentauth.core.binding.BindingInstance;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Layer 4 validator for identity consistency verification.
 * <p>
 * This validator ensures that the user identity is consistent across all tokens.
 * It verifies that the user identity (sub claim) matches between WIT and Agent OA Token.
 * Additionally, it performs two-layer identity verification by retrieving the binding
 * instance from the Authorization Server and validating both user and workload identities.
 * </p>
 * <p>
 * <b>Identity Consistency Checks:</b>
 * <ol>
 *   <li>Extract binding instance ID from AOAT's agent_identity.id</li>
 *   <li>Retrieve binding instance from the Authorization Server</li>
 *   <li>Verify user identity matches the binding's user identity</li>
 *   <li>Verify workload identity matches the binding's workload identity</li>
 * </ol>
 * </p>
 * <p>
 * <b>Protocol References:</b>
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a> - Agent Operation Authorization</li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @since 1.0
 */
public class IdentityConsistencyValidator implements LayerValidator {

    /**
     * Logger for the identity consistency validator.
     */
    private static final Logger logger = LoggerFactory.getLogger(IdentityConsistencyValidator.class);

    /**
     * The binding instance store for two-layer verification.
     */
    private final BindingInstanceStore bindingInstanceStore;

    /**
     * Creates a new identity consistency validator.
     *
     * @param bindingInstanceStore the binding instance store for two-layer verification
     */
    public IdentityConsistencyValidator(BindingInstanceStore bindingInstanceStore) {
        this.bindingInstanceStore = bindingInstanceStore;
    }

    /**
     * Creates a new identity consistency validator without binding instance store.
     * This constructor is for backward compatibility and will only perform basic validation.
     */
    public IdentityConsistencyValidator() {
        this(null);
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 4: Identity Consistency validation");

        // Check if required tokens are present
        if (context.getWit() == null) {
            logger.error("WIT is missing from validation context");
            return LayerValidationResult.failure(
                "WIT is required for identity consistency validation"
            );
        }

        if (context.getAgentOaToken() == null) {
            logger.error("AOAT is missing from validation context");
            return LayerValidationResult.failure(
                "AOAT is required for identity consistency validation"
            );
        }

        WorkloadIdentityToken wit = context.getWit();
        AgentOperationAuthToken aoat = context.getAgentOaToken();

        // Perform two-layer identity verification if binding instance store is available
        if (bindingInstanceStore != null) {

            // Verify user identity consistency
            LayerValidationResult userIdentityResult = verifyUserIdentityConsistency(wit, aoat);
            if (userIdentityResult.isFailure()) {
                logger.error("User identity verification failed: {}", userIdentityResult.getErrors());
                return userIdentityResult;
            }

            // Verify workload identity consistency
            LayerValidationResult workloadIdentityResult = verifyWorkloadIdentityConsistency(wit, aoat);
            if (workloadIdentityResult.isFailure()) {
                logger.error("Workload identity verification failed: {}", workloadIdentityResult.getErrors());
                return workloadIdentityResult;
            }
        } else {
            logger.warn("BindingInstanceStore not configured, skipping two-layer identity verification");
        }

        logger.debug("Layer 4: Identity Consistency validation passed successfully");
        return LayerValidationResult.success("Layer 4: Identity consistency validation completed successfully");
    }
    /**
     * Retrieves and validates the binding instance from the store.
     * <p>
     * This method handles common logic for:
     * <ol>
     *   <li>Extracting binding instance ID from AOAT's agent_identity.id</li>
     *   <li>Retrieving the binding instance from the Authorization Server</li>
     *   <li>Verifying binding is not expired</li>
     * </ol>
     * </p>
     *
     * @param aoat the Agent Operation Authorization Token
     * @param verificationLayer the name of the verification layer for error messages
     * @return the validated binding instance, or null if validation fails
     */
    private BindingInstance retrieveAndValidateBindingInstance(AgentOperationAuthToken aoat, String verificationLayer) {

        // Extract binding instance ID from AOAT's agent_identity.id
        if (aoat.getAgentIdentity() == null) {
            logger.error("AOAT is missing agent_identity claim");
            return null;
        }

        String bindingInstanceId = aoat.getAgentIdentity().getId();
        if (ValidationUtils.isNullOrEmpty(bindingInstanceId)) {
            logger.error("AOAT agent_identity.id is missing or empty");
            return null;
        }

        logger.debug("Retrieving binding instance with ID: {}", bindingInstanceId);

        // Retrieve binding instance from store
        BindingInstance binding = bindingInstanceStore.retrieve(bindingInstanceId);
        if (binding == null) {
            logger.error("Binding instance not found for ID: {}", bindingInstanceId);
            return null;
        }

        // Verify binding is not expired
        if (binding.isExpired()) {
            logger.error("Binding instance has expired for ID: {}", bindingInstanceId);
            return null;
        }

        return binding;
    }

    /**
     * Verifies user identity consistency using binding instance.
     * <p>
     * This method performs user identity verification by:
     * <ol>
     *   <li>Retrieving and validating the binding instance</li>
     *   <li>Extracting user identity from AOAT's agent_identity.issuedTo field</li>
     *   <li>Extracting user ID from the issuedTo field (format: "issuer|userId")</li>
     *   <li>Verifying the user ID matches the binding's user identity</li>
     * </ol>
     * </p>
     * <p>
     * According to draft-liu-agent-operation-authorization, the agent_identity.issuedTo
     * field contains the verified user identifier in the format "issuer|userId" (e.g.,
     * "https://idp.example.com|user-12345"). The user ID part (after the "|") should
     * be compared with the binding's user identity.
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param aoat the Agent Operation Authorization Token
     * @return the validation result
     */
    private LayerValidationResult verifyUserIdentityConsistency(WorkloadIdentityToken wit, AgentOperationAuthToken aoat) {
        
        // Retrieve and validate binding instance
        BindingInstance binding = retrieveAndValidateBindingInstance(aoat, "Layer 4 User Identity Verification");
        if (binding == null) {
            return LayerValidationResult.failure(
                "Failed to retrieve or validate binding instance",
                "Layer 4 User Identity Verification"
            );
        }

        // Extract user identity from AOAT's agent_identity.issuedTo field
        // According to the protocol, this is the verified user identifier
        if (aoat.getAgentIdentity() == null) {
            logger.error("AOAT is missing agent_identity claim");
            return LayerValidationResult.failure(
                "AOAT is missing agent_identity claim",
                "Layer 4 User Identity Verification"
            );
        }

        String issuedTo = aoat.getAgentIdentity().getIssuedTo();
        if (ValidationUtils.isNullOrEmpty(issuedTo)) {
            return LayerValidationResult.failure(
                "AOAT agent_identity.issuedTo is missing or empty",
                "Layer 4 User Identity Verification"
            );
        }

        // Extract user ID from issuedTo field (format: "issuer|userId")
        String aoatUserId = extractUserIdFromIssuedTo(issuedTo);
        String bindingUserId = binding.getUserIdentity();

        if (!aoatUserId.equals(bindingUserId)) {
            logger.error("User identity mismatch: AOAT issuedTo={}, extracted userId={}, binding userIdentity={}", 
                         issuedTo, aoatUserId, bindingUserId);
            return LayerValidationResult.failure(
                "User identity mismatch between AOAT agent_identity.issuedTo and binding instance",
                "Layer 4 User Identity Verification"
            );
        }

        logger.debug("User identity verification passed: user={}", bindingUserId);
        return LayerValidationResult.success();
    }

    /**
     * Extracts user ID from the issuedTo field.
     * <p>
     * The issuedTo field format is "issuer|userId" according to the protocol.
     * This method extracts the userId part (after the "|").
     * </p>
     *
     * @param issuedTo the issuedTo field value
     * @return the user ID
     */
    private String extractUserIdFromIssuedTo(String issuedTo) {

        // Check if issuedTo is null or empty
        if (ValidationUtils.isNullOrEmpty(issuedTo)) {
            return "";
        }
        
        // Split by "|" and return the second part (userId)
        String[] parts = issuedTo.split("\\|");
        if (parts.length >= 2) {
            return parts[1];
        }
        
        // If no "|" found, return the entire string as user ID (fallback)
        return issuedTo;
    }

    /**
     * Verifies workload identity consistency using binding instance.
     * <p>
     * This method performs workload identity verification by:
     * <ol>
     *   <li>Retrieving and validating the binding instance</li>
     *   <li>Verifying WIT's workload identity matches the binding's workload identity</li>
     * </ol>
     * </p>
     *
     * @param wit the Workload Identity Token
     * @param aoat the Agent Operation Authorization Token
     * @return the validation result
     */
    private LayerValidationResult verifyWorkloadIdentityConsistency(WorkloadIdentityToken wit, AgentOperationAuthToken aoat) {
        
        // Retrieve and validate binding instance
        BindingInstance binding = retrieveAndValidateBindingInstance(aoat, "Layer 4 Workload Identity Verification");
        if (binding == null) {
            return LayerValidationResult.failure(
                "Failed to retrieve or validate binding instance",
                "Layer 4 Workload Identity Verification"
            );
        }

        // Verify workload identity consistency
        String witWorkloadId = wit.getSubject();
        String bindingWorkloadId = binding.getWorkloadIdentity();
        if (ValidationUtils.isNullOrEmpty(witWorkloadId)) {
            return LayerValidationResult.failure(
                "WIT is missing workload identity (sub claim)",
                "Layer 4 Workload Identity Verification"
            );
        }

        if (!witWorkloadId.equals(bindingWorkloadId)) {
            logger.error("Workload identity mismatch: WIT workload={}, binding workload={}", witWorkloadId, bindingWorkloadId);
            return LayerValidationResult.failure(
                "Workload identity mismatch between WIT and binding instance",
                "Layer 4 Workload Identity Verification"
            );
        }

        logger.debug("Workload identity verification passed: workload={}", bindingWorkloadId);
        return LayerValidationResult.success();
    }

    @Override
    public String getName() {
        return "Layer 4: Identity Consistency Validator";
    }

    @Override
    public double getOrder() {
        return 4.0;
    }

}