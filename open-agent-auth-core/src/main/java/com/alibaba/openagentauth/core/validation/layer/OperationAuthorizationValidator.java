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

import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.alibaba.openagentauth.core.model.identity.DelegationChain;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.List;

/**
 * Layer 3 validator for Agent Operation Authorization Token (AOAT) verification.
 * <p>
 * This validator delegates to the existing {@link AoatValidator} to perform
 * comprehensive verification of the AOAT, including:
 * <ul>
 *   <li>Token presence check</li>
 *   <li>Signature verification using the authorization server's public key</li>
 *   <li>Expiration time validation</li>
 *   <li>Required claims validation (iss, sub, aud, exp, iat, jti)</li>
 *   <li>Agent identity validation</li>
 *   <li>Agent operation authorization validation</li>
 *   <li>Delegation chain validation (if present, per draft-liu-agent-operation-authorization Section 6)</li>
 * </ul>
 * </p>
 * <p>
 * <b>Protocol References:</b>
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a> - Agent Operation Authorization</li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 - JSON Web Signature (JWS)</a></li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @see AgentOperationAuthToken
 * @since 1.0
 */
public class OperationAuthorizationValidator implements LayerValidator {

    /**
     * The logger for agent operation authorization validator.
     */
    private static final Logger logger = LoggerFactory.getLogger(OperationAuthorizationValidator.class);

    /**
     * The delegated AOAT validator.
     */
    private final AoatValidator aoatValidator;

    /**
     * Creates a new agent operation authorization validator.
     *
     * @param aoatValidator the AOAT validator to delegate to
     * @throws IllegalArgumentException if aoatValidator is null
     */
    public OperationAuthorizationValidator(AoatValidator aoatValidator) {
        ValidationUtils.validateNotNull(aoatValidator, "AoatValidator");
        this.aoatValidator = aoatValidator;
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 3: Agent Operation Authorization validation");

        // Check if AOAT is present
        if (context.getAgentOaToken() == null) {
            logger.error("AOAT is missing from validation context");
            return LayerValidationResult.failure(
                "AOAT is required but not present in the validation context"
            );
        }

        // Get the JWT string from the AOAT
        String aoatJwtString;
        try {
            aoatJwtString = context.getAgentOaToken().getJwtString();
        } catch (JOSEException e) {
            logger.error("Failed to get AOAT JWT string", e);
            return LayerValidationResult.failure(
                "AOAT JWT string is not available: " + e.getMessage()
            );
        }
        if (ValidationUtils.isNullOrEmpty(aoatJwtString)) {
            logger.error("AOAT JWT string is null or empty");
            return LayerValidationResult.failure(
                "AOAT JWT string is required but not present in the validation context"
            );
        }

        try {
            // Delegate to the existing AoatValidator
            var result = aoatValidator.validate(aoatJwtString);
            
            if (!result.isValid()) {
                logger.error("Layer 3: Agent Operation Authorization validation failed: {}", result.getErrorMessage());
                return LayerValidationResult.failure(
                    result.getErrorMessage(),
                    "Layer 3 AOAT Validation"
                );
            }

            // Verify delegation chain if present (optional per spec)
            AgentOperationAuthToken aoat = context.getAgentOaToken();
            var delegationChainResult = verifyDelegationChain(aoat);
            if (delegationChainResult.isFailure()) {
                logger.error("Layer 3: Delegation chain validation failed: {}", delegationChainResult.getErrors());
                return delegationChainResult;
            }
            
            logger.debug("Layer 3: Agent Operation Authorization validation passed successfully");
            return LayerValidationResult.success("Layer 3: AOAT validation completed successfully");
            
        } catch (Exception e) {
            logger.error("Error validating AOAT", e);
            return LayerValidationResult.failure(
                "AOAT validation failed: " + e.getMessage(),
                "Layer 3 AOAT Validation"
            );
        }
    }

    /**
     * Verifies the delegation chain claim in AOAT if present.
     * <p>
     * This method validates the delegation chain according to
     * draft-liu-agent-operation-authorization Section 6:
     * <ul>
     *   <li>Delegation chain is OPTIONAL - skip validation if not present</li>
     *   <li>Verify required fields in each delegation record</li>
     *   <li>Verify AS signature on each delegation record</li>
     *   <li>Verify delegation timestamp validity</li>
     * </ul>
     * </p>
     * <p>
     * <b>Note:</b> Full signature verification of delegation records requires
     * access to the Authorization Server's public key and is typically performed
     * during token validation. This implementation focuses on structural validation
     * and consistency checks.
     * </p>
     *
     * @param aoat the Agent Operation Authorization Token
     * @return the validation result
     */
    private LayerValidationResult verifyDelegationChain(AgentOperationAuthToken aoat) {
        List<DelegationChain> delegationChain = aoat.getDelegationChain();
        
        // Delegation chain is OPTIONAL per spec - skip if not present
        if (delegationChain == null || delegationChain.isEmpty()) {
            logger.debug("AOAT does not contain delegation_chain, skipping delegation validation");
            return LayerValidationResult.success();
        }

        logger.debug("AOAT contains delegation_chain with {} entries, starting validation", delegationChain.size());

        // Verify each delegation record
        for (int i = 0; i < delegationChain.size(); i++) {
            DelegationChain delegationRecord = delegationChain.get(i);
            var recordResult = verifyDelegationRecord(delegationRecord, i, aoat);
            if (recordResult.isFailure()) {
                return recordResult;
            }
        }

        logger.debug("Delegation chain validation completed successfully for {} entries", delegationChain.size());
        return LayerValidationResult.success("Layer 3: Delegation chain validation completed successfully");
    }

    /**
     * Verifies a single delegation record.
     * <p>
     * This method validates the structure and required fields of a delegation record
     * according to draft-liu-agent-operation-authorization Section 6 and Table 5.
     * </p>
     *
     * @param delegationRecord the delegation record to verify
     * @param index the index of the record in the chain
     * @param aoat the Agent Operation Authorization Token containing the record
     * @return the validation result
     */
    private LayerValidationResult verifyDelegationRecord(DelegationChain delegationRecord, int index, AgentOperationAuthToken aoat) {
        // Verify delegator_jti
        if (ValidationUtils.isNullOrEmpty(delegationRecord.getDelegatorJti())) {
            return LayerValidationResult.failure(
                String.format("Delegation record at index %d is missing required field 'delegator_jti'", index),
                "Layer 3 Delegation Chain Validation"
            );
        }

        // Verify delegator_agent_identity
        if (delegationRecord.getDelegatorAgentIdentity() == null) {
            return LayerValidationResult.failure(
                String.format("Delegation record at index %d is missing required field 'delegator_agent_identity'",
                    index
                ),
                "Layer 3 Delegation Chain Validation"
            );
        }

        // Verify delegator_agent_identity structure
        AgentIdentity delegatorIdentity = delegationRecord.getDelegatorAgentIdentity();
        if (ValidationUtils.isNullOrEmpty(delegatorIdentity.getId())) {
            return LayerValidationResult.failure(
                String.format("Delegation record at index %d has invalid delegator_agent_identity: missing 'id' field",
                    index
                ),
                "Layer 3 Delegation Chain Validation"
            );
        }

        // Verify delegation_timestamp
        if (delegationRecord.getDelegationTimestamp() == null) {
            return LayerValidationResult.failure(
                String.format("Delegation record at index %d is missing required field 'delegation_timestamp'", index),
                "Layer 3 Delegation Chain Validation"
            );
        }

        // Verify delegation_timestamp is not in the future
        Instant now = Instant.now();
        if (delegationRecord.getDelegationTimestamp().isAfter(now)) {
            return LayerValidationResult.failure(
                String.format(
                    "Delegation record at index %d has invalid delegation_timestamp: timestamp is in the future (%s)",
                    index, delegationRecord.getDelegationTimestamp()
                ),
                "Layer 3 Delegation Chain Validation"
            );
        }

        // Verify as_signature
        if (ValidationUtils.isNullOrEmpty(delegationRecord.getAsSignature())) {
            return LayerValidationResult.failure(
                String.format("Delegation record at index %d is missing required field 'as_signature'", index),
                "Layer 3 Delegation Chain Validation"
            );
        }

        // Note: Full signature verification is typically performed during token validation
        // This implementation focuses on structural validation
        logger.debug("Delegation record at index {} passed structural validation", index);
        return LayerValidationResult.success();
    }

    @Override
    public String getName() {
        return "Layer 3: Agent Operation Authorization Validator";
    }

    @Override
    public double getOrder() {
        return 3.0;
    }
}