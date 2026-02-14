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

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.nimbusds.jose.JOSEException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Layer 2 validator for Workload Proof Token (WPT) verification.
 * <p>
 * This validator delegates to the existing {@link WptValidator} to perform
 * comprehensive verification of the WPT, including:
 * <ul>
 *   <li>WPT presence check</li>
 *   <li>WPT signature verification using the WIT's public key</li>
 *   <li>Expiration time validation</li>
 *   <li>Required claims validation (wth)</li>
 *   <li>Algorithm consistency check (WPT alg vs WIT cnf.jwk.alg)</li>
 *   <li>WIT hash validation (wth claim)</li>
 *   <li>Other tokens hashes validation (oth claim) including AOAT</li>
 * </ul>
 * </p>
 * <p>
 * <b>Protocol References:</b>
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/">draft-ietf-wimse-wpt</a> - WIMSE Workload Proof Token</li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc9421">RFC 9421 - HTTP Message Signatures</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7800">RFC 7800 - Proof-of-Possession Key Semantics</a></li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @see WorkloadProofToken
 * @see WorkloadIdentityToken
 * @since 1.0
 */
public class WorkloadProofValidator implements LayerValidator {

    /**
     * The logger for workload proof validator.
     */
    private static final Logger logger = LoggerFactory.getLogger(WorkloadProofValidator.class);

    /**
     * The delegated WPT validator.
     */
    private final WptValidator wptValidator;

    /**
     * Creates a new workload proof validator.
     *
     * @param wptValidator the WPT validator to delegate to
     * @throws IllegalArgumentException if wptValidator is null
     */
    public WorkloadProofValidator(WptValidator wptValidator) {
        ValidationUtils.validateNotNull(wptValidator, "WptValidator");
        this.wptValidator = wptValidator;
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 2: Workload Proof validation");

        // Check if WPT is present
        if (context.getWpt() == null) {
            logger.error("WPT is missing from validation context");
            return LayerValidationResult.failure(
                "WPT is required but not present in the validation context"
            );
        }

        // Check if WIT is present (needed for verification)
        if (context.getWit() == null) {
            logger.error("WIT is missing from validation context, required for WPT verification");
            return LayerValidationResult.failure(
                "WIT is required for WPT verification but not present in the validation context"
            );
        }

        WorkloadProofToken wpt = context.getWpt();
        WorkloadIdentityToken wit = context.getWit();

        try {
            // Delegate to the existing WptValidator
            var result = wptValidator.validate(wpt, wit);
            
            if (!result.isValid()) {
                logger.error("Layer 2: Workload Proof validation failed: {}", result.getErrorMessage());
                return LayerValidationResult.failure(
                    result.getErrorMessage(),
                    "Layer 2 WPT Validation"
                );
            }

            // After WPT validation, verify the oth claim hashes if present
            String othValidationError = verifyOthClaimHashes(wpt, context);
            if (othValidationError != null) {
                logger.error("Layer 2: WPT oth claim hash validation failed: {}", othValidationError);
                return LayerValidationResult.failure(
                    othValidationError,
                    "Layer 2 WPT oth Validation"
                );
            }
            
            logger.debug("Layer 2: Workload Proof validation passed successfully");
            return LayerValidationResult.success("Layer 2: WPT validation completed successfully");
            
        } catch (Exception e) {
            logger.error("Error validating WPT", e);
            return LayerValidationResult.failure(
                "WPT validation failed: " + e.getMessage(),
                "Layer 2 WPT Validation"
            );
        }
    }

    /**
     * Verifies the oth (other tokens hashes) claim in the WPT.
     * <p>
     * This method validates that the hashes in the oth claim match the actual tokens
     * provided in the validation context. Currently supports:
     * <ul>
     *   <li><b>aoat</b>: Agent Operation Authorization Token hash</li>
     * </ul>
     * </p>
     *
     * @param wpt the WorkloadProofToken
     * @param context the validation context containing the actual tokens
     * @return error message if validation fails, null if valid
     */
    private String verifyOthClaimHashes(WorkloadProofToken wpt, ValidationContext context) {
        try {
            // Check if oth claim is present
            Map<String, String> otherTokenHashes = wpt.getClaims().getOtherTokenHashes();
            if (otherTokenHashes == null || otherTokenHashes.isEmpty()) {
                logger.debug("WPT does not contain oth claim, skipping hash verification");
                return null;
            }

            logger.debug("Verifying WPT oth claim hashes for {} token types", otherTokenHashes.size());

            // Validate each token type in oth claim
            for (Map.Entry<String, String> entry : otherTokenHashes.entrySet()) {
                String tokenType = entry.getKey();
                String expectedHash = entry.getValue();

                String validationError = verifyTokenHash(tokenType, expectedHash, context);
                if (validationError != null) {
                    return validationError;
                }
            }

            logger.debug("All oth claim hashes verified successfully");
            return null;

        } catch (Exception e) {
            logger.error("Error verifying oth claim hashes", e);
            return "Error verifying oth claim hashes: " + e.getMessage();
        }
    }

    /**
     * Verifies the hash for a specific token type.
     *
     * @param tokenType the token type identifier (e.g., "aoat")
     * @param expectedHash the expected hash value from the oth claim
     * @param context the validation context containing the actual tokens
     * @return error message if validation fails, null if valid
     */
    private String verifyTokenHash(String tokenType, String expectedHash, ValidationContext context) {
        switch (tokenType) {
            case "aoat":
                return verifyAoatHash(expectedHash, context);
            default:
                // Unknown token types should have been rejected by WptValidator
                logger.warn("Unexpected token type in oth claim: {}", tokenType);
                return String.format("Unexpected token type in oth claim: '%s'", tokenType);
        }
    }

    /**
     * Verifies that the AOAT hash in the oth claim matches the actual AOAT token.
     *
     * @param expectedHash the expected AOAT hash from the oth claim
     * @param context the validation context containing the actual AOAT token
     * @return error message if validation fails, null if valid
     */
    private String verifyAoatHash(String expectedHash, ValidationContext context) {
        try {
            // Get the actual AOAT token from the context
            AgentOperationAuthToken aoat = context.getAgentOaToken();
            if (aoat == null) {
                logger.warn("WPT oth claim contains aoat hash but AOAT token is not present in context");
                return "WPT oth claim contains aoat hash but AOAT token is not provided";
            }

            // Get the AOAT JWT string
            String aoatJwtString;
            try {
                aoatJwtString = aoat.getJwtString();
            } catch (JOSEException e) {
                logger.warn("Failed to get AOAT JWT string", e);
                return "AOAT token missing JWT string: " + e.getMessage();
            }
            if (ValidationUtils.isNullOrEmpty(aoatJwtString)) {
                logger.warn("AOAT token missing JWT string");
                return "AOAT token missing JWT string";
            }

            // Compute the actual hash of the AOAT token
            String actualHash = JwtHashUtil.computeAoatHash(aoatJwtString);

            // Compare hashes
            if (!expectedHash.equals(actualHash)) {
                logger.warn("WPT oth claim aoat hash mismatch: expected={}, actual={}", expectedHash, actualHash);
                return String.format(
                    "WPT oth claim aoat hash does not match actual AOAT token hash: expected='%s', actual='%s'",
                    expectedHash, actualHash
                );
            }

            logger.debug("WPT oth claim aoat hash verified successfully");
            return null;

        } catch (Exception e) {
            logger.error("Error verifying AOAT hash", e);
            return "Error verifying AOAT hash: " + e.getMessage();
        }
    }

    @Override
    public String getName() {
        return "Layer 2: Workload Proof Validator";
    }

    @Override
    public double getOrder() {
        return 2.0;
    }
}