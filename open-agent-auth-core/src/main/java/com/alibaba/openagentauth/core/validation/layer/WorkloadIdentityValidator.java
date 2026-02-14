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

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Layer 1 validator for Workload Identity Token (WIT) verification.
 * <p>
 * This validator delegates to the existing {@link WitValidator} to perform
 * comprehensive verification of the WIT, including:
 * <ul>
 *   <li>Token presence check</li>
 *   <li>Signature verification using the issuer's public key</li>
 *   <li>Expiration time validation</li>
 *   <li>Required claims validation (sub, exp)</li>
 *   <li>Trust domain validation (iss claim)</li>
 *   <li>Confirmation claim (cnf) validation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Protocol References:</b>
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a> - WIMSE Workload Credentials</li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a></li>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc7515">RFC 7515 - JSON Web Signature (JWS)</a></li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @see WorkloadIdentityToken
 * @since 1.0
 */
public class WorkloadIdentityValidator implements LayerValidator {

    /**
     * The logger for workload identity validator.
     */
    private static final Logger logger = LoggerFactory.getLogger(WorkloadIdentityValidator.class);

    /**
     * The delegated WIT validator.
     */
    private final WitValidator witValidator;

    /**
     * Creates a new workload identity validator.
     *
     * @param witValidator the WIT validator to delegate to
     * @throws IllegalArgumentException if witValidator is null
     */
    public WorkloadIdentityValidator(WitValidator witValidator) {
        ValidationUtils.validateNotNull(witValidator, "WitValidator");
        this.witValidator = witValidator;
    }

    @Override
    public LayerValidationResult validate(ValidationContext context) {
        logger.debug("Starting Layer 1: Workload Identity validation");

        // Check if WIT is present
        if (context.getWit() == null) {
            logger.error("WIT is missing from validation context");
            return LayerValidationResult.failure(
                "WIT is required but not present in the validation context"
            );
        }

        // Get the JWT string from the WIT
        String witJwtString = context.getWit().getJwtString();
        if (ValidationUtils.isNullOrEmpty(witJwtString)) {
            logger.error("WIT JWT string is null or empty");
            return LayerValidationResult.failure(
                "WIT JWT string is required but not present in the validation context"
            );
        }

        try {
            // Delegate to the existing WitValidator
            var result = witValidator.validate(witJwtString);
            
            if (result.isValid()) {
                logger.debug("Layer 1: Workload Identity validation passed successfully");
                return LayerValidationResult.success("Layer 1: WIT validation completed successfully");
            } else {
                logger.error("Layer 1: Workload Identity validation failed: {}", result.getErrorMessage());
                return LayerValidationResult.failure(
                    result.getErrorMessage(),
                    "Layer 1 WIT Validation"
                );
            }
        } catch (Exception e) {
            logger.error("Error validating WIT", e);
            return LayerValidationResult.failure(
                "WIT validation failed: " + e.getMessage(),
                "Layer 1 WIT Validation"
            );
        }
    }

    @Override
    public String getName() {
        return "Layer 1: Workload Identity Validator";
    }

    @Override
    public double getOrder() {
        return 1.0;
    }
}