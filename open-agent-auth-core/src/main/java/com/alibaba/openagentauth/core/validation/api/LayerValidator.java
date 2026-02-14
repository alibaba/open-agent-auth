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
package com.alibaba.openagentauth.core.validation.api;

import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;

/**
 * Interface for a single layer validator in the five-layer verification architecture.
 * <p>
 * Each layer validator is responsible for a specific aspect of the verification process.
 * Validators are executed in sequence, and any failure will cause the entire verification
 * process to fail (fail-fast strategy).
 * </p>
 * <p>
 * <b>Five-Layer Verification Architecture:</b>
 * <ol>
 *   <li><b>Layer 1</b>: WIT signature and validity verification</li>
 *   <li><b>Layer 2</b>: WPT signature and request integrity verification</li>
 *   <li><b>Layer 3</b>: AOAT signature and validity verification</li>
 *   <li><b>Layer 4</b>: Identity consistency verification</li>
 *   <li><b>Layer 5</b>: OPA policy evaluation for authorization decision</li>
 * </ol>
 * </p>
 * <p>
 * <b>Design Principles:</b>
 * <ul>
 *   <li><b>Single Responsibility</b>: Each validator handles one specific validation concern</li>
 *   <li><b>Fail-Fast</b>: Validators should fail immediately on error with clear messages</li>
 *   <li><b>Immutability</b>: Validators should not modify the validation context</li>
 *   <li><b>Testability</b>: Validators should be easily unit testable in isolation</li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @since 1.0
 */
public interface LayerValidator {

    /**
     * Validates the given validation context.
     * <p>
     * This method performs the specific validation logic for this layer. It should:
     * <ul>
     *   <li>Extract required information from the context</li>
     *   <li>Perform the validation checks</li>
     *   <li>Return a validation result with success/failure status</li>
     *   <li>Provide clear error messages if validation fails</li>
     * </ul>
     * </p>
     * <p>
     * <b>Implementation Guidelines:</b>
     * <ul>
     *   <li>Do not modify the validation context</li>
     *   <li>Return immediately on failure with clear error messages</li>
     *   <li>Include relevant protocol references in error messages</li>
     *   <li>Log important validation steps for debugging</li>
     * </ul>
     * </p>
     *
     * @param context the validation context containing all necessary information
     * @return the validation result with success/failure status and error messages
     * @throws IllegalArgumentException if the context is null or missing required information
     */
    LayerValidationResult validate(ValidationContext context);

    /**
     * Gets the name of this validator.
     * <p>
     * This name is used for logging and error reporting purposes.
     * It should be descriptive and clearly indicate which layer this validator represents.
     * </p>
     *
     * @return the validator name (e.g., "Layer 1: WIT Validator")
     */
    String getName();

    /**
     * Gets the order of this validator in the verification pipeline.
     * <p>
     * Lower numbers indicate that this validator should be executed earlier in the sequence.
     * Validators with the same order may be executed in any order (typically parallel if supported).
     * </p>
     *
     * @return the execution order (1, 2, 3, 4, 5 for the five layers)
     */
    default double getOrder() {
        return 0;
    }
}
