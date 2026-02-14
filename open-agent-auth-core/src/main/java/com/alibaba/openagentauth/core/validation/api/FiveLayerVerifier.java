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

import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.VerificationResult;

import java.util.List;

/**
 * Orchestrator for the five-layer verification architecture.
 * <p>
 * This interface defines the contract for executing the complete verification pipeline,
 * coordinating all five validation layers in the correct sequence. It implements the
 * orchestration pattern, managing the flow of control between individual validators.
 * </p>
 * <p>
 * <b>Verification Pipeline:</b>
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
 *   <li><b>Fail-Fast Strategy</b>: Stop immediately on first validation failure</li>
 *   <li><b>Comprehensive Reporting</b>: Collect all validation results for auditing</li>
 *   <li><b>Performance Optimization</b>: Skip unnecessary layers on early failure</li>
 *   <li><b>Observability</b>: Provide detailed logs and metrics for monitoring</li>
 * </ul>
 * </p>
 *
 * @see LayerValidator
 * @see ValidationContext
 * @see LayerValidationResult
 * @since 1.0
 */
public interface FiveLayerVerifier {

    /**
     * Executes the complete five-layer verification pipeline.
     * <p>
     * This method:
     * <ul>
     *   <li>Validates the input context</li>
 *   *   <li>Executes validators in order (1, 2, 3, 4, 5)</li>
 *   *   <li>Stops immediately on first failure (fail-fast)</li>
 *   *   <li>Collects all validation results</li>
 *   *   <li>Returns comprehensive verification result</li>
     * </ul>
     * </p>
     * <p>
     * <b>Execution Flow:</b>
     * <pre>
     * 1. Validate context is not null
     * 2. Execute Layer 1 (WIT validation)
     *    - If failed, return immediately with Layer 1 result
     * 3. Execute Layer 2 (WPT validation)
     *    - If failed, return immediately with Layer 2 result
     * 4. Execute Layer 3 (AOAT validation)
     *    - If failed, return immediately with Layer 3 result
     * 5. Execute Layer 4 (Identity consistency validation)
     *    - If failed, return immediately with Layer 4 result
     * 6. Execute Layer 5 (OPA policy evaluation)
     *    - If failed, return immediately with Layer 5 result
     * 7. Return success result with all layer results
     * </pre>
     * </p>
     *
     * @param context the validation context containing all tokens and request information
     * @return the comprehensive verification result with all layer results
     * @throws IllegalArgumentException if the context is null
     */
    VerificationResult verify(ValidationContext context);

    /**
     * Gets the list of registered layer validators.
     * <p>
     * This method returns an unmodifiable list of validators in execution order.
     * </p>
     *
     * @return the list of layer validators
     */
    List<LayerValidator> getValidators();

    /**
     * Registers a new layer validator.
     * <p>
     * This method allows dynamic registration of validators, enabling
     * runtime configuration and extensibility.
     * </p>
     *
     * @param validator the validator to register
     * @throws IllegalArgumentException if the validator is null
     */
    void registerValidator(LayerValidator validator);
}
