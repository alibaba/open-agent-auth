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
package com.alibaba.openagentauth.core.validation.impl;

import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.api.LayerValidator;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.VerificationResult;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Default implementation of the five-layer verification architecture orchestrator.
 * <p>
 * This class coordinates the execution of all five validation layers in the correct
 * sequence, implementing the fail-fast strategy to stop immediately on first failure.
 * It manages the lifecycle of validators and provides comprehensive reporting of
 * validation results.
 * </p>
 * <p>
 * <b>Execution Strategy:</b>
 * <ul>
 *   <li><b>Fail-Fast</b>: Stop immediately on first validation failure</li>
 *   <li><b>Ordered Execution</b>: Execute validators in order (1, 2, 3, 4, 5)</li>
 *   <li><b>Thread-Safe</b>: Uses concurrent collections for validator registration</li>
 *   <li><b>Comprehensive Reporting</b>: Collects all layer results for auditing</li>
 * </ul>
 * </p>
 *
 * @see FiveLayerVerifier
 * @see LayerValidator
 * @see ValidationContext
 * @since 1.0
 */
public class DefaultFiveLayerVerifier implements FiveLayerVerifier {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultFiveLayerVerifier.class);

    /**
     * List of registered layer validators.
     * <p>
     * Uses CopyOnWriteArrayList for thread-safe dynamic registration.
     * </p>
     */
    private final List<LayerValidator> validators = new CopyOnWriteArrayList<>();

    /**
     * Creates a new five-layer verifier.
     */
    public DefaultFiveLayerVerifier() {
        logger.info("DefaultFiveLayerVerifier initialized");
    }

    @Override
    public VerificationResult verify(ValidationContext context) {
        ValidationUtils.validateNotNull(context, "Validation context");

        logger.info("Starting five-layer verification pipeline");
        long startTime = System.currentTimeMillis();

        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        VerificationResult.LayerResult firstFailure = null;

        // Sort validators by order
        List<LayerValidator> sortedValidators = new ArrayList<>(validators);
        sortedValidators.sort(Comparator.comparingDouble(LayerValidator::getOrder));

        // Execute validators in order
        for (LayerValidator validator : sortedValidators) {
            logger.debug("Executing validator: {} (order: {})", validator.getName(), validator.getOrder());

            long layerStartTime = System.currentTimeMillis();
            var validationResult = validator.validate(context);
            long layerDuration = System.currentTimeMillis() - layerStartTime;

            VerificationResult.LayerResult layerResult = new VerificationResult.LayerResult(
                validator.getName(),
                validationResult,
                validator.getOrder()
            );
            layerResults.add(layerResult);

            logger.debug(
                "Validator {} completed in {}ms - Success: {}",
                validator.getName(),
                layerDuration,
                validationResult.isSuccess()
            );

            // Fail-fast: stop on first failure
            if (validationResult.isFailure()) {
                logger.error(
                    "Verification failed at layer: {} - Errors: {}",
                    validator.getName(),
                    validationResult.getErrors()
                );
                firstFailure = layerResult;
                break;
            }
        }

        long totalDuration = System.currentTimeMillis() - startTime;
        boolean success = (firstFailure == null);

        if (success) {
            logger.info("Five-layer verification completed successfully in {}ms", totalDuration);
        } else {
            logger.warn("Five-layer verification failed after {}ms at layer: {}", totalDuration, firstFailure.getValidatorName());
        }

        return new VerificationResult(success, layerResults, firstFailure);
    }

    @Override
    public List<LayerValidator> getValidators() {
        return new ArrayList<>(validators);
    }

    @Override
    public void registerValidator(LayerValidator validator) {
        ValidationUtils.validateNotNull(validator, "Validator");

        logger.info("Registering validator: {} (order: {})", validator.getName(), validator.getOrder());
        validators.add(validator);

        // Sort validators to maintain order
        validators.sort(Comparator.comparingDouble(LayerValidator::getOrder));
    }
}