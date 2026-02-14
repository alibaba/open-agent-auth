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
package com.alibaba.openagentauth.core.validation.model;

import java.util.List;

/**
 * Comprehensive result of the five-layer verification pipeline.
 * <p>
 * This class encapsulates the results of all validation layers, providing
 * complete visibility into the verification process.
 * </p>
 *
 * @see LayerValidationResult
 * @since 1.0
 */
public class VerificationResult {

    /**
     * The overall success status.
     */
    private final boolean success;

    /**
     * Results from each validation layer.
     */
    private final List<LayerResult> layerResults;

    /**
     * The first layer that failed (if any).
     */
    private final LayerResult firstFailure;

    /**
     * Creates a new verification result.
     *
     * @param success the overall success status
     * @param layerResults results from each layer
     * @param firstFailure the first layer that failed (if any)
     */
    public VerificationResult(boolean success, List<LayerResult> layerResults, LayerResult firstFailure) {
        this.success = success;
        this.layerResults = layerResults;
        this.firstFailure = firstFailure;
    }

    /**
     * Checks if the verification was successful.
     *
     * @return true if all layers passed, false otherwise
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Gets results from all layers.
     *
     * @return the list of layer results
     */
    public List<LayerResult> getLayerResults() {
        return layerResults;
    }

    /**
     * Gets the first layer that failed.
     *
     * @return the first failed layer, or null if all passed
     */
    public LayerResult getFirstFailure() {
        return firstFailure;
    }

    /**
     * Result from a single validation layer.
     */
    public static class LayerResult {

        /**
         * The validator name.
         */
        private final String validatorName;

        /**
         * The validation result.
         */
        private final LayerValidationResult result;

        /**
         * The execution order.
         */
        private final double order;

        /**
         * Creates a new layer result.
         *
         * @param validatorName the validator name
         * @param result the validation result
         * @param order the execution order
         */
        public LayerResult(String validatorName, LayerValidationResult result, double order) {
            this.validatorName = validatorName;
            this.result = result;
            this.order = order;
        }

        /**
         * Gets the validator name.
         *
         * @return the validator name
         */
        public String getValidatorName() {
            return validatorName;
        }

        /**
         * Gets the validation result.
         *
         * @return the validation result
         */
        public LayerValidationResult getResult() {
            return result;
        }

        /**
         * Gets the execution order.
         *
         * @return the execution order
         */
        public double getOrder() {
            return order;
        }

        /**
         * Checks if this layer passed.
         *
         * @return true if the layer passed, false otherwise
         */
        public boolean isPassed() {
            return result.isSuccess();
        }
    }
}
