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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link VerificationResult}.
 */
@DisplayName("VerificationResult Tests")
class VerificationResultTest {

    private static final String VALIDATOR_NAME = "TestValidator";

    @Test
    @DisplayName("Should create successful verification result")
    void shouldCreateSuccessfulVerificationResult() {
        // Arrange
        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        LayerValidationResult successResult = LayerValidationResult.success();
        layerResults.add(new VerificationResult.LayerResult(VALIDATOR_NAME, successResult, 1.0));

        // Act
        VerificationResult result = new VerificationResult(true, layerResults, null);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getLayerResults()).hasSize(1);
        assertThat(result.getFirstFailure()).isNull();
    }

    @Test
    @DisplayName("Should create failed verification result")
    void shouldCreateFailedVerificationResult() {
        // Arrange
        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        LayerValidationResult failureResult = LayerValidationResult.failure("Validation failed");
        VerificationResult.LayerResult firstFailure = 
                new VerificationResult.LayerResult(VALIDATOR_NAME, failureResult, 1.0);
        layerResults.add(firstFailure);

        // Act
        VerificationResult result = new VerificationResult(false, layerResults, firstFailure);

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getLayerResults()).hasSize(1);
        assertThat(result.getFirstFailure()).isNotNull();
        assertThat(result.getFirstFailure().getValidatorName()).isEqualTo(VALIDATOR_NAME);
    }

    @Test
    @DisplayName("Should handle multiple layer results")
    void shouldHandleMultipleLayerResults() {
        // Arrange
        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        layerResults.add(new VerificationResult.LayerResult("Layer1", LayerValidationResult.success(), 1.0));
        layerResults.add(new VerificationResult.LayerResult("Layer2", LayerValidationResult.success(), 2.0));
        layerResults.add(new VerificationResult.LayerResult("Layer3", LayerValidationResult.success(), 3.0));

        // Act
        VerificationResult result = new VerificationResult(true, layerResults, null);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getLayerResults()).hasSize(3);
        assertThat(result.getLayerResults().get(0).getValidatorName()).isEqualTo("Layer1");
        assertThat(result.getLayerResults().get(1).getValidatorName()).isEqualTo("Layer2");
        assertThat(result.getLayerResults().get(2).getValidatorName()).isEqualTo("Layer3");
    }

    @Test
    @DisplayName("Should handle empty layer results")
    void shouldHandleEmptyLayerResults() {
        // Act
        VerificationResult result = new VerificationResult(true, new ArrayList<>(), null);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getLayerResults()).isEmpty();
    }

    @Test
    @DisplayName("Should correctly identify first failure")
    void shouldCorrectlyIdentifyFirstFailure() {
        // Arrange
        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        layerResults.add(new VerificationResult.LayerResult("Layer1", LayerValidationResult.success(), 1.0));
        
        LayerValidationResult failureResult = LayerValidationResult.failure("Layer 2 failed");
        VerificationResult.LayerResult layer2Failure = 
                new VerificationResult.LayerResult("Layer2", failureResult, 2.0);
        layerResults.add(layer2Failure);
        
        layerResults.add(new VerificationResult.LayerResult("Layer3", LayerValidationResult.success(), 3.0));

        // Act
        VerificationResult result = new VerificationResult(false, layerResults, layer2Failure);

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getFirstFailure()).isNotNull();
        assertThat(result.getFirstFailure().getValidatorName()).isEqualTo("Layer2");
        assertThat(result.getFirstFailure().getOrder()).isEqualTo(2.0);
    }

    @Test
    @DisplayName("LayerResult should check passed status")
    void layerResultShouldCheckPassedStatus() {
        // Arrange
        LayerValidationResult successResult = LayerValidationResult.success();
        LayerValidationResult failureResult = LayerValidationResult.failure("Failed");
        
        VerificationResult.LayerResult passedLayer = 
                new VerificationResult.LayerResult("PassedValidator", successResult, 1.0);
        VerificationResult.LayerResult failedLayer = 
                new VerificationResult.LayerResult("FailedValidator", failureResult, 2.0);

        // Act & Assert
        assertThat(passedLayer.isPassed()).isTrue();
        assertThat(failedLayer.isPassed()).isFalse();
    }

    @Test
    @DisplayName("LayerResult should return validator name")
    void layerResultShouldReturnValidatorName() {
        // Arrange
        String validatorName = "TestValidator";
        VerificationResult.LayerResult layerResult = 
                new VerificationResult.LayerResult(validatorName, LayerValidationResult.success(), 1.0);

        // Act
        String name = layerResult.getValidatorName();

        // Assert
        assertThat(name).isEqualTo(validatorName);
    }

    @Test
    @DisplayName("LayerResult should return validation result")
    void layerResultShouldReturnValidationResult() {
        // Arrange
        LayerValidationResult validationResult = LayerValidationResult.success("Test metadata");
        VerificationResult.LayerResult layerResult = 
                new VerificationResult.LayerResult("Validator", validationResult, 1.0);

        // Act
        LayerValidationResult result = layerResult.getResult();

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMetadata()).isEqualTo("Test metadata");
    }

    @Test
    @DisplayName("LayerResult should return execution order")
    void layerResultShouldReturnExecutionOrder() {
        // Arrange
        double order = 3.5;
        VerificationResult.LayerResult layerResult = 
                new VerificationResult.LayerResult("Validator", LayerValidationResult.success(), order);

        // Act
        double returnedOrder = layerResult.getOrder();

        // Assert
        assertThat(returnedOrder).isEqualTo(order);
    }

    @Test
    @DisplayName("Should handle null layer results list")
    void shouldHandleNullLayerResultsList() {
        // Act
        VerificationResult result = new VerificationResult(true, null, null);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getLayerResults()).isNull();
    }

    @Test
    @DisplayName("Should handle null first failure")
    void shouldHandleNullFirstFailure() {
        // Arrange
        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        layerResults.add(new VerificationResult.LayerResult("Layer1", LayerValidationResult.success(), 1.0));

        // Act
        VerificationResult result = new VerificationResult(true, layerResults, null);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getFirstFailure()).isNull();
    }

    @Test
    @DisplayName("Should preserve layer results order")
    void shouldPreserveLayerResultsOrder() {
        // Arrange
        List<VerificationResult.LayerResult> layerResults = new ArrayList<>();
        layerResults.add(new VerificationResult.LayerResult("Layer1", LayerValidationResult.success(), 1.0));
        layerResults.add(new VerificationResult.LayerResult("Layer2", LayerValidationResult.success(), 2.0));
        layerResults.add(new VerificationResult.LayerResult("Layer3", LayerValidationResult.success(), 3.0));

        // Act
        VerificationResult result = new VerificationResult(true, layerResults, null);

        // Assert
        assertThat(result.getLayerResults()).hasSize(3);
        assertThat(result.getLayerResults().get(0).getOrder()).isEqualTo(1.0);
        assertThat(result.getLayerResults().get(1).getOrder()).isEqualTo(2.0);
        assertThat(result.getLayerResults().get(2).getOrder()).isEqualTo(3.0);
    }
}
