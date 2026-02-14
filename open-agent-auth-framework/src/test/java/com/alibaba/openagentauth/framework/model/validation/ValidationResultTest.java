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
package com.alibaba.openagentauth.framework.model.validation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ValidationResult.Builder} and {@link ValidationResult.LayerResult.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("ValidationResult.Builder and LayerResult.Builder Tests")
class ValidationResultTest {

    private static final String TEST_ERROR_MESSAGE = "Validation failed";
    private static final String TEST_LAYER_NAME = "Layer1";

    @Test
    @DisplayName("Should build LayerResult instance with all fields when all setters are called")
    void shouldBuildLayerResultInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        ValidationResult.LayerResult layerResult = ValidationResult.LayerResult.builder()
                .layer(1)
                .layerName(TEST_LAYER_NAME)
                .valid(true)
                .message("Layer validation passed")
                .build();

        // Then
        assertThat(layerResult).isNotNull();
        assertThat(layerResult.getLayer()).isEqualTo(1);
        assertThat(layerResult.getLayerName()).isEqualTo(TEST_LAYER_NAME);
        assertThat(layerResult.isValid()).isTrue();
        assertThat(layerResult.getMessage()).isEqualTo("Layer validation passed");
    }

    @Test
    @DisplayName("Should support method chaining when using LayerResult builder")
    void shouldSupportMethodChainingWhenUsingLayerResultBuilder() {
        // Given
        ValidationResult.LayerResult.Builder builder = ValidationResult.LayerResult.builder();

        // When
        ValidationResult.LayerResult layerResult = builder
                .layer(1)
                .layerName(TEST_LAYER_NAME)
                .valid(true)
                .message("Validation passed")
                .build();

        // Then
        assertThat(layerResult).isNotNull();
        assertThat(layerResult.getLayer()).isEqualTo(1);
        assertThat(layerResult.getLayerName()).isEqualTo(TEST_LAYER_NAME);
        assertThat(layerResult.isValid()).isTrue();
    }

    @Test
    @DisplayName("Should build LayerResult instance with only layer and valid")
    void shouldBuildLayerResultInstanceWithOnlyLayerAndValidWhenOnlyLayerAndValidAreSet() {
        // Given
        ValidationResult.LayerResult layerResult = ValidationResult.LayerResult.builder()
                .layer(1)
                .valid(true)
                .build();

        // Then
        assertThat(layerResult).isNotNull();
        assertThat(layerResult.getLayer()).isEqualTo(1);
        assertThat(layerResult.isValid()).isTrue();
        assertThat(layerResult.getLayerName()).isNull();
        assertThat(layerResult.getMessage()).isNull();
    }

    @Test
    @DisplayName("Should build ValidationResult instance with all fields when all setters are called")
    void shouldBuildValidationResultInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        ValidationResult.LayerResult layerResult1 = ValidationResult.LayerResult.builder()
                .layer(1)
                .layerName("Layer1")
                .valid(true)
                .message("Passed")
                .build();

        ValidationResult.LayerResult layerResult2 = ValidationResult.LayerResult.builder()
                .layer(2)
                .layerName("Layer2")
                .valid(false)
                .message("Failed")
                .build();

        ValidationResult result = ValidationResult.builder()
                .valid(false)
                .layerResults(List.of(layerResult1, layerResult2))
                .errors(List.of("Error 1", "Error 2"))
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getLayerResults()).hasSize(2);
        assertThat(result.getErrors()).hasSize(2);
    }

    @Test
    @DisplayName("Should support method chaining when using ValidationResult builder")
    void shouldSupportMethodChainingWhenUsingValidationResultBuilder() {
        // Given
        ValidationResult.LayerResult layerResult = ValidationResult.LayerResult.builder()
                .layer(1)
                .valid(true)
                .build();

        ValidationResult.Builder builder = ValidationResult.builder();

        // When
        ValidationResult result = builder
                .valid(true)
                .layerResults(List.of(layerResult))
                .errors(List.of())
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getLayerResults()).hasSize(1);
    }

    @Test
    @DisplayName("Should build ValidationResult instance with only valid flag")
    void shouldBuildValidationResultInstanceWithOnlyValidFlagWhenOnlyValidIsSet() {
        // Given
        ValidationResult result = ValidationResult.builder()
                .valid(true)
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getLayerResults()).isNull();
        assertThat(result.getErrors()).isNull();
    }

    @Test
    @DisplayName("Should build ValidationResult with empty layer results and errors")
    void shouldBuildValidationResultWithEmptyLayerResultsAndErrorsWhenEmptyListsAreSet() {
        // Given
        ValidationResult result = ValidationResult.builder()
                .valid(true)
                .layerResults(List.of())
                .errors(List.of())
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getLayerResults()).isNotNull();
        assertThat(result.getLayerResults()).isEmpty();
        assertThat(result.getErrors()).isNotNull();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should handle multiple layer results")
    void shouldHandleMultipleLayerResultsWhenMultipleLayerResultsAreAdded() {
        // Given
        List<ValidationResult.LayerResult> layerResults = List.of(
                ValidationResult.LayerResult.builder().layer(1).valid(true).build(),
                ValidationResult.LayerResult.builder().layer(2).valid(true).build(),
                ValidationResult.LayerResult.builder().layer(3).valid(false).build()
        );

        ValidationResult result = ValidationResult.builder()
                .valid(false)
                .layerResults(layerResults)
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getLayerResults()).hasSize(3);
        assertThat(result.getLayerResults().get(0).getLayer()).isEqualTo(1);
        assertThat(result.getLayerResults().get(2).isValid()).isFalse();
    }

    @Test
    @DisplayName("Should handle multiple errors")
    void shouldHandleMultipleErrorsWhenMultipleErrorsAreAdded() {
        // Given
        List<String> errors = List.of(
                "Error 1: Invalid input",
                "Error 2: Missing required field",
                "Error 3: Validation failed"
        );

        ValidationResult result = ValidationResult.builder()
                .valid(false)
                .errors(errors)
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getErrors()).hasSize(3);
        assertThat(result.getErrors()).contains("Error 1: Invalid input");
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        ValidationResult.Builder builder1 = ValidationResult.builder();
        ValidationResult.Builder builder2 = ValidationResult.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        ValidationResult.Builder builder = ValidationResult.builder();

        // When
        ValidationResult result1 = builder
                .valid(true)
                .layerResults(List.of(ValidationResult.LayerResult.builder().layer(1).valid(true).build()))
                .errors(List.of())
                .build();

        ValidationResult result2 = builder
                .valid(false)
                .layerResults(List.of(ValidationResult.LayerResult.builder().layer(1).valid(false).build()))
                .errors(List.of("Error"))
                .build();

        // Then
        assertThat(result1).isNotNull();
        assertThat(result2).isNotNull();
        assertThat(result1.isValid()).isTrue();
        assertThat(result2.isValid()).isFalse();
        assertThat(result1.getLayerResults().get(0).isValid()).isTrue();
        assertThat(result2.getLayerResults().get(0).isValid()).isFalse();
    }

    @Test
    @DisplayName("Should handle different layer numbers")
    void shouldHandleDifferentLayerNumbersWhenDifferentLayersAreSet() {
        // Given
        ValidationResult.LayerResult layer1 = ValidationResult.LayerResult.builder()
                .layer(1)
                .valid(true)
                .build();

        ValidationResult.LayerResult layer2 = ValidationResult.LayerResult.builder()
                .layer(2)
                .valid(true)
                .build();

        ValidationResult.LayerResult layer3 = ValidationResult.LayerResult.builder()
                .layer(3)
                .valid(false)
                .build();

        // Then
        assertThat(layer1.getLayer()).isEqualTo(1);
        assertThat(layer2.getLayer()).isEqualTo(2);
        assertThat(layer3.getLayer()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should build successful validation result")
    void shouldBuildSuccessfulValidationResultWhenValidIsTrue() {
        // Given
        ValidationResult result = ValidationResult.builder()
                .valid(true)
                .layerResults(List.of(
                        ValidationResult.LayerResult.builder().layer(1).valid(true).build(),
                        ValidationResult.LayerResult.builder().layer(2).valid(true).build()
                ))
                .errors(List.of())
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.isValid()).isTrue();
        assertThat(result.getLayerResults()).allMatch(ValidationResult.LayerResult::isValid);
    }

    @Test
    @DisplayName("Should build failed validation result")
    void shouldBuildFailedValidationResultWhenValidIsFalse() {
        // Given
        ValidationResult result = ValidationResult.builder()
                .valid(false)
                .layerResults(List.of(
                        ValidationResult.LayerResult.builder().layer(1).valid(true).build(),
                        ValidationResult.LayerResult.builder().layer(2).valid(false).build()
                ))
                .errors(List.of("Validation failed at layer 2"))
                .build();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.isValid()).isFalse();
        assertThat(result.getErrors()).hasSize(1);
    }
}
