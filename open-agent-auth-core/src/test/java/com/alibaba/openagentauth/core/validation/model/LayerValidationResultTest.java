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
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link LayerValidationResult}.
 */
@DisplayName("LayerValidationResult Tests")
class LayerValidationResultTest {

    @Test
    @DisplayName("Should create successful result")
    void shouldCreateSuccessfulResult() {
        // Act
        LayerValidationResult result = LayerValidationResult.success();

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.isFailure()).isFalse();
        assertThat(result.getErrors()).isEmpty();
        assertThat(result.getMetadata()).isNull();
    }

    @Test
    @DisplayName("Should create successful result with metadata")
    void shouldCreateSuccessfulResultWithMetadata() {
        // Arrange
        String metadata = "Test metadata";

        // Act
        LayerValidationResult result = LayerValidationResult.success(metadata);

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMetadata()).isEqualTo(metadata);
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should create failed result with single error")
    void shouldCreateFailedResultWithSingleError() {
        // Arrange
        String error = "Validation failed";

        // Act
        LayerValidationResult result = LayerValidationResult.failure(error);

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.isFailure()).isTrue();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).isEqualTo(error);
    }

    @Test
    @DisplayName("Should create failed result with multiple errors")
    void shouldCreateFailedResultWithMultipleErrors() {
        // Arrange
        List<String> errors = Arrays.asList("Error 1", "Error 2", "Error 3");

        // Act
        LayerValidationResult result = LayerValidationResult.failure(errors);

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).hasSize(3);
        assertThat(result.getErrors()).containsExactlyElementsOf(errors);
    }

    @Test
    @DisplayName("Should create failed result with error and metadata")
    void shouldCreateFailedResultWithErrorAndMetadata() {
        // Arrange
        String error = "Validation failed";
        String metadata = "Test metadata";

        // Act
        LayerValidationResult result = LayerValidationResult.failure(error, metadata);

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).hasSize(1);
        assertThat(result.getErrors().get(0)).isEqualTo(error);
        assertThat(result.getMetadata()).isEqualTo(metadata);
    }

    @Test
    @DisplayName("Should build result using builder")
    void shouldBuildResultUsingBuilder() {
        // Arrange & Act
        LayerValidationResult result = LayerValidationResult.builder()
                .success(true)
                .metadata("Test metadata")
                .build();

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMetadata()).isEqualTo("Test metadata");
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should build failed result using builder with errors")
    void shouldBuildFailedResultUsingBuilderWithErrors() {
        // Arrange & Act
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .addError("Error 1")
                .addError("Error 2")
                .metadata("Failed validation")
                .build();

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).hasSize(2);
        assertThat(result.getErrors()).containsExactly("Error 1", "Error 2");
        assertThat(result.getMetadata()).isEqualTo("Failed validation");
    }

    @Test
    @DisplayName("Should build result with error list")
    void shouldBuildResultWithErrorList() {
        // Arrange
        List<String> errors = Arrays.asList("Error 1", "Error 2");

        // Act
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .errors(errors)
                .build();

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).hasSize(2);
        assertThat(result.getErrors()).containsExactlyElementsOf(errors);
    }

    @Test
    @DisplayName("Should throw exception when building successful result with errors")
    void shouldThrowExceptionWhenBuildingSuccessfulResultWithErrors() {
        // Act & Assert
        assertThatThrownBy(() -> LayerValidationResult.builder()
                .success(true)
                .addError("Error")
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be successful with errors");
    }

    @Test
    @DisplayName("Should return unmodifiable errors list")
    void shouldReturnUnmodifiableErrorsList() {
        // Arrange
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .addError("Error 1")
                .addError("Error 2")
                .build();

        // Act & Assert
        assertThatThrownBy(() -> result.getErrors().add("New Error"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Should handle empty error list")
    void shouldHandleEmptyErrorList() {
        // Arrange
        List<String> emptyErrors = new ArrayList<>();

        // Act
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .errors(emptyErrors)
                .build();

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should handle null error list")
    void shouldHandleNullErrorList() {
        // Act
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .errors(null)
                .build();

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should support fluent builder pattern")
    void shouldSupportFluentBuilderPattern() {
        // Arrange & Act
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .addError("Error 1")
                .addError("Error 2")
                .addError("Error 3")
                .metadata("Multiple errors")
                .build();

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getErrors()).hasSize(3);
        assertThat(result.getMetadata()).isEqualTo("Multiple errors");
    }

    @Test
    @DisplayName("Should implement equals correctly")
    void shouldImplementEqualsCorrectly() {
        // Arrange
        LayerValidationResult result1 = LayerValidationResult.builder()
                .success(false)
                .addError("Error")
                .metadata("Test")
                .build();

        LayerValidationResult result2 = LayerValidationResult.builder()
                .success(false)
                .addError("Error")
                .metadata("Test")
                .build();

        LayerValidationResult result3 = LayerValidationResult.builder()
                .success(true)
                .build();

        // Act & Assert
        assertThat(result1).isEqualTo(result2);
        assertThat(result1).isNotEqualTo(result3);
        assertThat(result1).isNotEqualTo(null);
        assertThat(result1).isNotEqualTo("string");
    }

    @Test
    @DisplayName("Should implement hashCode correctly")
    void shouldImplementHashCodeCorrectly() {
        // Arrange
        LayerValidationResult result1 = LayerValidationResult.builder()
                .success(false)
                .addError("Error")
                .metadata("Test")
                .build();

        LayerValidationResult result2 = LayerValidationResult.builder()
                .success(false)
                .addError("Error")
                .metadata("Test")
                .build();

        // Act & Assert
        assertThat(result1.hashCode()).isEqualTo(result2.hashCode());
    }

    @Test
    @DisplayName("Should implement toString correctly")
    void shouldImplementToStringCorrectly() {
        // Arrange
        LayerValidationResult result = LayerValidationResult.builder()
                .success(false)
                .addError("Error 1")
                .addError("Error 2")
                .metadata("Test")
                .build();

        // Act
        String toString = result.toString();

        // Assert
        assertThat(toString).contains("success=false");
        assertThat(toString).contains("Error 1");
        assertThat(toString).contains("Error 2");
        assertThat(toString).contains("metadata='Test'");
    }

    @Test
    @DisplayName("Should create successful result without metadata")
    void shouldCreateSuccessfulResultWithoutMetadata() {
        // Act
        LayerValidationResult result = LayerValidationResult.success();

        // Assert
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMetadata()).isNull();
        assertThat(result.getErrors()).isEmpty();
    }

    @Test
    @DisplayName("Should create failed result without metadata")
    void shouldCreateFailedResultWithoutMetadata() {
        // Arrange
        String error = "Validation failed";

        // Act
        LayerValidationResult result = LayerValidationResult.failure(error);

        // Assert
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMetadata()).isNull();
        assertThat(result.getErrors()).hasSize(1);
    }
}
