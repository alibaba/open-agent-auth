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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Result of a validation operation in the five-layer verification architecture.
 * <p>
 * This class encapsulates the outcome of a validation step, including success/failure status,
 * error messages, and any additional metadata. It follows the immutable pattern to ensure
 * thread-safety and prevent accidental modifications.
 * </p>
 * <p>
 * <b>Design Principles:</b>
 * <ul>
 *   <li><b>Immutability</b>: Once created, the result cannot be modified</li>
 *   <li><b>Builder Pattern</b>: Provides a fluent API for constructing results</li>
   *   <li><b>Rich Error Information</b>: Supports multiple error messages with detailed context</li>
 *   <li><b>Type Safety</b>: Strong typing ensures compile-time correctness</li>
 * </ul>
 * </p>
 *
 * @see ValidationContext
 * @since 1.0
 */
public class LayerValidationResult {

    /**
     * Indicates whether the validation was successful.
     */
    private final boolean success;

    /**
     * Error messages explaining why validation failed.
     * <p>
     * This list is empty when validation succeeds.
     * </p>
     */
    private final List<String> errors;

    /**
     * Additional metadata about the validation result.
     * <p>
     * This can include information such as validation layer name, timing information,
     * or other diagnostic data.
     * </p>
     */
    private final String metadata;

    /**
     * Private constructor to enforce immutability.
     *
     * @param builder the builder instance
     */
    private LayerValidationResult(Builder builder) {
        this.success = builder.success;
        this.errors = builder.errors != null ? 
                Collections.unmodifiableList(new ArrayList<>(builder.errors)) : 
                Collections.emptyList();
        this.metadata = builder.metadata;
    }

    /**
     * Checks if the validation was successful.
     *
     * @return true if validation succeeded, false otherwise
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * Checks if the validation failed.
     *
     * @return true if validation failed, false otherwise
     */
    public boolean isFailure() {
        return !success;
    }

    /**
     * Gets the list of error messages.
     *
     * @return an unmodifiable list of error messages
     */
    public List<String> getErrors() {
        return errors;
    }

    /**
     * Gets the metadata associated with this result.
     *
     * @return the metadata, or null if not set
     */
    public String getMetadata() {
        return metadata;
    }

    /**
     * Creates a successful validation result.
     *
     * @return a successful result with no errors
     */
    public static LayerValidationResult success() {
        return new Builder().success(true).build();
    }

    /**
     * Creates a successful validation result with metadata.
     *
     * @param metadata the metadata to include
     * @return a successful result with the specified metadata
     */
    public static LayerValidationResult success(String metadata) {
        return new Builder().success(true).metadata(metadata).build();
    }

    /**
     * Creates a failed validation result.
     *
     * @param error the error message
     * @return a failed result with the specified error
     */
    public static LayerValidationResult failure(String error) {
        return new Builder().success(false).addError(error).build();
    }

    /**
     * Creates a failed validation result with multiple errors.
     *
     * @param errors the error messages
     * @return a failed result with the specified errors
     */
    public static LayerValidationResult failure(List<String> errors) {
        return new Builder().success(false).errors(errors).build();
    }

    /**
     * Creates a failed validation result with error and metadata.
     *
     * @param error the error message
     * @param metadata the metadata to include
     * @return a failed result with the specified error and metadata
     */
    public static LayerValidationResult failure(String error, String metadata) {
        return new Builder().success(false).addError(error).metadata(metadata).build();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LayerValidationResult that = (LayerValidationResult) o;
        return success == that.success &&
                Objects.equals(errors, that.errors) &&
                Objects.equals(metadata, that.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(success, errors, metadata);
    }

    @Override
    public String toString() {
        return "ValidationResult{" +
                "success=" + success +
                ", errors=" + errors +
                ", metadata='" + metadata + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link LayerValidationResult}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link LayerValidationResult}.
     * <p>
     * Provides a fluent API for constructing validation results.
     * </p>
     */
    public static class Builder {

        private boolean success;
        private List<String> errors;
        private String metadata;

        /**
         * Sets whether the validation was successful.
         *
         * @param success true if successful, false otherwise
         * @return this builder instance
         */
        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        /**
         * Adds an error message.
         *
         * @param error the error message
         * @return this builder instance
         */
        public Builder addError(String error) {
            if (this.errors == null) {
                this.errors = new ArrayList<>();
            }
            this.errors.add(error);
            return this;
        }

        /**
         * Sets all error messages.
         *
         * @param errors the error messages
         * @return this builder instance
         */
        public Builder errors(List<String> errors) {
            this.errors = errors;
            return this;
        }

        /**
         * Sets the metadata.
         *
         * @param metadata the metadata
         * @return this builder instance
         */
        public Builder metadata(String metadata) {
            this.metadata = metadata;
            return this;
        }

        /**
         * Builds the {@link LayerValidationResult}.
         *
         * @return the built validation result
         */
        public LayerValidationResult build() {
            // If success is true but there are errors, log a warning
            if (success && errors != null && !errors.isEmpty()) {
                // This is a programming error - success should not be true with errors
                throw new IllegalStateException("Validation result cannot be successful with errors");
            }
            return new LayerValidationResult(this);
        }
    }
}
