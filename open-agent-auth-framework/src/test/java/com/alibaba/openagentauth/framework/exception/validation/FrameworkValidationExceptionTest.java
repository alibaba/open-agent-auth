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
package com.alibaba.openagentauth.framework.exception.validation;

import com.alibaba.openagentauth.framework.exception.FrameworkException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for FrameworkValidationException.
 * <p>
 * This test class validates the functionality of the framework validation exception,
 * including constructors, message formatting, cause chaining, and failed layer tracking.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkValidationException Test")
class FrameworkValidationExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkValidationException exception = new FrameworkValidationException(
                "Request validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Request validation failed");
        assertThat(exception.getMessage()).contains("Request validation failed");
        assertThat(exception.getCause()).isNull();
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should create exception with message and failed layer")
    void shouldCreateExceptionWithMessageAndFailedLayer() {
        FrameworkValidationException exception = new FrameworkValidationException(
                2, "Layer 2 validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Layer 2 validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Validation logic error");
        FrameworkValidationException exception = new FrameworkValidationException(
                "Cannot validate request", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Cannot validate request");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Should create exception with message, failed layer, and cause")
    void shouldCreateExceptionWithMessageFailedLayerAndCause() {
        Throwable cause = new RuntimeException("Layer 3 error");
        FrameworkValidationException exception = new FrameworkValidationException(
                3, "Layer 3 validation failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Layer 3 validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(3);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new NullPointerException("Missing field");
        Throwable intermediateCause = new RuntimeException("Validation failed", rootCause);
        FrameworkValidationException exception = new FrameworkValidationException(
                "Validation error", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of ValidationException")
    void shouldBeInstanceOfValidationException() {
        FrameworkValidationException exception = new FrameworkValidationException("test error");

        assertThat(exception).isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkValidationException exception = new FrameworkValidationException("test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkValidationException exception = new FrameworkValidationException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_03");
        assertThat(exception.getErrorCode()).endsWith("01");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkValidationException exception = new FrameworkValidationException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle all valid layers")
    void shouldHandleAllValidLayers() {
        for (int layer = 0; layer <= 4; layer++) {
            FrameworkValidationException exception = new FrameworkValidationException(
                    layer, "Layer " + layer + " error");
            assertThat(exception.getFailedLayer()).isEqualTo(layer);
        }
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkValidationException exception = new FrameworkValidationException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should track failed layer when cause is present")
    void shouldTrackFailedLayerWhenCauseIsPresent() {
        Throwable cause = new RuntimeException("Error");
        FrameworkValidationException exception = new FrameworkValidationException(
                4, "Layer 4 error", cause);

        assertThat(exception.getFailedLayer()).isEqualTo(4);
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
