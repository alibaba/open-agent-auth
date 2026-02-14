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
package com.alibaba.openagentauth.framework.exception.token;

import com.alibaba.openagentauth.framework.exception.FrameworkException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for FrameworkTokenGenerationException.
 * <p>
 * This test class validates the functionality of the token generation exception,
 * including constructors, message formatting, and cause chaining.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkTokenGenerationException Test")
class FrameworkTokenGenerationExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException(
                "Failed to generate AOAT token");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token generation failed: Failed to generate AOAT token");
        assertThat(exception.getMessage()).contains("Failed to generate AOAT token");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Missing signing key");
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException(
                "Token generation failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token generation failed: Token generation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getMessage()).isEqualTo("Missing signing key");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new NullPointerException("Key is null");
        Throwable intermediateCause = new RuntimeException("Cryptographic operation failed", rootCause);
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException(
                "Cannot generate token", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of TokenException")
    void shouldBeInstanceOfTokenException() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException(
                "test error");

        assertThat(exception).isInstanceOf(TokenException.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException(
                "test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_02");
        assertThat(exception.getErrorCode()).endsWith("01");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token generation failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }
}
