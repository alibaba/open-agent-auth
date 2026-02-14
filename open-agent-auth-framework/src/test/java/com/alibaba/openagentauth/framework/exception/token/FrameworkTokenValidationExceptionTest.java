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
 * Test class for FrameworkTokenValidationException.
 * <p>
 * This test class validates the functionality of the token validation exception,
 * including constructors, message formatting, and cause chaining.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkTokenValidationException Test")
class FrameworkTokenValidationExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException(
                "Invalid token signature");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0202");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token validation failed: Invalid token signature");
        assertThat(exception.getMessage()).contains("Invalid token signature");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Expired at 2025-01-01");
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException(
                "Token expired", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0202");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token validation failed: Token expired");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getMessage()).isEqualTo("Expired at 2025-01-01");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new SecurityException("Invalid signature");
        Throwable intermediateCause = new RuntimeException("Validation failed", rootCause);
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException(
                "Token validation error", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of TokenException")
    void shouldBeInstanceOfTokenException() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException(
                "test error");

        assertThat(exception).isInstanceOf(TokenException.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException(
                "test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_02");
        assertThat(exception.getErrorCode()).endsWith("02");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token validation failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should have different error code from generation exception")
    void shouldHaveDifferentErrorCodeFromGenerationException() {
        FrameworkTokenGenerationException generationException = new FrameworkTokenGenerationException("test");
        FrameworkTokenValidationException validationException = new FrameworkTokenValidationException("test");

        assertThat(generationException.getErrorCode()).isNotEqualTo(validationException.getErrorCode());
        assertThat(generationException.getErrorCode()).endsWith("01");
        assertThat(validationException.getErrorCode()).endsWith("02");
    }
}
