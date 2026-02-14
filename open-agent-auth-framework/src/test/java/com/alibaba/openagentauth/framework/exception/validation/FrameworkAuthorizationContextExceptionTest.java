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
 * Test class for FrameworkAuthorizationContextException.
 * <p>
 * This test class validates the functionality of the authorization context preparation
 * exception, including constructors, message formatting, and cause chaining.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkAuthorizationContextException Test")
class FrameworkAuthorizationContextExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException(
                "Missing WIT token");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization context preparation failed: Missing WIT token");
        assertThat(exception.getMessage()).contains("Missing WIT token");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Failed to retrieve WPT token");
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException(
                "Authorization context preparation failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization context preparation failed: Authorization context preparation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getMessage()).isEqualTo("Failed to retrieve WPT token");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new NullPointerException("Token is null");
        Throwable intermediateCause = new RuntimeException("Cannot build context", rootCause);
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException(
                "Context preparation error", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of ValidationException")
    void shouldBeInstanceOfValidationException() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException(
                "test error");

        assertThat(exception).isInstanceOf(ValidationException.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException(
                "test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_03");
        assertThat(exception.getErrorCode()).endsWith("02");
    }

    @Test
    @DisplayName("Should have different error code from validation exception")
    void shouldHaveDifferentErrorCodeFromValidationException() {
        FrameworkValidationException validationException = new FrameworkValidationException("test");
        FrameworkAuthorizationContextException authContextException = new FrameworkAuthorizationContextException("test");

        assertThat(validationException.getErrorCode()).isNotEqualTo(authContextException.getErrorCode());
        assertThat(validationException.getErrorCode()).endsWith("01");
        assertThat(authContextException.getErrorCode()).endsWith("02");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization context preparation failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }
}
