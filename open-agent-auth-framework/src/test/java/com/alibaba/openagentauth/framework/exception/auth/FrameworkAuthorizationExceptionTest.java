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
package com.alibaba.openagentauth.framework.exception.auth;

import com.alibaba.openagentauth.framework.exception.FrameworkException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for FrameworkAuthorizationException.
 * <p>
 * This test class validates the functionality of the authorization exception,
 * including constructors, message formatting, and cause chaining.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkAuthorizationException Test")
class FrameworkAuthorizationExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException(
                "User not authorized to perform this action");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0102");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization failed: User not authorized to perform this action");
        assertThat(exception.getMessage()).contains("User not authorized to perform this action");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Permission check failed");
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException(
                "Authorization failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0102");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization failed: Authorization failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getMessage()).isEqualTo("Permission check failed");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new SecurityException("Access denied");
        Throwable intermediateCause = new RuntimeException("Authorization check failed", rootCause);
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException(
                "Cannot authorize request", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of AuthException")
    void shouldBeInstanceOfAuthException() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException(
                "test error");

        assertThat(exception).isInstanceOf(AuthException.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException(
                "test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_01");
        assertThat(exception.getErrorCode()).endsWith("02");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should have different error code from authentication exception")
    void shouldHaveDifferentErrorCodeFromAuthenticationException() {
        FrameworkAuthenticationException authnException = new FrameworkAuthenticationException("test");
        FrameworkAuthorizationException authzException = new FrameworkAuthorizationException("test");

        assertThat(authnException.getErrorCode()).isNotEqualTo(authzException.getErrorCode());
        assertThat(authnException.getErrorCode()).endsWith("01");
        assertThat(authzException.getErrorCode()).endsWith("02");
    }
}
