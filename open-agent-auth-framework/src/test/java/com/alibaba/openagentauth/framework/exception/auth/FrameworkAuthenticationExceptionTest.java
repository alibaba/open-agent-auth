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
 * Test class for FrameworkAuthenticationException.
 * <p>
 * This test class validates the functionality of the authentication exception,
 * including constructors, message formatting, and cause chaining.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkAuthenticationException Test")
class FrameworkAuthenticationExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException(
                "Invalid credentials");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: Invalid credentials");
        assertThat(exception.getMessage()).contains("Invalid credentials");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Token expired");
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException(
                "Authentication failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: Authentication failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getMessage()).isEqualTo("Token expired");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new NullPointerException("Missing token");
        Throwable intermediateCause = new RuntimeException("Auth failed", rootCause);
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException(
                "Cannot authenticate user", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of AuthException")
    void shouldBeInstanceOfAuthException() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException(
                "test error");

        assertThat(exception).isInstanceOf(AuthException.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException(
                "test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_01");
        assertThat(exception.getErrorCode()).endsWith("01");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should have different error code from authorization exception")
    void shouldHaveDifferentErrorCodeFromAuthorizationException() {
        FrameworkAuthenticationException authnException = new FrameworkAuthenticationException("test");
        FrameworkAuthorizationException authzException = new FrameworkAuthorizationException("test");

        assertThat(authnException.getErrorCode()).isNotEqualTo(authzException.getErrorCode());
        assertThat(authnException.getErrorCode()).endsWith("01");
        assertThat(authzException.getErrorCode()).endsWith("02");
    }
}
