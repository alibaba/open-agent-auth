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
package com.alibaba.openagentauth.framework.exception.oauth2;

import com.alibaba.openagentauth.framework.exception.FrameworkException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for FrameworkParProcessingException.
 * <p>
 * This test class validates the functionality of the PAR (Pushed Authorization Request)
 * processing exception, including constructors, message formatting, and cause chaining.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkParProcessingException Test")
class FrameworkParProcessingExceptionTest {

    @Test
    @DisplayName("Should create exception with message only")
    void shouldCreateExceptionWithMessageOnly() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException(
                "PAR request validation failed");

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0401");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework PAR processing failed: PAR request validation failed");
        assertThat(exception.getMessage()).contains("PAR request validation failed");
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with message and cause")
    void shouldCreateExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Invalid redirect URI");
        FrameworkParProcessingException exception = new FrameworkParProcessingException(
                "PAR processing error", cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0401");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework PAR processing failed: PAR processing error");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getMessage()).isEqualTo("Invalid redirect URI");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new NullPointerException("Missing parameter");
        Throwable intermediateCause = new RuntimeException("Validation failed", rootCause);
        FrameworkParProcessingException exception = new FrameworkParProcessingException(
                "Cannot process PAR request", intermediateCause);

        assertThat(exception.getCause()).isEqualTo(intermediateCause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should be instance of OAuth2Exception")
    void shouldBeInstanceOfOauth2Exception() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException(
                "test error");

        assertThat(exception).isInstanceOf(OAuth2Exception.class);
    }

    @Test
    @DisplayName("Should be instance of FrameworkException")
    void shouldBeInstanceOfFrameworkException() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException(
                "test error");

        assertThat(exception).isInstanceOf(FrameworkException.class);
    }

    @Test
    @DisplayName("Should have correct error code constant")
    void shouldHaveCorrectErrorCodeConstant() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException("test");

        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_11_04");
        assertThat(exception.getErrorCode()).endsWith("01");
    }

    @Test
    @DisplayName("Should handle empty message")
    void shouldHandleEmptyMessage() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException("");

        assertThat(exception.getFormattedMessage()).isEqualTo("Framework PAR processing failed: ");
        assertThat(exception.getErrorParams()).containsExactly("");
    }

    @Test
    @DisplayName("Should handle null in exception chain")
    void shouldHandleNullInExceptionChain() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException(
                "test error", null);

        assertThat(exception.getCause()).isNull();
    }
}
