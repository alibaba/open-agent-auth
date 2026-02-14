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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Validation domain exceptions.
 * <p>
 * This test class validates the functionality of validation and authorization context
 * exceptions in the Framework module.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Validation Exception Test")
class ValidationExceptionTest {

    @Test
    @DisplayName("Test FrameworkValidationException with message")
    void testFrameworkValidationExceptionWithMessage() {
        FrameworkValidationException exception = new FrameworkValidationException("Validation failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Validation failed");
        assertThat(exception.getErrorParams()).containsExactly("Validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Test FrameworkValidationException with message and failed layer")
    void testFrameworkValidationExceptionWithMessageAndFailedLayer() {
        FrameworkValidationException exception = new FrameworkValidationException(2, "Validation failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Validation failed");
        assertThat(exception.getErrorParams()).containsExactly("Validation failed");
        assertThat(exception.getFailedLayer()).isEqualTo(2);
    }

    @Test
    @DisplayName("Test FrameworkValidationException with message and cause")
    void testFrameworkValidationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Invalid parameter");
        FrameworkValidationException exception = new FrameworkValidationException("Validation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Validation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getFailedLayer()).isEqualTo(0);
    }

    @Test
    @DisplayName("Test FrameworkValidationException with message, failed layer and cause")
    void testFrameworkValidationExceptionWithMessageFailedLayerAndCause() {
        Throwable cause = new RuntimeException("Invalid parameter");
        FrameworkValidationException exception = new FrameworkValidationException(3, "Validation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: Validation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getFailedLayer()).isEqualTo(3);
    }

    @Test
    @DisplayName("Test FrameworkAuthorizationContextException with message")
    void testFrameworkAuthorizationContextExceptionWithMessage() {
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException("Context preparation failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization context preparation failed: Context preparation failed");
        assertThat(exception.getErrorParams()).containsExactly("Context preparation failed");
    }

    @Test
    @DisplayName("Test FrameworkAuthorizationContextException with message and cause")
    void testFrameworkAuthorizationContextExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Missing WIT token");
        FrameworkAuthorizationContextException exception = new FrameworkAuthorizationContextException("Context preparation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0302");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization context preparation failed: Context preparation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test ValidationErrorCode properties")
    void testValidationErrorCodeProperties() {
        assertThat(ValidationErrorCode.DOMAIN_CODE).isEqualTo("03");
        
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorName()).isEqualTo("FrameworkValidationFailed");
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getHttpStatus().value()).isEqualTo(400);
        
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0302");
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getErrorName()).isEqualTo("FrameworkAuthContextPreparationFailed");
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Test ValidationErrorCode formatMessage")
    void testValidationErrorCodeFormatMessage() {
        String message = ValidationErrorCode.VALIDATION_FAILED.formatMessage("username is empty");
        assertThat(message).isEqualTo("Framework validation failed: username is empty");
        
        message = ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.formatMessage("WIT token missing");
        assertThat(message).isEqualTo("Framework authorization context preparation failed: WIT token missing");
    }
}
