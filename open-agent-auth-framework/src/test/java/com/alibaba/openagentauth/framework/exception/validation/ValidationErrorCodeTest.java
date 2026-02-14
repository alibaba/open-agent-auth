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

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for ValidationErrorCode enum.
 * <p>
 * This test class validates the error code definitions for the Validation domain,
 * ensuring proper error code structure, message templates, and HTTP status mapping.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ValidationErrorCode Test")
class ValidationErrorCodeTest {

    @Test
    @DisplayName("Should have correct domain code")
    void shouldHaveCorrectDomainCode() {
        assertThat(ValidationErrorCode.DOMAIN_CODE).isEqualTo("03");
    }

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getSystemCode()).isEqualTo("11");
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should generate correct error code for VALIDATION_FAILED")
    void shouldGenerateCorrectErrorCodeForValidationFailed() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0301");
    }

    @Test
    @DisplayName("Should generate correct error code for AUTHORIZATION_CONTEXT_PREPARATION_FAILED")
    void shouldGenerateCorrectErrorCodeForAuthorizationContextPreparationFailed() {
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0302");
    }

    @Test
    @DisplayName("Should have correct sub codes")
    void shouldHaveCorrectSubCodes() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getSubCode()).isEqualTo("01");
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Should have correct error names")
    void shouldHaveCorrectErrorNames() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getErrorName())
                .isEqualTo("FrameworkValidationFailed");
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getErrorName())
                .isEqualTo("FrameworkAuthContextPreparationFailed");
    }

    @Test
    @DisplayName("Should have correct message templates")
    void shouldHaveCorrectMessageTemplates() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getMessageTemplate())
                .isEqualTo("Framework validation failed: {0}");
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getMessageTemplate())
                .isEqualTo("Framework authorization context preparation failed: {0}");
    }

    @Test
    @DisplayName("Should have correct HTTP status codes")
    void shouldHaveCorrectHttpStatusCodes() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    @DisplayName("Should format messages correctly")
    void shouldFormatMessagesCorrectly() {
        String validationMessage = ValidationErrorCode.VALIDATION_FAILED.formatMessage("Invalid parameter");
        assertThat(validationMessage).isEqualTo("Framework validation failed: Invalid parameter");

        String authContextMessage = ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.formatMessage("Missing WIT token");
        assertThat(authContextMessage).isEqualTo("Framework authorization context preparation failed: Missing WIT token");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String message = ValidationErrorCode.VALIDATION_FAILED.formatMessage((Object[]) null);
        assertThat(message).isEqualTo("Framework validation failed: {0}");
    }

    @Test
    @DisplayName("Should implement FrameworkErrorCode")
    void shouldImplementFrameworkErrorCode() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
        assertThat(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
    }

    @Test
    @DisplayName("Should verify error codes are sequential")
    void shouldVerifyErrorCodesAreSequential() {
        String firstCode = ValidationErrorCode.VALIDATION_FAILED.getErrorCode();
        String secondCode = ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getErrorCode();

        assertThat(firstCode).endsWith("01");
        assertThat(secondCode).endsWith("02");
    }

    @Test
    @DisplayName("Should have consistent domain code across all enum values")
    void shouldHaveConsistentDomainCodeAcrossAllEnumValues() {
        assertThat(ValidationErrorCode.VALIDATION_FAILED.getDomainCode())
                .isEqualTo(ValidationErrorCode.AUTHORIZATION_CONTEXT_PREPARATION_FAILED.getDomainCode())
                .isEqualTo("03");
    }
}
