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
package com.alibaba.openagentauth.core.exception.binding;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for BindingErrorCode enum.
 * <p>
 * This test class validates the error code structure, message templates,
 * and HTTP status codes for all Binding error codes.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Binding Error Code Test")
class BindingErrorCodeTest {

    @Test
    @DisplayName("Should verify BINDING_NOT_FOUND error code properties")
    void shouldVerifyBindingNotFoundErrorCodeProperties() {
        BindingErrorCode errorCode = BindingErrorCode.BINDING_NOT_FOUND;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0701");
        assertThat(errorCode.getDomainCode()).isEqualTo("07");
        assertThat(errorCode.getSubCode()).isEqualTo("01");
        assertThat(errorCode.getSystemCode()).isEqualTo("10");
        assertThat(errorCode.getErrorName()).isEqualTo("BindingNotFound");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Binding instance not found: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(404);
    }

    @Test
    @DisplayName("Should verify BINDING_EXPIRED error code properties")
    void shouldVerifyBindingExpiredErrorCodeProperties() {
        BindingErrorCode errorCode = BindingErrorCode.BINDING_EXPIRED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0702");
        assertThat(errorCode.getDomainCode()).isEqualTo("07");
        assertThat(errorCode.getSubCode()).isEqualTo("02");
        assertThat(errorCode.getErrorName()).isEqualTo("BindingExpired");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Binding instance has expired: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(404);
    }

    @Test
    @DisplayName("Should verify BINDING_VALIDATION_FAILED error code properties")
    void shouldVerifyBindingValidationFailedErrorCodeProperties() {
        BindingErrorCode errorCode = BindingErrorCode.BINDING_VALIDATION_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0703");
        assertThat(errorCode.getDomainCode()).isEqualTo("07");
        assertThat(errorCode.getSubCode()).isEqualTo("03");
        assertThat(errorCode.getErrorName()).isEqualTo("BindingValidationFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Binding validation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should verify BINDING_ALREADY_EXISTS error code properties")
    void shouldVerifyBindingAlreadyExistsErrorCodeProperties() {
        BindingErrorCode errorCode = BindingErrorCode.BINDING_ALREADY_EXISTS;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0704");
        assertThat(errorCode.getDomainCode()).isEqualTo("07");
        assertThat(errorCode.getSubCode()).isEqualTo("04");
        assertThat(errorCode.getErrorName()).isEqualTo("BindingAlreadyExists");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Binding instance already exists: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(409);
    }

    @Test
    @DisplayName("Should verify all error codes have correct domain code")
    void shouldVerifyAllErrorCodesHaveCorrectDomainCode() {
        assertThat(BindingErrorCode.BINDING_NOT_FOUND.getDomainCode()).isEqualTo("07");
        assertThat(BindingErrorCode.BINDING_EXPIRED.getDomainCode()).isEqualTo("07");
        assertThat(BindingErrorCode.BINDING_VALIDATION_FAILED.getDomainCode()).isEqualTo("07");
        assertThat(BindingErrorCode.BINDING_ALREADY_EXISTS.getDomainCode()).isEqualTo("07");
    }

    @Test
    @DisplayName("Should verify all error codes have correct system code")
    void shouldVerifyAllErrorCodesHaveCorrectSystemCode() {
        assertThat(BindingErrorCode.BINDING_NOT_FOUND.getSystemCode()).isEqualTo("10");
        assertThat(BindingErrorCode.BINDING_EXPIRED.getSystemCode()).isEqualTo("10");
        assertThat(BindingErrorCode.BINDING_VALIDATION_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(BindingErrorCode.BINDING_ALREADY_EXISTS.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Should verify domain code constant")
    void shouldVerifyDomainCodeConstant() {
        assertThat(BindingErrorCode.DOMAIN_CODE).isEqualTo("07");
    }

    @Test
    @DisplayName("Should verify unique sub codes")
    void shouldVerifyUniqueSubCodes() {
        assertThat(BindingErrorCode.BINDING_NOT_FOUND.getSubCode()).isEqualTo("01");
        assertThat(BindingErrorCode.BINDING_EXPIRED.getSubCode()).isEqualTo("02");
        assertThat(BindingErrorCode.BINDING_VALIDATION_FAILED.getSubCode()).isEqualTo("03");
        assertThat(BindingErrorCode.BINDING_ALREADY_EXISTS.getSubCode()).isEqualTo("04");
    }

    @Test
    @DisplayName("Should verify error code format consistency")
    void shouldVerifyErrorCodeFormatConsistency() {
        for (BindingErrorCode errorCode : BindingErrorCode.values()) {
            assertThat(errorCode.getErrorCode()).matches("OPEN_AGENT_AUTH_10_07\\d{2}");
            assertThat(errorCode.getErrorCode()).hasSize(23);
        }
    }
}