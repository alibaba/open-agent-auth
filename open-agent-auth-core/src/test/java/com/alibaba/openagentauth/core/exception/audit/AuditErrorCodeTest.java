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
package com.alibaba.openagentauth.core.exception.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for AuditErrorCode enum.
 * <p>
 * This test class validates the error code structure, message templates,
 * and HTTP status codes for all Audit error codes.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Audit Error Code Test")
class AuditErrorCodeTest {

    @Test
    @DisplayName("Should verify AUDIT_STORAGE_FAILED error code properties")
    void shouldVerifyAuditStorageFailedErrorCodeProperties() {
        AuditErrorCode errorCode = AuditErrorCode.AUDIT_STORAGE_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(errorCode.getDomainCode()).isEqualTo("02");
        assertThat(errorCode.getSubCode()).isEqualTo("01");
        assertThat(errorCode.getSystemCode()).isEqualTo("10");
        assertThat(errorCode.getErrorName()).isEqualTo("AuditStorageFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Audit storage operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify AUDIT_PROCESSING_FAILED error code properties")
    void shouldVerifyAuditProcessingFailedErrorCodeProperties() {
        AuditErrorCode errorCode = AuditErrorCode.AUDIT_PROCESSING_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0202");
        assertThat(errorCode.getDomainCode()).isEqualTo("02");
        assertThat(errorCode.getSubCode()).isEqualTo("02");
        assertThat(errorCode.getSystemCode()).isEqualTo("10");
        assertThat(errorCode.getErrorName()).isEqualTo("AuditProcessingFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Audit processing operation failed: {0}");
        assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should verify all error codes have correct domain code")
    void shouldVerifyAllErrorCodesHaveCorrectDomainCode() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getDomainCode()).isEqualTo("02");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getDomainCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Should verify all error codes have correct system code")
    void shouldVerifyAllErrorCodesHaveCorrectSystemCode() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Should verify domain code constant")
    void shouldVerifyDomainCodeConstant() {
        assertThat(AuditErrorCode.DOMAIN_CODE).isEqualTo("02");
    }

    @Test
    @DisplayName("Should verify unique sub codes")
    void shouldVerifyUniqueSubCodes() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getSubCode()).isEqualTo("01");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Should verify error code format consistency")
    void shouldVerifyErrorCodeFormatConsistency() {
        for (AuditErrorCode errorCode : AuditErrorCode.values()) {
            assertThat(errorCode.getErrorCode()).matches("OPEN_AGENT_AUTH_10_02\\d{2}");
            assertThat(errorCode.getErrorCode()).hasSize(23);
        }
    }

    @Test
    @DisplayName("Should verify all error codes have HTTP status 500")
    void shouldVerifyAllErrorCodesHaveHttpStatus500() {
        for (AuditErrorCode errorCode : AuditErrorCode.values()) {
            assertThat(errorCode.getHttpStatus().value()).isEqualTo(500);
        }
    }
}