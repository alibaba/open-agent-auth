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
 * Test class for Audit exceptions.
 * <p>
 * This test class validates the error codes and message formatting
 * for AuditStorageException and AuditProcessingException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Audit Exception Test")
class AuditExceptionTest {

    @Test
    @DisplayName("Test AuditStorageException with single parameter")
    void testAuditStorageExceptionWithSingleParameter() {
        AuditStorageException exception = new AuditStorageException("Database connection failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Audit storage operation failed: Database connection failed");
        assertThat(exception.getErrorParams()).containsExactly("Database connection failed");
    }

    @Test
    @DisplayName("Test AuditStorageException with message and cause")
    void testAuditStorageExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Connection timeout");
        AuditStorageException exception = new AuditStorageException("Database connection failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Audit storage operation failed: Database connection failed");
        assertThat(exception.getErrorParams()).containsExactly("Database connection failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test AuditStorageException error code properties")
    void testAuditStorageExceptionErrorCodeProperties() {
        AuditStorageException exception = new AuditStorageException("Test message");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(exception.toString()).contains("AuditStorageException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0201'");
    }

    @Test
    @DisplayName("Test AuditProcessingException with single parameter")
    void testAuditProcessingExceptionWithSingleParameter() {
        AuditProcessingException exception = new AuditProcessingException("Invalid event format");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0202");
        assertThat(exception.getFormattedMessage()).isEqualTo("Audit processing operation failed: Invalid event format");
        assertThat(exception.getErrorParams()).containsExactly("Invalid event format");
    }

    @Test
    @DisplayName("Test AuditProcessingException with message and cause")
    void testAuditProcessingExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Enrichment service unavailable");
        AuditProcessingException exception = new AuditProcessingException("Invalid event format", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0202");
        assertThat(exception.getFormattedMessage()).isEqualTo("Audit processing operation failed: Invalid event format");
        assertThat(exception.getErrorParams()).containsExactly("Invalid event format");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test AuditProcessingException error code properties")
    void testAuditProcessingExceptionErrorCodeProperties() {
        AuditProcessingException exception = new AuditProcessingException("Test message");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0202");
        assertThat(exception.toString()).contains("AuditProcessingException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0202'");
    }

    @Test
    @DisplayName("Test AuditErrorCode error code format")
    void testAuditErrorCodeFormat() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0202");
    }

    @Test
    @DisplayName("Test AuditErrorCode domain code")
    void testAuditErrorCodeDomainCode() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getDomainCode()).isEqualTo("02");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getDomainCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Test AuditErrorCode sub code")
    void testAuditErrorCodeSubCode() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getSubCode()).isEqualTo("01");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Test AuditErrorCode system code")
    void testAuditErrorCodeSystemCode() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test AuditErrorCode error names")
    void testAuditErrorCodeErrorNames() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getErrorName()).isEqualTo("AuditStorageFailed");
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getErrorName()).isEqualTo("AuditProcessingFailed");
    }

    @Test
    @DisplayName("Test AuditErrorCode HTTP status")
    void testAuditErrorCodeHttpStatus() {
        assertThat(AuditErrorCode.AUDIT_STORAGE_FAILED.getHttpStatus().value()).isEqualTo(500);
        assertThat(AuditErrorCode.AUDIT_PROCESSING_FAILED.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Test AuditErrorCode domain code constant")
    void testAuditErrorCodeDomainCodeConstant() {
        assertThat(AuditErrorCode.DOMAIN_CODE).isEqualTo("02");
    }
}
