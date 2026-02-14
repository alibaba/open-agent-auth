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
 * Test class for AuditStorageException.
 * <p>
 * This test class validates the exception creation, message formatting,
 * and exception chaining for AuditStorageException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Audit Storage Exception Test")
class AuditStorageExceptionTest {

    @Test
    @DisplayName("Should create AuditStorageException with message")
    void shouldCreateAuditStorageExceptionWithMessage() {
        String message = "Database connection failed";
        AuditStorageException exception = new AuditStorageException(message);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Audit storage operation failed: Database connection failed");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create AuditStorageException with message and cause")
    void shouldCreateAuditStorageExceptionWithMessageAndCause() {
        String message = "Storage quota exceeded";
        Throwable cause = new RuntimeException("Disk full");
        AuditStorageException exception = new AuditStorageException(message, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Audit storage operation failed: Storage quota exceeded");
        assertThat(exception.getErrorParams()).containsExactly(message);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception details in toString")
    void shouldContainExceptionDetailsInToString() {
        AuditStorageException exception = new AuditStorageException("Test error");
        
        assertThat(exception.toString()).contains("AuditStorageException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0201'");
        assertThat(exception.toString()).contains("Audit storage operation failed: Test error");
    }

    @Test
    @DisplayName("Should preserve exception chain")
    void shouldPreserveExceptionChain() {
        Throwable rootCause = new RuntimeException("Network timeout");
        Throwable cause = new RuntimeException("Connection failed", rootCause);
        AuditStorageException exception = new AuditStorageException("Test error", cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getCause().getCause()).isEqualTo(rootCause);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        AuditStorageException exception = new AuditStorageException("Storage error");
        
        // Error code format: OPEN_AGENT_AUTH_10_02ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_02");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}