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

package com.alibaba.openagentauth.core.exception.workload;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Workload exceptions.
 * <p>
 * This test class validates the error codes and message formatting
 * for VcVerificationException, WorkloadCreationException, and WorkloadNotFoundException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Workload Exception Test")
class WorkloadExceptionTest {

    @Test
    @DisplayName("Test VcVerificationException with single parameter")
    void testVcVerificationExceptionWithSingleParameter() {
        VcVerificationException exception = new VcVerificationException("Invalid signature");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0601");
        assertThat(exception.getFormattedMessage()).isEqualTo("VC verification failed: Invalid signature (Code: null)");
        assertThat(exception.getErrorParams()).containsExactly("Invalid signature", null);
    }

    @Test
    @DisplayName("Test VcVerificationException with message and code")
    void testVcVerificationExceptionWithMessageAndCode() {
        VcVerificationException exception = new VcVerificationException("Issuer mismatch", "VC-INVALID-ISSUER");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0601");
        assertThat(exception.getVcErrorCode()).isEqualTo("VC-INVALID-ISSUER");
        assertThat(exception.getFormattedMessage()).isEqualTo("VC verification failed: Issuer mismatch (Code: VC-INVALID-ISSUER)");
        assertThat(exception.getErrorParams()).containsExactly("Issuer mismatch", "VC-INVALID-ISSUER");
    }

    @Test
    @DisplayName("Test VcVerificationException with message and cause")
    void testVcVerificationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Verification failed");
        VcVerificationException exception = new VcVerificationException("Invalid signature", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0601");
        assertThat(exception.getVcErrorCode()).isNull();
        assertThat(exception.getFormattedMessage()).isEqualTo("VC verification failed: Invalid signature (Code: null)");
        assertThat(exception.getErrorParams()).containsExactly("Invalid signature", null);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test VcVerificationException with message, code and cause")
    void testVcVerificationExceptionWithMessageCodeAndCause() {
        Throwable cause = new RuntimeException("Verification failed");
        VcVerificationException exception = new VcVerificationException("Signature verification failed", "VC-INVALID-SIGNATURE", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0601");
        assertThat(exception.getVcErrorCode()).isEqualTo("VC-INVALID-SIGNATURE");
        assertThat(exception.getFormattedMessage()).isEqualTo("VC verification failed: Signature verification failed (Code: VC-INVALID-SIGNATURE)");
        assertThat(exception.getErrorParams()).containsExactly("Signature verification failed", "VC-INVALID-SIGNATURE");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test WorkloadCreationException with single parameter")
    void testWorkloadCreationExceptionWithSingleParameter() {
        WorkloadCreationException exception = new WorkloadCreationException("Key generation failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0602");
        assertThat(exception.getFormattedMessage()).isEqualTo("Workload creation failed: Key generation failed");
        assertThat(exception.getErrorParams()).containsExactly("Key generation failed");
    }

    @Test
    @DisplayName("Test WorkloadCreationException with message and cause")
    void testWorkloadCreationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Resource allocation failed");
        WorkloadCreationException exception = new WorkloadCreationException("Key generation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0602");
        assertThat(exception.getFormattedMessage()).isEqualTo("Workload creation failed: Key generation failed");
        assertThat(exception.getErrorParams()).containsExactly("Key generation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test WorkloadNotFoundException with single parameter")
    void testWorkloadNotFoundExceptionWithSingleParameter() {
        WorkloadNotFoundException exception = new WorkloadNotFoundException("Workload not found: workload-123");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0603");
        assertThat(exception.getFormattedMessage()).isEqualTo("Workload not found: Workload not found: workload-123");
        assertThat(exception.getErrorParams()).containsExactly("Workload not found: workload-123");
    }

    @Test
    @DisplayName("Test WorkloadErrorCode error code format")
    void testWorkloadErrorCodeFormat() {
        assertThat(WorkloadErrorCode.VC_VERIFICATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0601");
        assertThat(WorkloadErrorCode.WORKLOAD_CREATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0602");
        assertThat(WorkloadErrorCode.WORKLOAD_NOT_FOUND.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0603");
    }

    @Test
    @DisplayName("Test WorkloadErrorCode domain code")
    void testWorkloadErrorCodeDomainCode() {
        assertThat(WorkloadErrorCode.VC_VERIFICATION_FAILED.getDomainCode()).isEqualTo("06");
        assertThat(WorkloadErrorCode.WORKLOAD_CREATION_FAILED.getDomainCode()).isEqualTo("06");
        assertThat(WorkloadErrorCode.WORKLOAD_NOT_FOUND.getDomainCode()).isEqualTo("06");
    }

    @Test
    @DisplayName("Test WorkloadErrorCode sub code")
    void testWorkloadErrorCodeSubCode() {
        assertThat(WorkloadErrorCode.VC_VERIFICATION_FAILED.getSubCode()).isEqualTo("01");
        assertThat(WorkloadErrorCode.WORKLOAD_CREATION_FAILED.getSubCode()).isEqualTo("02");
        assertThat(WorkloadErrorCode.WORKLOAD_NOT_FOUND.getSubCode()).isEqualTo("03");
    }

    @Test
    @DisplayName("Test WorkloadErrorCode system code")
    void testWorkloadErrorCodeSystemCode() {
        assertThat(WorkloadErrorCode.VC_VERIFICATION_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(WorkloadErrorCode.WORKLOAD_CREATION_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(WorkloadErrorCode.WORKLOAD_NOT_FOUND.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test WorkloadErrorCode error names")
    void testWorkloadErrorCodeErrorNames() {
        assertThat(WorkloadErrorCode.VC_VERIFICATION_FAILED.getErrorName()).isEqualTo("VcVerificationFailed");
        assertThat(WorkloadErrorCode.WORKLOAD_CREATION_FAILED.getErrorName()).isEqualTo("WorkloadCreationFailed");
        assertThat(WorkloadErrorCode.WORKLOAD_NOT_FOUND.getErrorName()).isEqualTo("WorkloadNotFound");
    }

    @Test
    @DisplayName("Test WorkloadErrorCode HTTP status")
    void testWorkloadErrorCodeHttpStatus() {
        assertThat(WorkloadErrorCode.VC_VERIFICATION_FAILED.getHttpStatus().value()).isEqualTo(400);
        assertThat(WorkloadErrorCode.WORKLOAD_CREATION_FAILED.getHttpStatus().value()).isEqualTo(500);
        assertThat(WorkloadErrorCode.WORKLOAD_NOT_FOUND.getHttpStatus().value()).isEqualTo(404);
    }

    @Test
    @DisplayName("Test WorkloadErrorCode domain code constant")
    void testWorkloadErrorCodeDomainCodeConstant() {
        assertThat(WorkloadErrorCode.DOMAIN_CODE).isEqualTo("06");
    }

    @Test
    @DisplayName("Test VcVerificationException getVcErrorCode returns null when not provided")
    void testVcVerificationExceptionGetVcErrorCodeReturnsNull() {
        VcVerificationException exception = new VcVerificationException("Invalid signature");
        
        assertThat(exception.getVcErrorCode()).isNull();
    }

    @Test
    @DisplayName("Test VcVerificationException getVcErrorCode returns value when provided")
    void testVcVerificationExceptionGetVcErrorCodeReturnsValue() {
        VcVerificationException exception = new VcVerificationException("Invalid signature", "VC-INVALID-SIGNATURE");
        
        assertThat(exception.getVcErrorCode()).isEqualTo("VC-INVALID-SIGNATURE");
    }
}
