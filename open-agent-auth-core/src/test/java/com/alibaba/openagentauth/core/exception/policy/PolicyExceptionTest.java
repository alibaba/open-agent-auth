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
package com.alibaba.openagentauth.core.exception.policy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Policy exceptions.
 * <p>
 * This test class validates the error codes, message formatting,
 * and policy-specific features for PolicyNotFoundException, PolicyEvaluationException,
 * PolicyValidationException, and PolicyRegistrationException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Policy Exception Test")
class PolicyExceptionTest {

    @Test
    @DisplayName("Test PolicyNotFoundException with single parameter")
    void testPolicyNotFoundExceptionWithSingleParameter() {
        PolicyNotFoundException exception = new PolicyNotFoundException("policy-123");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0501");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy not found: policy-123");
    }

    @Test
    @DisplayName("Test PolicyNotFoundException with message and cause")
    void testPolicyNotFoundExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Database query failed");
        PolicyNotFoundException exception = new PolicyNotFoundException("Policy not found: policy-123", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0501");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy not found: Policy not found: policy-123");
        assertThat(exception.getErrorParams()).containsExactly("Policy not found: policy-123");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test PolicyEvaluationException with single parameter")
    void testPolicyEvaluationExceptionWithSingleParameter() {
        PolicyEvaluationException exception = new PolicyEvaluationException("division by zero");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0502");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy evaluation failed: division by zero");
    }

    @Test
    @DisplayName("Test PolicyEvaluationException with message and cause")
    void testPolicyEvaluationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Runtime error");
        PolicyEvaluationException exception = new PolicyEvaluationException("Evaluation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0502");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy evaluation failed: Evaluation failed");
        assertThat(exception.getErrorParams()).containsExactly("Evaluation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test PolicyEvaluationException with input data")
    void testPolicyEvaluationExceptionWithInputData() {
        Object inputData = new Object();
        PolicyEvaluationException exception = new PolicyEvaluationException("Evaluation failed", new RuntimeException("Error"), inputData);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0502");
        assertThat(exception.getInputData()).isSameAs(inputData);
    }

    @Test
    @DisplayName("Test PolicyEvaluationException getInputData returns null when not provided")
    void testPolicyEvaluationExceptionGetInputDataReturnsNull() {
        PolicyEvaluationException exception = new PolicyEvaluationException("Evaluation failed");
        
        assertThat(exception.getInputData()).isNull();
    }

    @Test
    @DisplayName("Test PolicyValidationException with single parameter")
    void testPolicyValidationExceptionWithSingleParameter() {
        PolicyValidationException exception = new PolicyValidationException("Syntax error at line 10");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy validation failed: Syntax error at line 10");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.VALIDATION_ERROR);
    }

    @Test
    @DisplayName("Test PolicyValidationException with message and cause")
    void testPolicyValidationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Validation error");
        PolicyValidationException exception = new PolicyValidationException("Syntax error", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy validation failed: Syntax error");
        assertThat(exception.getErrorParams()).containsExactly("Syntax error");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test PolicyValidationException with error type")
    void testPolicyValidationExceptionWithErrorType() {
        PolicyValidationException exception = new PolicyValidationException(
                "Invalid syntax",
                PolicyValidationException.ValidationErrorType.SYNTAX_ERROR
        );
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.SYNTAX_ERROR);
    }

    @Test
    @DisplayName("Test PolicyValidationException with location information")
    void testPolicyValidationExceptionWithLocationInformation() {
        PolicyValidationException exception = new PolicyValidationException(
                "Syntax error",
                PolicyValidationException.ValidationErrorType.SYNTAX_ERROR,
                10,
                5
        );
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.SYNTAX_ERROR);
        assertThat(exception.getLineNumber()).isEqualTo(10);
        assertThat(exception.getColumnNumber()).isEqualTo(5);
    }

    @Test
    @DisplayName("Test PolicyValidationException static factory method - syntaxError")
    void testPolicyValidationExceptionSyntaxError() {
        PolicyValidationException exception = PolicyValidationException.syntaxError("Missing closing brace", 15);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.SYNTAX_ERROR);
        assertThat(exception.getLineNumber()).isEqualTo(15);
        assertThat(exception.getColumnNumber()).isNull();
    }

    @Test
    @DisplayName("Test PolicyValidationException static factory method - semanticError")
    void testPolicyValidationExceptionSemanticError() {
        PolicyValidationException exception = PolicyValidationException.semanticError("Undefined variable");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.SEMANTIC_ERROR);
    }

    @Test
    @DisplayName("Test PolicyValidationException static factory method - securityViolation")
    void testPolicyValidationExceptionSecurityViolation() {
        PolicyValidationException exception = PolicyValidationException.securityViolation("Access to forbidden resource");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.SECURITY_VIOLATION);
    }

    @Test
    @DisplayName("Test PolicyValidationException static factory method - missingRequiredField")
    void testPolicyValidationExceptionMissingRequiredField() {
        PolicyValidationException exception = PolicyValidationException.missingRequiredField("policy_id");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(exception.getErrorType()).isEqualTo(PolicyValidationException.ValidationErrorType.MISSING_REQUIRED_FIELD);
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy validation failed: Missing required field: policy_id");
    }

    @Test
    @DisplayName("Test PolicyRegistrationException with single parameter")
    void testPolicyRegistrationExceptionWithSingleParameter() {
        PolicyRegistrationException exception = new PolicyRegistrationException("Registration failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy registration failed: Registration failed");
        assertThat(exception.getErrorType()).isEqualTo(PolicyRegistrationException.RegistrationErrorType.REGISTRATION_ERROR);
    }

    @Test
    @DisplayName("Test PolicyRegistrationException with message and cause")
    void testPolicyRegistrationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Storage error");
        PolicyRegistrationException exception = new PolicyRegistrationException("Registration failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy registration failed: Registration failed");
        assertThat(exception.getErrorParams()).containsExactly("Registration failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test PolicyRegistrationException with error type")
    void testPolicyRegistrationExceptionWithErrorType() {
        PolicyRegistrationException exception = new PolicyRegistrationException(
                "Duplicate policy",
                PolicyRegistrationException.RegistrationErrorType.DUPLICATE_POLICY
        );
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
        assertThat(exception.getErrorType()).isEqualTo(PolicyRegistrationException.RegistrationErrorType.DUPLICATE_POLICY);
    }

    @Test
    @DisplayName("Test PolicyRegistrationException static factory method - validationFailed")
    void testPolicyRegistrationExceptionValidationFailed() {
        PolicyRegistrationException exception = PolicyRegistrationException.validationFailed("Invalid policy syntax");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
        assertThat(exception.getErrorType()).isEqualTo(PolicyRegistrationException.RegistrationErrorType.VALIDATION_FAILED);
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy registration failed: Policy validation failed: Invalid policy syntax");
    }

    @Test
    @DisplayName("Test PolicyRegistrationException static factory method - duplicatePolicy")
    void testPolicyRegistrationExceptionDuplicatePolicy() {
        PolicyRegistrationException exception = PolicyRegistrationException.duplicatePolicy("policy-123");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
        assertThat(exception.getErrorType()).isEqualTo(PolicyRegistrationException.RegistrationErrorType.DUPLICATE_POLICY);
        assertThat(exception.getFormattedMessage()).isEqualTo("Policy registration failed: Policy already exists: policy-123");
    }

    @Test
    @DisplayName("Test PolicyRegistrationException static factory method - storageError")
    void testPolicyRegistrationExceptionStorageError() {
        Throwable cause = new RuntimeException("Database connection failed");
        PolicyRegistrationException exception = PolicyRegistrationException.storageError("Unable to save policy", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
        assertThat(exception.getErrorType()).isEqualTo(PolicyRegistrationException.RegistrationErrorType.STORAGE_ERROR);
        assertThat(exception.getFormattedMessage()).contains("Storage error");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test PolicyErrorCode error code format")
    void testPolicyErrorCodeFormat() {
        assertThat(PolicyErrorCode.POLICY_NOT_FOUND.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0501");
        assertThat(PolicyErrorCode.POLICY_EVALUATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0502");
        assertThat(PolicyErrorCode.POLICY_VALIDATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0503");
        assertThat(PolicyErrorCode.POLICY_REGISTRATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0504");
    }

    @Test
    @DisplayName("Test PolicyErrorCode domain code")
    void testPolicyErrorCodeDomainCode() {
        assertThat(PolicyErrorCode.POLICY_NOT_FOUND.getDomainCode()).isEqualTo("05");
        assertThat(PolicyErrorCode.POLICY_EVALUATION_FAILED.getDomainCode()).isEqualTo("05");
        assertThat(PolicyErrorCode.POLICY_VALIDATION_FAILED.getDomainCode()).isEqualTo("05");
        assertThat(PolicyErrorCode.POLICY_REGISTRATION_FAILED.getDomainCode()).isEqualTo("05");
    }

    @Test
    @DisplayName("Test PolicyErrorCode sub code")
    void testPolicyErrorCodeSubCode() {
        assertThat(PolicyErrorCode.POLICY_NOT_FOUND.getSubCode()).isEqualTo("01");
        assertThat(PolicyErrorCode.POLICY_EVALUATION_FAILED.getSubCode()).isEqualTo("02");
        assertThat(PolicyErrorCode.POLICY_VALIDATION_FAILED.getSubCode()).isEqualTo("03");
        assertThat(PolicyErrorCode.POLICY_REGISTRATION_FAILED.getSubCode()).isEqualTo("04");
    }

    @Test
    @DisplayName("Test PolicyErrorCode system code")
    void testPolicyErrorCodeSystemCode() {
        assertThat(PolicyErrorCode.POLICY_NOT_FOUND.getSystemCode()).isEqualTo("10");
        assertThat(PolicyErrorCode.POLICY_EVALUATION_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(PolicyErrorCode.POLICY_VALIDATION_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(PolicyErrorCode.POLICY_REGISTRATION_FAILED.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test PolicyErrorCode error names")
    void testPolicyErrorCodeErrorNames() {
        assertThat(PolicyErrorCode.POLICY_NOT_FOUND.getErrorName()).isEqualTo("PolicyNotFound");
        assertThat(PolicyErrorCode.POLICY_EVALUATION_FAILED.getErrorName()).isEqualTo("PolicyEvaluationFailed");
        assertThat(PolicyErrorCode.POLICY_VALIDATION_FAILED.getErrorName()).isEqualTo("PolicyValidationFailed");
        assertThat(PolicyErrorCode.POLICY_REGISTRATION_FAILED.getErrorName()).isEqualTo("PolicyRegistrationFailed");
    }

    @Test
    @DisplayName("Test PolicyErrorCode HTTP status")
    void testPolicyErrorCodeHttpStatus() {
        assertThat(PolicyErrorCode.POLICY_NOT_FOUND.getHttpStatus().value()).isEqualTo(404);
        assertThat(PolicyErrorCode.POLICY_EVALUATION_FAILED.getHttpStatus().value()).isEqualTo(500);
        assertThat(PolicyErrorCode.POLICY_VALIDATION_FAILED.getHttpStatus().value()).isEqualTo(400);
        assertThat(PolicyErrorCode.POLICY_REGISTRATION_FAILED.getHttpStatus().value()).isEqualTo(400);
    }

    @Test
    @DisplayName("Test PolicyErrorCode domain code constant")
    void testPolicyErrorCodeDomainCodeConstant() {
        assertThat(PolicyErrorCode.DOMAIN_CODE).isEqualTo("05");
    }

    @Test
    @DisplayName("Test PolicyValidationException ValidationErrorType enum values")
    void testPolicyValidationExceptionValidationErrorTypeEnum() {
        assertThat(PolicyValidationException.ValidationErrorType.values()).hasSize(7);
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("SYNTAX_ERROR")).isNotNull();
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("SEMANTIC_ERROR")).isNotNull();
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("SECURITY_VIOLATION")).isNotNull();
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("MISSING_REQUIRED_FIELD")).isNotNull();
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("COMPLEXITY_VIOLATION")).isNotNull();
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("UNSUPPORTED_FEATURE")).isNotNull();
        assertThat(PolicyValidationException.ValidationErrorType.valueOf("VALIDATION_ERROR")).isNotNull();
    }

    @Test
    @DisplayName("Test PolicyRegistrationException RegistrationErrorType enum values")
    void testPolicyRegistrationExceptionRegistrationErrorTypeEnum() {
        assertThat(PolicyRegistrationException.RegistrationErrorType.values()).hasSize(6);
        assertThat(PolicyRegistrationException.RegistrationErrorType.valueOf("VALIDATION_FAILED")).isNotNull();
        assertThat(PolicyRegistrationException.RegistrationErrorType.valueOf("DUPLICATE_POLICY")).isNotNull();
        assertThat(PolicyRegistrationException.RegistrationErrorType.valueOf("STORAGE_ERROR")).isNotNull();
        assertThat(PolicyRegistrationException.RegistrationErrorType.valueOf("QUOTA_EXCEEDED")).isNotNull();
        assertThat(PolicyRegistrationException.RegistrationErrorType.valueOf("PERMISSION_DENIED")).isNotNull();
        assertThat(PolicyRegistrationException.RegistrationErrorType.valueOf("REGISTRATION_ERROR")).isNotNull();
    }
}
