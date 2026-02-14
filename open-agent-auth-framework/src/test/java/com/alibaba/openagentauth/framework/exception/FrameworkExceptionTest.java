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
package com.alibaba.openagentauth.framework.exception;

import com.alibaba.openagentauth.core.exception.ErrorCode;
import com.alibaba.openagentauth.core.exception.HttpStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Framework exception base classes and error code functionality.
 * <p>
 * This test class validates the core functionality of the Framework exception hierarchy,
 * including message formatting, error code handling, and parameter passing.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Framework Exception Base Classes Test")
class FrameworkExceptionTest {

    /**
     * Test error code implementation for Framework module.
     */
    private enum TestFrameworkErrorCode implements FrameworkErrorCode {
        TEST_AUTH_FAILED("01", "TestAuthFailed", 
                        "Framework authentication failed: {0}", HttpStatus.UNAUTHORIZED),
        TEST_TOKEN_ERROR("02", "TestTokenError", 
                        "Framework token generation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
        TEST_VALIDATION_ERROR("03", "TestValidationError", 
                             "Framework validation failed: {0} - {1}", HttpStatus.BAD_REQUEST),
        TEST_OAUTH2_ERROR("04", "TestOAuth2Error", 
                         "Framework OAuth2 processing failed: {0}", HttpStatus.BAD_REQUEST);

        private final String subCode;
        private final String errorName;
        private final String messageTemplate;
        private final HttpStatus httpStatus;

        TestFrameworkErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
            this.subCode = subCode;
            this.errorName = errorName;
            this.messageTemplate = messageTemplate;
            this.httpStatus = httpStatus;
        }

        @Override
        public String getDomainCode() {
            return subCode;
        }

        @Override
        public String getSubCode() {
            return "01";
        }

        @Override
        public String getErrorName() {
            return errorName;
        }

        @Override
        public String getMessageTemplate() {
            return messageTemplate;
        }

        @Override
        public HttpStatus getHttpStatus() {
            return httpStatus;
        }
    }

    /**
     * Test Framework exception implementation.
     */
    private static class TestFrameworkException extends FrameworkException {
        public TestFrameworkException(ErrorCode errorCode) {
            super(errorCode);
        }

        public TestFrameworkException(ErrorCode errorCode, Object... errorParams) {
            super(errorCode, errorParams);
        }

        public TestFrameworkException(ErrorCode errorCode, List<Object> errorParams, Map<String, Object> context) {
            super(errorCode, errorParams, context);
        }

        public TestFrameworkException(ErrorCode errorCode, Throwable cause) {
            super(errorCode, cause);
        }

        public TestFrameworkException(ErrorCode errorCode, Throwable cause, Object... errorParams) {
            super(errorCode, cause, errorParams);
        }

        public TestFrameworkException(ErrorCode errorCode, List<Object> errorParams, 
                                     Map<String, Object> context, Throwable cause) {
            super(errorCode, errorParams, context, cause);
        }
    }

    @Test
    @DisplayName("Test FrameworkErrorCode system code constant")
    void testFrameworkErrorCodeSystemCode() {
        assertThat(FrameworkErrorCode.SYSTEM_CODE).isEqualTo("11");
    }

    @Test
    @DisplayName("Test FrameworkErrorCode domain codes")
    void testFrameworkErrorCodeDomainCodes() {
        assertThat(FrameworkErrorCode.DOMAIN_CODE_AUTH).isEqualTo("01");
        assertThat(FrameworkErrorCode.DOMAIN_CODE_TOKEN).isEqualTo("02");
        assertThat(FrameworkErrorCode.DOMAIN_CODE_VALIDATION).isEqualTo("03");
        assertThat(FrameworkErrorCode.DOMAIN_CODE_OAUTH2).isEqualTo("04");
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with single parameter")
    void testFormatMessageWithSingleParameter() {
        String message = TestFrameworkErrorCode.TEST_AUTH_FAILED.formatMessage("john.doe");
        assertThat(message).isEqualTo("Framework authentication failed: john.doe");
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with multiple parameters")
    void testFormatMessageWithMultipleParameters() {
        String message = TestFrameworkErrorCode.TEST_VALIDATION_ERROR.formatMessage("username", "cannot be empty");
        assertThat(message).isEqualTo("Framework validation failed: username - cannot be empty");
    }

    @Test
    @DisplayName("Test FrameworkException with error code only")
    void testFrameworkExceptionWithErrorCodeOnly() {
        TestFrameworkException exception = new TestFrameworkException(TestFrameworkErrorCode.TEST_AUTH_FAILED);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: {0}");
        assertThat(exception.getErrorParams()).isNull();
    }

    @Test
    @DisplayName("Test FrameworkException with varargs parameters")
    void testFrameworkExceptionWithVarargsParameters() {
        TestFrameworkException exception = new TestFrameworkException(TestFrameworkErrorCode.TEST_AUTH_FAILED, "john.doe");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: john.doe");
        assertThat(exception.getErrorParams()).containsExactly("john.doe");
    }

    @Test
    @DisplayName("Test FrameworkException with multiple varargs parameters")
    void testFrameworkExceptionWithMultipleVarargsParameters() {
        TestFrameworkException exception = new TestFrameworkException(
            TestFrameworkErrorCode.TEST_VALIDATION_ERROR, "username", "cannot be empty");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: username - cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("username", "cannot be empty");
    }

    @Test
    @DisplayName("Test FrameworkException with error params list and context")
    void testFrameworkExceptionWithErrorParamsListAndContext() {
        List<Object> errorParams = Arrays.asList("john.doe");
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "12345");
        context.put("ipAddress", "192.168.1.1");

        TestFrameworkException exception = new TestFrameworkException(
            TestFrameworkErrorCode.TEST_AUTH_FAILED, errorParams, context);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: john.doe");
        assertThat(exception.getErrorParams()).containsExactly("john.doe");
        assertThat(exception.getContext()).containsExactlyEntriesOf(context);
    }

    @Test
    @DisplayName("Test FrameworkException with cause")
    void testFrameworkExceptionWithCause() {
        Throwable cause = new RuntimeException("Root cause");
        TestFrameworkException exception = new TestFrameworkException(TestFrameworkErrorCode.TEST_AUTH_FAILED, cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
    }

    @Test
    @DisplayName("Test FrameworkException with cause and varargs parameters")
    void testFrameworkExceptionWithCauseAndVarargsParameters() {
        Throwable cause = new RuntimeException("Root cause");
        TestFrameworkException exception = new TestFrameworkException(
            TestFrameworkErrorCode.TEST_AUTH_FAILED, cause, "john.doe");
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: john.doe");
    }

    @Test
    @DisplayName("Test FrameworkException with all parameters")
    void testFrameworkExceptionWithAllParameters() {
        List<Object> errorParams = Arrays.asList("username", "cannot be empty");
        Map<String, Object> context = new HashMap<>();
        context.put("field", "username");
        Throwable cause = new RuntimeException("Validation failed");

        TestFrameworkException exception = new TestFrameworkException(
            TestFrameworkErrorCode.TEST_VALIDATION_ERROR, errorParams, context, cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0301");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework validation failed: username - cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("username", "cannot be empty");
        assertThat(exception.getContext()).containsExactlyEntriesOf(context);
    }

    @Test
    @DisplayName("Test error code properties")
    void testErrorCodeProperties() {
        TestFrameworkErrorCode errorCode = TestFrameworkErrorCode.TEST_AUTH_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(errorCode.getErrorName()).isEqualTo("TestAuthFailed");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Framework authentication failed: {0}");
        assertThat(errorCode.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Test exception toString")
    void testExceptionToString() {
        TestFrameworkException exception = new TestFrameworkException(
            TestFrameworkErrorCode.TEST_AUTH_FAILED, "john.doe");
        
        String toString = exception.toString();
        assertThat(toString).contains("TestFrameworkException");
        assertThat(toString).contains("errorCode='OPEN_AGENT_AUTH_11_0101'");
        assertThat(toString).contains("formattedMessage='Framework authentication failed: john.doe'");
    }

    @Test
    @DisplayName("Test errorParams is unmodifiable")
    void testErrorParamsIsUnmodifiable() {
        TestFrameworkException exception = new TestFrameworkException(
            TestFrameworkErrorCode.TEST_AUTH_FAILED, "john.doe");
        
        List<Object> errorParams = exception.getErrorParams();
        assertThat(errorParams).isNotNull();
        
        // Attempting to modify should throw UnsupportedOperationException
        try {
            errorParams.add("another.param");
            assertThat(false).isTrue();
        } catch (UnsupportedOperationException e) {
            assertThat(true).isTrue();
        }
    }
}
