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
package com.alibaba.openagentauth.core.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for exception base classes and error code functionality.
 * <p>
 * This test class validates the core functionality of the exception hierarchy,
 * including message formatting, error code handling, and parameter passing.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Exception Base Classes Test")
class ExceptionBaseTest {

    /**
     * Test error code implementation for Core module.
     */
    private enum TestCoreErrorCode implements CoreErrorCode {
        TEST_AUTH_FAILED("0001", "TEST_AUTH_FAILED", 
                        "Authentication failed for user {0}", HttpStatus.UNAUTHORIZED),
        TEST_TOKEN_EXPIRED("0001", "TEST_TOKEN_EXPIRED", 
                          "Token expired at {0}", HttpStatus.UNAUTHORIZED),
        TEST_VALIDATION_ERROR("0001", "TEST_VALIDATION_ERROR", 
                             "Validation failed: {0} - {1}", HttpStatus.BAD_REQUEST);

        private final String subCode;
        private final String errorName;
        private final String messageTemplate;
        private final HttpStatus httpStatus;

        TestCoreErrorCode(String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
            this.subCode = subCode;
            this.errorName = errorName;
            this.messageTemplate = messageTemplate;
            this.httpStatus = httpStatus;
        }

        @Override
        public String getDomainCode() {
            return "01";
        }

        @Override
        public String getSystemCode() {
            return "10";
        }

        @Override
        public String getSubCode() {
            return subCode;
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
     * Test error code implementation for Framework module.
     */
    private enum TestFrameworkErrorCode implements ErrorCode {
        TEST_AGENT_ERROR("10", "01", "0001", "TEST_AGENT_ERROR", 
                        "Agent operation failed: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
        TEST_AUTHORIZATION_ERROR("11", "02", "0001", "TEST_AUTHORIZATION_ERROR", 
                                "Authorization denied for resource {0}", HttpStatus.FORBIDDEN),
        TEST_TOKEN_ERROR("11", "03", "0001", "TEST_TOKEN_ERROR", 
                        "Token generation failed: {0}", HttpStatus.BAD_REQUEST);

        private final String systemCode;
        private final String domainCode;
        private final String subCode;
        private final String errorName;
        private final String messageTemplate;
        private final HttpStatus httpStatus;

        TestFrameworkErrorCode(String systemCode, String domainCode, String subCode, String errorName, String messageTemplate, HttpStatus httpStatus) {
            this.systemCode = systemCode;
            this.domainCode = domainCode;
            this.subCode = subCode;
            this.errorName = errorName;
            this.messageTemplate = messageTemplate;
            this.httpStatus = httpStatus;
        }

        @Override
        public String getSystemCode() {
            return systemCode;
        }

        @Override
        public String getDomainCode() {
            return domainCode;
        }

        @Override
        public String getSubCode() {
            return subCode;
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
     * Test Core exception implementation.
     */
    private static class TestCoreException extends CoreException {
        public TestCoreException(ErrorCode errorCode) {
            super(errorCode);
        }

        public TestCoreException(ErrorCode errorCode, Object... errorParams) {
            super(errorCode, errorParams);
        }

        public TestCoreException(ErrorCode errorCode, List<Object> errorParams, Map<String, Object> context) {
            super(errorCode, errorParams, context);
        }

        public TestCoreException(ErrorCode errorCode, Throwable cause) {
            super(errorCode, cause);
        }

        public TestCoreException(ErrorCode errorCode, Throwable cause, Object... errorParams) {
            super(errorCode, cause, errorParams);
        }

        public TestCoreException(ErrorCode errorCode, List<Object> errorParams, 
                               Map<String, Object> context, Throwable cause) {
            super(errorCode, errorParams, context, cause);
        }
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with single parameter")
    void testFormatMessageWithSingleParameter() {
        String message = TestCoreErrorCode.TEST_AUTH_FAILED.formatMessage("john.doe");
        assertThat(message).isEqualTo("Authentication failed for user john.doe");
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with multiple parameters")
    void testFormatMessageWithMultipleParameters() {
        String message = TestCoreErrorCode.TEST_VALIDATION_ERROR.formatMessage("username", "cannot be empty");
        assertThat(message).isEqualTo("Validation failed: username - cannot be empty");
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with no parameters")
    void testFormatMessageWithNoParameters() {
        String template = "No parameters needed";
        ErrorCode errorCode = new ErrorCode() {
            @Override
            public String getSystemCode() {
                return "99";
            }

            @Override
            public String getDomainCode() {
                return "99";
            }

            @Override
            public String getSubCode() {
                return "0001";
            }

            @Override
            public String getErrorName() {
                return "TEST_ERROR";
            }

            @Override
            public String getMessageTemplate() {
                return template;
            }

            @Override
            public HttpStatus getHttpStatus() {
                return HttpStatus.BAD_REQUEST;
            }
        };
        String message = errorCode.formatMessage();
        assertThat(message).isEqualTo(template);
    }

    @Test
    @DisplayName("Test ErrorCode formatMessage with null parameter")
    void testFormatMessageWithNullParameter() {
        String message = TestCoreErrorCode.TEST_AUTH_FAILED.formatMessage((Object)null);
        assertThat(message).isEqualTo("Authentication failed for user null");
    }

    @Test
    @DisplayName("Test CoreException with error code only")
    void testCoreExceptionWithErrorCodeOnly() {
        TestCoreException exception = new TestCoreException(TestCoreErrorCode.TEST_AUTH_FAILED);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed for user {0}");
        assertThat(exception.getErrorParams()).isNull();
    }

    @Test
    @DisplayName("Test CoreException with varargs parameters")
    void testCoreExceptionWithVarargsParameters() {
        TestCoreException exception = new TestCoreException(TestCoreErrorCode.TEST_AUTH_FAILED, "john.doe");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed for user john.doe");
        assertThat(exception.getErrorParams()).containsExactly("john.doe");
    }

    @Test
    @DisplayName("Test CoreException with multiple varargs parameters")
    void testCoreExceptionWithMultipleVarargsParameters() {
        TestCoreException exception = new TestCoreException(
            TestCoreErrorCode.TEST_VALIDATION_ERROR, "username", "cannot be empty");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(exception.getFormattedMessage()).isEqualTo("Validation failed: username - cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("username", "cannot be empty");
    }

    @Test
    @DisplayName("Test CoreException with error params list and context")
    void testCoreExceptionWithErrorParamsListAndContext() {
        List<Object> errorParams = Arrays.asList("john.doe");
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "12345");
        context.put("ipAddress", "192.168.1.1");

        TestCoreException exception = new TestCoreException(
            TestCoreErrorCode.TEST_AUTH_FAILED, errorParams, context);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed for user john.doe");
        assertThat(exception.getErrorParams()).containsExactly("john.doe");
        assertThat(exception.getContext()).containsExactlyEntriesOf(context);
    }

    @Test
    @DisplayName("Test CoreException with cause")
    void testCoreExceptionWithCause() {
        Throwable cause = new RuntimeException("Root cause");
        TestCoreException exception = new TestCoreException(TestCoreErrorCode.TEST_AUTH_FAILED, cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
    }

    @Test
    @DisplayName("Test CoreException with cause and varargs parameters")
    void testCoreExceptionWithCauseAndVarargsParameters() {
        Throwable cause = new RuntimeException("Root cause");
        TestCoreException exception = new TestCoreException(
            TestCoreErrorCode.TEST_AUTH_FAILED, cause, "john.doe");
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed for user john.doe");
    }

    @Test
    @DisplayName("Test CoreException with all parameters")
    void testCoreExceptionWithAllParameters() {
        List<Object> errorParams = Arrays.asList("username", "cannot be empty");
        Map<String, Object> context = new HashMap<>();
        context.put("field", "username");
        Throwable cause = new RuntimeException("Validation failed");

        TestCoreException exception = new TestCoreException(
            TestCoreErrorCode.TEST_VALIDATION_ERROR, errorParams, context, cause);
        
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(exception.getFormattedMessage()).isEqualTo("Validation failed: username - cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("username", "cannot be empty");
        assertThat(exception.getContext()).containsExactlyEntriesOf(context);
    }

    @Test
    @DisplayName("Test FrameworkErrorCode properties")
    void testFrameworkErrorCodeProperties() {
        TestFrameworkErrorCode errorCode = TestFrameworkErrorCode.TEST_AGENT_ERROR;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(errorCode.getErrorName()).isEqualTo("TEST_AGENT_ERROR");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Agent operation failed: {0}");
        assertThat(errorCode.getHttpStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    @DisplayName("Test errorParams is unmodifiable")
    void testErrorParamsIsUnmodifiable() {
        TestCoreException exception = new TestCoreException(
            TestCoreErrorCode.TEST_AUTH_FAILED, "john.doe");
        
        List<Object> errorParams = exception.getErrorParams();
        assertThat(errorParams).isNotNull();
        
        // Attempting to modify should throw UnsupportedOperationException
        try {
            errorParams.add("another.param");
            // If we reach here, the list is modifiable (should not happen)
            assertThat(false).isTrue();
        } catch (UnsupportedOperationException e) {
            // Expected behavior
            assertThat(true).isTrue();
        }
    }

    @Test
    @DisplayName("Test CoreErrorCode system code constant")
    void testCoreErrorCodeSystemCode() {
        assertThat(CoreErrorCode.SYSTEM_CODE).isEqualTo("10");
    }

    @Test
    @DisplayName("Test error code properties")
    void testErrorCodeProperties() {
        TestCoreErrorCode errorCode = TestCoreErrorCode.TEST_AUTH_FAILED;
        
        assertThat(errorCode.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_010001");
        assertThat(errorCode.getErrorName()).isEqualTo("TEST_AUTH_FAILED");
        assertThat(errorCode.getMessageTemplate()).isEqualTo("Authentication failed for user {0}");
        assertThat(errorCode.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Test exception toString")
    void testExceptionToString() {
        TestCoreException exception = new TestCoreException(
            TestCoreErrorCode.TEST_AUTH_FAILED, "john.doe");
        
        String toString = exception.toString();
        assertThat(toString).contains("TestCoreException");
        assertThat(toString).contains("errorCode='OPEN_AGENT_AUTH_10_010001'");
        assertThat(toString).contains("formattedMessage='Authentication failed for user john.doe'");
    }

    @Test
    @DisplayName("Test HttpStatus enum")
    void testHttpStatusEnum() {
        assertThat(HttpStatus.OK.value()).isEqualTo(200);
        assertThat(HttpStatus.BAD_REQUEST.value()).isEqualTo(400);
        assertThat(HttpStatus.UNAUTHORIZED.value()).isEqualTo(401);
        assertThat(HttpStatus.FORBIDDEN.value()).isEqualTo(403);
        assertThat(HttpStatus.INTERNAL_SERVER_ERROR.value()).isEqualTo(500);
        
        assertThat(HttpStatus.OK.is2xxSuccessful()).isTrue();
        assertThat(HttpStatus.BAD_REQUEST.is4xxClientError()).isTrue();
        assertThat(HttpStatus.INTERNAL_SERVER_ERROR.is5xxServerError()).isTrue();
        assertThat(HttpStatus.OK.isError()).isFalse();
        assertThat(HttpStatus.BAD_REQUEST.isError()).isTrue();
    }

    @Test
    @DisplayName("Test HttpStatus valueOf")
    void testHttpStatusValueOf() {
        assertThat(HttpStatus.valueOf(200)).isEqualTo(HttpStatus.OK);
        assertThat(HttpStatus.valueOf(404)).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(HttpStatus.valueOf(500)).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
