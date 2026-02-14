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

import com.alibaba.openagentauth.core.exception.HttpStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for FrameworkErrorCode interface.
 * <p>
 * This test class validates the constants and default methods defined
 * in the FrameworkErrorCode interface, ensuring proper error code structure.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkErrorCode Test")
class FrameworkErrorCodeTest {

    /**
     * Test implementation of FrameworkErrorCode for testing.
     */
    private enum TestFrameworkErrorCode implements FrameworkErrorCode {
        TEST_AUTH_ERROR("01", "TestAuthError", "Auth error: {0}", HttpStatus.BAD_REQUEST),
        TEST_TOKEN_ERROR("02", "TestTokenError", "Token error: {0}", HttpStatus.INTERNAL_SERVER_ERROR),
        TEST_VALIDATION_ERROR("03", "TestValidationError", "Validation error: {0}", HttpStatus.BAD_REQUEST),
        TEST_OAUTH2_ERROR("04", "TestOAuth2Error", "OAuth2 error: {0}", HttpStatus.BAD_REQUEST);

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
            return "01";
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

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(FrameworkErrorCode.SYSTEM_CODE).isEqualTo("11");
    }

    @Test
    @DisplayName("Should have correct domain code for Auth")
    void shouldHaveCorrectDomainCodeForAuth() {
        assertThat(FrameworkErrorCode.DOMAIN_CODE_AUTH).isEqualTo("01");
    }

    @Test
    @DisplayName("Should have correct domain code for Token")
    void shouldHaveCorrectDomainCodeForToken() {
        assertThat(FrameworkErrorCode.DOMAIN_CODE_TOKEN).isEqualTo("02");
    }

    @Test
    @DisplayName("Should have correct domain code for Validation")
    void shouldHaveCorrectDomainCodeForValidation() {
        assertThat(FrameworkErrorCode.DOMAIN_CODE_VALIDATION).isEqualTo("03");
    }

    @Test
    @DisplayName("Should have correct domain code for OAuth2")
    void shouldHaveCorrectDomainCodeForOauth2() {
        assertThat(FrameworkErrorCode.DOMAIN_CODE_OAUTH2).isEqualTo("04");
    }

    @Test
    @DisplayName("Should return correct system code from default method")
    void shouldReturnCorrectSystemCodeFromDefaultMethod() {
        assertThat(TestFrameworkErrorCode.TEST_AUTH_ERROR.getSystemCode()).isEqualTo("11");
        assertThat(TestFrameworkErrorCode.TEST_TOKEN_ERROR.getSystemCode()).isEqualTo("11");
        assertThat(TestFrameworkErrorCode.TEST_VALIDATION_ERROR.getSystemCode()).isEqualTo("11");
        assertThat(TestFrameworkErrorCode.TEST_OAUTH2_ERROR.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should format message with single parameter")
    void shouldFormatMessageWithSingleParameter() {
        String formatted = TestFrameworkErrorCode.TEST_AUTH_ERROR.formatMessage("test");
        assertThat(formatted).isEqualTo("Auth error: test");
    }

    @Test
    @DisplayName("Should format message with multiple parameters")
    void shouldFormatMessageWithMultipleParameters() {
        String formatted = TestFrameworkErrorCode.TEST_AUTH_ERROR.formatMessage("param1", "param2");
        assertThat(formatted).isEqualTo("Auth error: param1");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String formatted = TestFrameworkErrorCode.TEST_AUTH_ERROR.formatMessage((Object[]) null);
        assertThat(formatted).isEqualTo("Auth error: {0}");
    }

    @Test
    @DisplayName("Should format message with empty parameters")
    void shouldFormatMessageWithEmptyParameters() {
        String formatted = TestFrameworkErrorCode.TEST_AUTH_ERROR.formatMessage();
        assertThat(formatted).isEqualTo("Auth error: {0}");
    }

    @Test
    @DisplayName("Should generate correct error code for Auth domain")
    void shouldGenerateCorrectErrorCodeForAuthDomain() {
        assertThat(TestFrameworkErrorCode.TEST_AUTH_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0101");
    }

    @Test
    @DisplayName("Should generate correct error code for Token domain")
    void shouldGenerateCorrectErrorCodeForTokenDomain() {
        assertThat(TestFrameworkErrorCode.TEST_TOKEN_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0102");
    }

    @Test
    @DisplayName("Should generate correct error code for Validation domain")
    void shouldGenerateCorrectErrorCodeForValidationDomain() {
        assertThat(TestFrameworkErrorCode.TEST_VALIDATION_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0103");
    }

    @Test
    @DisplayName("Should generate correct error code for OAuth2 domain")
    void shouldGenerateCorrectErrorCodeForOauth2Domain() {
        assertThat(TestFrameworkErrorCode.TEST_OAUTH2_ERROR.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0104");
    }

    @Test
    @DisplayName("Should return correct sub code")
    void shouldReturnCorrectSubCode() {
        assertThat(TestFrameworkErrorCode.TEST_AUTH_ERROR.getSubCode()).isEqualTo("01");
        assertThat(TestFrameworkErrorCode.TEST_TOKEN_ERROR.getSubCode()).isEqualTo("02");
        assertThat(TestFrameworkErrorCode.TEST_VALIDATION_ERROR.getSubCode()).isEqualTo("03");
        assertThat(TestFrameworkErrorCode.TEST_OAUTH2_ERROR.getSubCode()).isEqualTo("04");
    }

    @Test
    @DisplayName("Should return correct error name")
    void shouldReturnCorrectErrorName() {
        assertThat(TestFrameworkErrorCode.TEST_AUTH_ERROR.getErrorName()).isEqualTo("TestAuthError");
        assertThat(TestFrameworkErrorCode.TEST_TOKEN_ERROR.getErrorName()).isEqualTo("TestTokenError");
    }

    @Test
    @DisplayName("Should return correct message template")
    void shouldReturnCorrectMessageTemplate() {
        assertThat(TestFrameworkErrorCode.TEST_AUTH_ERROR.getMessageTemplate())
                .isEqualTo("Auth error: {0}");
    }

    @Test
    @DisplayName("Should verify domain codes are sequential")
    void shouldVerifyDomainCodesAreSequential() {
        assertThat(FrameworkErrorCode.DOMAIN_CODE_AUTH).isEqualTo("01");
        assertThat(FrameworkErrorCode.DOMAIN_CODE_TOKEN).isEqualTo("02");
        assertThat(FrameworkErrorCode.DOMAIN_CODE_VALIDATION).isEqualTo("03");
        assertThat(FrameworkErrorCode.DOMAIN_CODE_OAUTH2).isEqualTo("04");
    }
}
