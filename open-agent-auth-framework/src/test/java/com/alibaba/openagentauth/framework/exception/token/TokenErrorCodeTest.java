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
package com.alibaba.openagentauth.framework.exception.token;

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for TokenErrorCode enum.
 * <p>
 * This test class validates the error code definitions for the Token domain,
 * ensuring proper error code structure, message templates, and HTTP status mapping.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("TokenErrorCode Test")
class TokenErrorCodeTest {

    @Test
    @DisplayName("Should have correct domain code")
    void shouldHaveCorrectDomainCode() {
        assertThat(TokenErrorCode.DOMAIN_CODE).isEqualTo("02");
    }

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getSystemCode()).isEqualTo("11");
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should generate correct error code for TOKEN_GENERATION_FAILED")
    void shouldGenerateCorrectErrorCodeForTokenGenerationFailed() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0201");
    }

    @Test
    @DisplayName("Should generate correct error code for TOKEN_VALIDATION_FAILED")
    void shouldGenerateCorrectErrorCodeForTokenValidationFailed() {
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0202");
    }

    @Test
    @DisplayName("Should have correct sub codes")
    void shouldHaveCorrectSubCodes() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getSubCode()).isEqualTo("01");
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Should have correct error names")
    void shouldHaveCorrectErrorNames() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getErrorName())
                .isEqualTo("FrameworkTokenGenerationFailed");
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getErrorName())
                .isEqualTo("FrameworkTokenValidationFailed");
    }

    @Test
    @DisplayName("Should have correct message templates")
    void shouldHaveCorrectMessageTemplates() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getMessageTemplate())
                .isEqualTo("Framework token generation failed: {0}");
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getMessageTemplate())
                .isEqualTo("Framework token validation failed: {0}");
    }

    @Test
    @DisplayName("Should have correct HTTP status codes")
    void shouldHaveCorrectHttpStatusCodes() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("Should format messages correctly")
    void shouldFormatMessagesCorrectly() {
        String generationMessage = TokenErrorCode.TOKEN_GENERATION_FAILED.formatMessage("Cryptographic error");
        assertThat(generationMessage).isEqualTo("Framework token generation failed: Cryptographic error");

        String validationMessage = TokenErrorCode.TOKEN_VALIDATION_FAILED.formatMessage("Expired token");
        assertThat(validationMessage).isEqualTo("Framework token validation failed: Expired token");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String message = TokenErrorCode.TOKEN_GENERATION_FAILED.formatMessage((Object[]) null);
        assertThat(message).isEqualTo("Framework token generation failed: {0}");
    }

    @Test
    @DisplayName("Should implement FrameworkErrorCode")
    void shouldImplementFrameworkErrorCode() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
    }

    @Test
    @DisplayName("Should verify error codes are sequential")
    void shouldVerifyErrorCodesAreSequential() {
        String firstCode = TokenErrorCode.TOKEN_GENERATION_FAILED.getErrorCode();
        String secondCode = TokenErrorCode.TOKEN_VALIDATION_FAILED.getErrorCode();

        assertThat(firstCode).endsWith("01");
        assertThat(secondCode).endsWith("02");
    }

    @Test
    @DisplayName("Should have consistent domain code across all enum values")
    void shouldHaveConsistentDomainCodeAcrossAllEnumValues() {
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getDomainCode())
                .isEqualTo(TokenErrorCode.TOKEN_VALIDATION_FAILED.getDomainCode())
                .isEqualTo("02");
    }
}
