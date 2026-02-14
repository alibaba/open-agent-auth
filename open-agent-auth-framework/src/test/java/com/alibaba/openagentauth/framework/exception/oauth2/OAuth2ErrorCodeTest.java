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
package com.alibaba.openagentauth.framework.exception.oauth2;

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for OAuth2ErrorCode enum.
 * <p>
 * This test class validates the error code definitions for the OAuth2 domain,
 * ensuring proper error code structure, message templates, and HTTP status mapping.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OAuth2ErrorCode Test")
class OAuth2ErrorCodeTest {

    @Test
    @DisplayName("Should have correct domain code")
    void shouldHaveCorrectDomainCode() {
        assertThat(OAuth2ErrorCode.DOMAIN_CODE).isEqualTo("04");
    }

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should generate correct error code for PAR_PROCESSING_FAILED")
    void shouldGenerateCorrectErrorCodeForParProcessingFailed() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0401");
    }

    @Test
    @DisplayName("Should have correct sub codes")
    void shouldHaveCorrectSubCodes() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getSubCode()).isEqualTo("01");
    }

    @Test
    @DisplayName("Should have correct error names")
    void shouldHaveCorrectErrorNames() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getErrorName())
                .isEqualTo("FrameworkParProcessingFailed");
    }

    @Test
    @DisplayName("Should have correct message templates")
    void shouldHaveCorrectMessageTemplates() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getMessageTemplate())
                .isEqualTo("Framework PAR processing failed: {0}");
    }

    @Test
    @DisplayName("Should have correct HTTP status codes")
    void shouldHaveCorrectHttpStatusCodes() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    @DisplayName("Should format messages correctly")
    void shouldFormatMessagesCorrectly() {
        String message = OAuth2ErrorCode.PAR_PROCESSING_FAILED.formatMessage("Invalid PAR request");
        assertThat(message).isEqualTo("Framework PAR processing failed: Invalid PAR request");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String message = OAuth2ErrorCode.PAR_PROCESSING_FAILED.formatMessage((Object[]) null);
        assertThat(message).isEqualTo("Framework PAR processing failed: {0}");
    }

    @Test
    @DisplayName("Should implement FrameworkErrorCode")
    void shouldImplementFrameworkErrorCode() {
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        String errorCode = OAuth2ErrorCode.PAR_PROCESSING_FAILED.getErrorCode();
        assertThat(errorCode).startsWith("OPEN_AGENT_AUTH_11_04");
        assertThat(errorCode).endsWith("01");
    }
}
