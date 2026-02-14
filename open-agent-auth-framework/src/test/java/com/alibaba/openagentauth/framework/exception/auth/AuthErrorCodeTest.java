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
package com.alibaba.openagentauth.framework.exception.auth;

import com.alibaba.openagentauth.core.exception.HttpStatus;
import com.alibaba.openagentauth.framework.exception.FrameworkErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for AuthErrorCode enum.
 * <p>
 * This test class validates the error code definitions for the Auth domain,
 * ensuring proper error code structure, message templates, and HTTP status mapping.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuthErrorCode Test")
class AuthErrorCodeTest {

    @Test
    @DisplayName("Should have correct domain code")
    void shouldHaveCorrectDomainCode() {
        assertThat(AuthErrorCode.DOMAIN_CODE).isEqualTo("01");
    }

    @Test
    @DisplayName("Should have correct system code")
    void shouldHaveCorrectSystemCode() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getSystemCode()).isEqualTo("11");
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getSystemCode()).isEqualTo("11");
    }

    @Test
    @DisplayName("Should generate correct error code for AUTHENTICATION_FAILED")
    void shouldGenerateCorrectErrorCodeForAuthenticationFailed() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0101");
    }

    @Test
    @DisplayName("Should generate correct error code for AUTHORIZATION_FAILED")
    void shouldGenerateCorrectErrorCodeForAuthorizationFailed() {
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getErrorCode())
                .isEqualTo("OPEN_AGENT_AUTH_11_0102");
    }

    @Test
    @DisplayName("Should have correct sub codes")
    void shouldHaveCorrectSubCodes() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getSubCode()).isEqualTo("01");
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Should have correct error names")
    void shouldHaveCorrectErrorNames() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getErrorName())
                .isEqualTo("FrameworkAuthenticationFailed");
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getErrorName())
                .isEqualTo("FrameworkAuthorizationFailed");
    }

    @Test
    @DisplayName("Should have correct message templates")
    void shouldHaveCorrectMessageTemplates() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getMessageTemplate())
                .isEqualTo("Framework authentication failed: {0}");
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getMessageTemplate())
                .isEqualTo("Framework authorization failed: {0}");
    }

    @Test
    @DisplayName("Should have correct HTTP status codes")
    void shouldHaveCorrectHttpStatusCodes() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    @DisplayName("Should format messages correctly")
    void shouldFormatMessagesCorrectly() {
        String authMessage = AuthErrorCode.AUTHENTICATION_FAILED.formatMessage("Invalid credentials");
        assertThat(authMessage).isEqualTo("Framework authentication failed: Invalid credentials");

        String authzMessage = AuthErrorCode.AUTHORIZATION_FAILED.formatMessage("Insufficient permissions");
        assertThat(authzMessage).isEqualTo("Framework authorization failed: Insufficient permissions");
    }

    @Test
    @DisplayName("Should format message with null parameters")
    void shouldFormatMessageWithNullParameters() {
        String message = AuthErrorCode.AUTHENTICATION_FAILED.formatMessage((Object[]) null);
        assertThat(message).isEqualTo("Framework authentication failed: {0}");
    }

    @Test
    @DisplayName("Should implement FrameworkErrorCode")
    void shouldImplementFrameworkErrorCode() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED)
                .isInstanceOf(FrameworkErrorCode.class);
    }

    @Test
    @DisplayName("Should verify error codes are sequential")
    void shouldVerifyErrorCodesAreSequential() {
        String firstCode = AuthErrorCode.AUTHENTICATION_FAILED.getErrorCode();
        String secondCode = AuthErrorCode.AUTHORIZATION_FAILED.getErrorCode();

        assertThat(firstCode).endsWith("01");
        assertThat(secondCode).endsWith("02");
    }

    @Test
    @DisplayName("Should have consistent domain code across all enum values")
    void shouldHaveConsistentDomainCodeAcrossAllEnumValues() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getDomainCode())
                .isEqualTo(AuthErrorCode.AUTHORIZATION_FAILED.getDomainCode())
                .isEqualTo("01");
    }

    @Test
    @DisplayName("Should have distinct HTTP status codes for authentication and authorization")
    void shouldHaveDistinctHttpStatusCodesForAuthenticationAndAuthorization() {
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getHttpStatus())
                .isNotEqualTo(AuthErrorCode.AUTHORIZATION_FAILED.getHttpStatus());
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getHttpStatus())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }
}
