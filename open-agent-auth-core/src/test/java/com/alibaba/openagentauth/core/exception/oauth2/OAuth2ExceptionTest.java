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
package com.alibaba.openagentauth.core.exception.oauth2;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for OAuth2 exceptions.
 * <p>
 * This test class validates the error codes, message formatting,
 * and RFC error codes for DcrException, ParException, OAuth2TokenException,
 * OAuth2AuthorizationException, and ClientAssertionException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OAuth2 Exception Test")
class OAuth2ExceptionTest {

    @Test
    @DisplayName("Test DcrException with single parameter")
    void testDcrExceptionWithSingleParameter() {
        DcrException exception = new DcrException("Invalid redirect URI");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0401");
        assertThat(exception.getFormattedMessage()).isEqualTo("Dynamic Client Registration error: Invalid redirect URI");
        assertThat(exception.getRfcErrorCode()).isEqualTo("server_error");
    }

    @Test
    @DisplayName("Test DcrException with message and cause")
    void testDcrExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Validation failed");
        DcrException exception = new DcrException("Invalid redirect URI", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0401");
        assertThat(exception.getFormattedMessage()).isEqualTo("Dynamic Client Registration error: Invalid redirect URI");
        assertThat(exception.getRfcErrorCode()).isEqualTo("server_error");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test DcrException static factory method - invalidRedirectUri")
    void testDcrExceptionInvalidRedirectUri() {
        DcrException exception = DcrException.invalidRedirectUri("https://example.com/callback");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0401");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_redirect_uri");
        assertThat(exception.getFormattedMessage()).isEqualTo("Dynamic Client Registration error: https://example.com/callback");
    }

    @Test
    @DisplayName("Test DcrException static factory method - invalidClientMetadata")
    void testDcrExceptionInvalidClientMetadata() {
        DcrException exception = DcrException.invalidClientMetadata("Missing required field: redirect_uris");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0401");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_client_metadata");
    }

    @Test
    @DisplayName("Test ParException static factory method - missingParameter")
    void testParExceptionMissingParameter() {
        ParException exception = ParException.missingParameter("code_challenge");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0402");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_request");
    }

    @Test
    @DisplayName("Test ParException static factory method - authenticationFailed")
    void testParExceptionAuthenticationFailed() {
        ParException exception = ParException.authenticationFailed("Invalid client credentials");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0402");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    @DisplayName("Test OAuth2TokenException with single parameter")
    void testOAuth2TokenExceptionWithSingleParameter() {
        OAuth2TokenException exception = new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_GRANT, "Invalid grant type");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0403");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_grant");
    }

    @Test
    @DisplayName("Test OAuth2TokenException with message and cause")
    void testOAuth2TokenExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Token generation failed");
        OAuth2TokenException exception = new OAuth2TokenException(OAuth2RfcErrorCode.INVALID_GRANT, "Invalid grant type", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0403");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_grant");
        assertThat(exception.getFormattedMessage()).isEqualTo("OAuth 2.0 Token error: Invalid grant type");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test OAuth2TokenException static factory method - invalidGrant")
    void testOAuth2TokenExceptionInvalidGrant() {
        OAuth2TokenException exception = OAuth2TokenException.invalidGrant("Authorization code expired");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0403");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_grant");
    }

    @Test
    @DisplayName("Test OAuth2TokenException static factory method - invalidClient")
    void testOAuth2TokenExceptionInvalidClient() {
        OAuth2TokenException exception = OAuth2TokenException.invalidClient("Invalid client credentials");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0403");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_client");
    }

    @Test
    @DisplayName("Test OAuth2AuthorizationException with single parameter")
    void testOAuth2AuthorizationExceptionWithSingleParameter() {
        OAuth2AuthorizationException exception = new OAuth2AuthorizationException(OAuth2RfcErrorCode.INVALID_REQUEST, "Invalid request");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0404");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_request");
        assertThat(exception.getFormattedMessage()).isEqualTo("OAuth 2.0 Authorization error: Invalid request");
    }

    @Test
    @DisplayName("Test OAuth2AuthorizationException with message and cause")
    void testOAuth2AuthorizationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Authorization failed");
        OAuth2AuthorizationException exception = new OAuth2AuthorizationException(OAuth2RfcErrorCode.INVALID_REQUEST, "Invalid request", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0404");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_request");
        assertThat(exception.getFormattedMessage()).isEqualTo("OAuth 2.0 Authorization error: Invalid request");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test OAuth2AuthorizationException static factory method - accessDenied")
    void testOAuth2AuthorizationExceptionAccessDenied() {
        OAuth2AuthorizationException exception = OAuth2AuthorizationException.accessDenied("User denied access");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0404");
        assertThat(exception.getRfcErrorCode()).isEqualTo("access_denied");
    }

    @Test
    @DisplayName("Test OAuth2AuthorizationException static factory method - invalidScope")
    void testOAuth2AuthorizationExceptionInvalidScope() {
        OAuth2AuthorizationException exception = OAuth2AuthorizationException.invalidScope("Invalid scope: read write");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0404");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_scope");
    }

    @Test
    @DisplayName("Test ClientAssertionException with single parameter")
    void testClientAssertionExceptionWithSingleParameter() {
        ClientAssertionException exception = new ClientAssertionException("Invalid assertion");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0405");
        assertThat(exception.getFormattedMessage()).isEqualTo("Client assertion error: Invalid assertion");
    }

    @Test
    @DisplayName("Test ClientAssertionException with message and cause")
    void testClientAssertionExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Assertion validation failed");
        ClientAssertionException exception = new ClientAssertionException("Invalid assertion", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0405");
        assertThat(exception.getFormattedMessage()).isEqualTo("Client assertion error: Invalid assertion");
        assertThat(exception.getErrorParams()).containsExactly("Invalid assertion");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode error code format")
    void testOAuth2ErrorCodeFormat() {
        assertThat(OAuth2ErrorCode.DCR_ERROR.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0401");
        assertThat(OAuth2ErrorCode.PAR_ERROR.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0402");
        assertThat(OAuth2ErrorCode.TOKEN_ERROR.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0403");
        assertThat(OAuth2ErrorCode.AUTHORIZATION_ERROR.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0404");
        assertThat(OAuth2ErrorCode.CLIENT_ASSERTION_ERROR.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0405");
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode domain code")
    void testOAuth2ErrorCodeDomainCode() {
        assertThat(OAuth2ErrorCode.DCR_ERROR.getDomainCode()).isEqualTo("04");
        assertThat(OAuth2ErrorCode.PAR_ERROR.getDomainCode()).isEqualTo("04");
        assertThat(OAuth2ErrorCode.TOKEN_ERROR.getDomainCode()).isEqualTo("04");
        assertThat(OAuth2ErrorCode.AUTHORIZATION_ERROR.getDomainCode()).isEqualTo("04");
        assertThat(OAuth2ErrorCode.CLIENT_ASSERTION_ERROR.getDomainCode()).isEqualTo("04");
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode sub code")
    void testOAuth2ErrorCodeSubCode() {
        assertThat(OAuth2ErrorCode.DCR_ERROR.getSubCode()).isEqualTo("01");
        assertThat(OAuth2ErrorCode.PAR_ERROR.getSubCode()).isEqualTo("02");
        assertThat(OAuth2ErrorCode.TOKEN_ERROR.getSubCode()).isEqualTo("03");
        assertThat(OAuth2ErrorCode.AUTHORIZATION_ERROR.getSubCode()).isEqualTo("04");
        assertThat(OAuth2ErrorCode.CLIENT_ASSERTION_ERROR.getSubCode()).isEqualTo("05");
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode system code")
    void testOAuth2ErrorCodeSystemCode() {
        assertThat(OAuth2ErrorCode.DCR_ERROR.getSystemCode()).isEqualTo("10");
        assertThat(OAuth2ErrorCode.PAR_ERROR.getSystemCode()).isEqualTo("10");
        assertThat(OAuth2ErrorCode.TOKEN_ERROR.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode error names")
    void testOAuth2ErrorCodeErrorNames() {
        assertThat(OAuth2ErrorCode.DCR_ERROR.getErrorName()).isEqualTo("DcrError");
        assertThat(OAuth2ErrorCode.PAR_ERROR.getErrorName()).isEqualTo("ParError");
        assertThat(OAuth2ErrorCode.TOKEN_ERROR.getErrorName()).isEqualTo("TokenError");
        assertThat(OAuth2ErrorCode.AUTHORIZATION_ERROR.getErrorName()).isEqualTo("AuthorizationError");
        assertThat(OAuth2ErrorCode.CLIENT_ASSERTION_ERROR.getErrorName()).isEqualTo("ClientAssertionError");
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode HTTP status")
    void testOAuth2ErrorCodeHttpStatus() {
        assertThat(OAuth2ErrorCode.DCR_ERROR.getHttpStatus().value()).isEqualTo(400);
        assertThat(OAuth2ErrorCode.PAR_ERROR.getHttpStatus().value()).isEqualTo(400);
        assertThat(OAuth2ErrorCode.TOKEN_ERROR.getHttpStatus().value()).isEqualTo(400);
        assertThat(OAuth2ErrorCode.AUTHORIZATION_ERROR.getHttpStatus().value()).isEqualTo(400);
        assertThat(OAuth2ErrorCode.CLIENT_ASSERTION_ERROR.getHttpStatus().value()).isEqualTo(400);
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode domain code constant")
    void testOAuth2ErrorCodeDomainCodeConstant() {
        assertThat(OAuth2ErrorCode.DOMAIN_CODE).isEqualTo("04");
    }

    @Test
    @DisplayName("Test OAuth2Exception getRfcErrorCode returns RFC error code")
    void testOAuth2ExceptionGetRfcErrorCode() {
        DcrException exception = DcrException.invalidRedirectUri("https://example.com/callback");
        
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_redirect_uri");
    }

    @Test
    @DisplayName("Test OAuth2Exception getErrorCode returns OPEN AGENT AUTH error code")
    void testOAuth2ExceptionGetErrorCode() {
        DcrException exception = DcrException.invalidRedirectUri("https://example.com/callback");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0401");
    }
}