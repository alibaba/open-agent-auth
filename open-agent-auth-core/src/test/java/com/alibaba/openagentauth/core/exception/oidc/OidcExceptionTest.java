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
package com.alibaba.openagentauth.core.exception.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test class for OIDC exceptions.
 * <p>
 * This test class validates the error codes and message formatting
 * for AuthenticationException and IdTokenException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OIDC Exception Test")
class OidcExceptionTest {

    @Test
    @DisplayName("Test AuthenticationException with single parameter")
    void testAuthenticationExceptionWithSingleParameter() {
        AuthenticationException exception = new AuthenticationException("Username cannot be empty");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed: Username cannot be empty");
        assertThat(exception.getErrorParams()).containsExactly("Username cannot be empty");
    }

    @Test
    @DisplayName("Test AuthenticationException with message and cause")
    void testAuthenticationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Authentication failed");
        AuthenticationException exception = new AuthenticationException("Invalid authentication request", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed: Invalid authentication request");
        assertThat(exception.getErrorParams()).containsExactly("Invalid authentication request");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test AuthenticationException with type and message")
    void testAuthenticationExceptionWithTypeAndMessage() {
        AuthenticationException exception = new AuthenticationException("Invalid authentication request");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed: Invalid authentication request");
        assertThat(exception.getErrorParams()).containsExactly("Invalid authentication request");
    }

    @Test
    @DisplayName("Test AuthenticationException error code properties")
    void testAuthenticationExceptionErrorCodeProperties() {
        AuthenticationException exception = new AuthenticationException("Test message");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.toString()).contains("AuthenticationException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0101'");
    }

    @Test
    @DisplayName("Test IdTokenException with single parameter")
    void testIdTokenExceptionWithSingleParameter() {
        IdTokenException exception = new IdTokenException("Invalid access token");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
        assertThat(exception.getFormattedMessage()).isEqualTo("ID token format error: Invalid access token");
        assertThat(exception.getErrorParams()).containsExactly("Invalid access token");
    }

    @Test
    @DisplayName("Test IdTokenException with message and cause")
    void testIdTokenExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Token validation failed");
        IdTokenException exception = new IdTokenException("Invalid access token", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
        assertThat(exception.getFormattedMessage()).isEqualTo("ID token format error: Invalid access token");
        assertThat(exception.getErrorParams()).containsExactly("Invalid access token");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test IdTokenException error code properties")
    void testIdTokenExceptionErrorCodeProperties() {
        IdTokenException exception = new IdTokenException("Test message");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
        assertThat(exception.toString()).contains("IdTokenException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0102'");
    }

    @Test
    @DisplayName("Test OidcErrorCode error code format")
    void testOidcErrorCodeFormat() {
        assertThat(OidcErrorCode.AUTHENTICATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(OidcErrorCode.ID_TOKEN_FORMAT_ERROR.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
    }

    @Test
    @DisplayName("Test OidcErrorCode domain code")
    void testOidcErrorCodeDomainCode() {
        assertThat(OidcErrorCode.AUTHENTICATION_FAILED.getDomainCode()).isEqualTo("01");
        assertThat(OidcErrorCode.ID_TOKEN_FORMAT_ERROR.getDomainCode()).isEqualTo("01");
    }

    @Test
    @DisplayName("Test OidcErrorCode sub code")
    void testOidcErrorCodeSubCode() {
        assertThat(OidcErrorCode.AUTHENTICATION_FAILED.getSubCode()).isEqualTo("01");
        assertThat(OidcErrorCode.ID_TOKEN_FORMAT_ERROR.getSubCode()).isEqualTo("02");
    }

    @Test
    @DisplayName("Test OidcErrorCode system code")
    void testOidcErrorCodeSystemCode() {
        assertThat(OidcErrorCode.AUTHENTICATION_FAILED.getSystemCode()).isEqualTo("10");
        assertThat(OidcErrorCode.ID_TOKEN_FORMAT_ERROR.getSystemCode()).isEqualTo("10");
    }

    @Test
    @DisplayName("Test OidcErrorCode error names")
    void testOidcErrorCodeErrorNames() {
        assertThat(OidcErrorCode.AUTHENTICATION_FAILED.getErrorName()).isEqualTo("AuthenticationFailed");
        assertThat(OidcErrorCode.ID_TOKEN_FORMAT_ERROR.getErrorName()).isEqualTo("IdTokenFormatError");
    }

    @Test
    @DisplayName("Test OidcErrorCode HTTP status")
    void testOidcErrorCodeHttpStatus() {
        assertThat(OidcErrorCode.AUTHENTICATION_FAILED.getHttpStatus().value()).isEqualTo(401);
        assertThat(OidcErrorCode.ID_TOKEN_FORMAT_ERROR.getHttpStatus().value()).isEqualTo(400);
    }

    @Test
    @DisplayName("Test AuthenticationException with RFC error code")
    void testAuthenticationExceptionWithRfcErrorCode() {
        AuthenticationException exception = new AuthenticationException(OidcRfcErrorCode.LOGIN_REQUIRED, "User must login");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.getRfcErrorCode()).isEqualTo("login_required");
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed: User must login");
    }

    @Test
    @DisplayName("Test AuthenticationException with RFC error code and cause")
    void testAuthenticationExceptionWithRfcErrorCodeAndCause() {
        Throwable cause = new RuntimeException("Authentication failed");
        AuthenticationException exception = new AuthenticationException(OidcRfcErrorCode.ACCESS_DENIED, "Access denied", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.getRfcErrorCode()).isEqualTo("access_denied");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test AuthenticationException without RFC error code (backward compatibility)")
    void testAuthenticationExceptionWithoutRfcErrorCode() {
        AuthenticationException exception = new AuthenticationException("Username cannot be empty");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
        assertThat(exception.getRfcErrorCode()).isNull();
        assertThat(exception.getFormattedMessage()).isEqualTo("Authentication failed: Username cannot be empty");
    }

    @Test
    @DisplayName("Test IdTokenException with RFC error code")
    void testIdTokenExceptionWithRfcErrorCode() {
        IdTokenException exception = new IdTokenException(OidcRfcErrorCode.INVALID_ID_TOKEN, "Invalid token signature");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_id_token");
        assertThat(exception.getFormattedMessage()).isEqualTo("ID token format error: Invalid token signature");
    }

    @Test
    @DisplayName("Test IdTokenException with RFC error code and cause")
    void testIdTokenExceptionWithRfcErrorCodeAndCause() {
        Throwable cause = new RuntimeException("Token validation failed");
        IdTokenException exception = new IdTokenException(OidcRfcErrorCode.INVALID_ID_TOKEN, "Invalid token signature", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
        assertThat(exception.getRfcErrorCode()).isEqualTo("invalid_id_token");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test IdTokenException without RFC error code (backward compatibility)")
    void testIdTokenExceptionWithoutRfcErrorCode() {
        IdTokenException exception = new IdTokenException("Invalid access token");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0102");
        assertThat(exception.getRfcErrorCode()).isNull();
        assertThat(exception.getFormattedMessage()).isEqualTo("ID token format error: Invalid access token");
    }

    @Test
    @DisplayName("Test OidcException getRfcErrorCode returns RFC error code")
    void testOidcExceptionGetRfcErrorCode() {
        AuthenticationException exception = new AuthenticationException(OidcRfcErrorCode.LOGIN_REQUIRED, "User must login");
        
        assertThat(exception.getRfcErrorCode()).isEqualTo("login_required");
    }

    @Test
    @DisplayName("Test OidcException getErrorCode returns OPEN AGENT AUTH error code")
    void testOidcExceptionGetErrorCode() {
        AuthenticationException exception = new AuthenticationException(OidcRfcErrorCode.LOGIN_REQUIRED, "User must login");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0101");
    }

    @Test
    @DisplayName("Test OidcRfcErrorCode fromValue")
    void testOidcRfcErrorCodeFromValue() {
        assertThat(OidcRfcErrorCode.fromValue("invalid_request")).isEqualTo(OidcRfcErrorCode.INVALID_REQUEST);
        assertThat(OidcRfcErrorCode.fromValue("login_required")).isEqualTo(OidcRfcErrorCode.LOGIN_REQUIRED);
        assertThat(OidcRfcErrorCode.fromValue("invalid_id_token")).isEqualTo(OidcRfcErrorCode.INVALID_ID_TOKEN);
    }

    @Test
    @DisplayName("Test OidcRfcErrorCode fromValue throws exception for invalid value")
    void testOidcRfcErrorCodeFromValueInvalid() {
        assertThatThrownBy(() -> OidcRfcErrorCode.fromValue("invalid_error_code"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No matching OidcRfcErrorCode for");
    }

    @Test
    @DisplayName("Test OidcRfcErrorCode isAuthenticationError")
    void testOidcRfcErrorCodeIsAuthenticationError() {
        assertThat(OidcRfcErrorCode.INVALID_REQUEST.isAuthenticationError()).isTrue();
        assertThat(OidcRfcErrorCode.LOGIN_REQUIRED.isAuthenticationError()).isTrue();
        assertThat(OidcRfcErrorCode.ACCESS_DENIED.isAuthenticationError()).isTrue();
        assertThat(OidcRfcErrorCode.INVALID_ID_TOKEN.isAuthenticationError()).isFalse();
    }

    @Test
    @DisplayName("Test OidcRfcErrorCode isIdTokenError")
    void testOidcRfcErrorCodeIsIdTokenError() {
        assertThat(OidcRfcErrorCode.INVALID_ID_TOKEN.isIdTokenError()).isTrue();
        assertThat(OidcRfcErrorCode.INVALID_REQUEST.isIdTokenError()).isFalse();
        assertThat(OidcRfcErrorCode.LOGIN_REQUIRED.isIdTokenError()).isFalse();
    }

    @Test
    @DisplayName("Test OidcRfcErrorCode getValue and getDescription")
    void testOidcRfcErrorCodeProperties() {
        OidcRfcErrorCode errorCode = OidcRfcErrorCode.LOGIN_REQUIRED;
        
        assertThat(errorCode.getValue()).isEqualTo("login_required");
        assertThat(errorCode.getDescription()).isEqualTo("The Authorization Server requires End-User authentication");
    }

    @Test
    @DisplayName("Test OidcRfcErrorCode toString")
    void testOidcRfcErrorCodeToString() {
        assertThat(OidcRfcErrorCode.LOGIN_REQUIRED.toString()).isEqualTo("login_required: The Authorization Server requires End-User authentication");
        assertThat(OidcRfcErrorCode.INVALID_ID_TOKEN.toString()).isEqualTo("invalid_id_token: The ID Token is invalid");
    }
}