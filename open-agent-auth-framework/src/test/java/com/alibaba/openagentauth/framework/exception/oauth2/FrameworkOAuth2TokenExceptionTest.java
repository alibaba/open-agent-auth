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

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for FrameworkOAuth2TokenException.
 * <p>
 * This test class validates the functionality of the OAuth2 token exception,
 * including constructors, error code handling, HTTP status mapping, and factory methods.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("FrameworkOAuth2TokenException Test")
class FrameworkOAuth2TokenExceptionTest {

    @Test
    @DisplayName("Should create exception with error code and message")
    void shouldCreateExceptionWithErrorCodeAndMessage() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_request", "Missing required parameter");

        assertThat(exception.getErrorCode()).isEqualTo("invalid_request");
        assertThat(exception.getErrorDescription()).isEqualTo("Missing required parameter");
        assertThat(exception.getMessage()).isEqualTo("Missing required parameter");
        assertThat(exception.getHttpStatus()).isEqualTo(400);
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("Should create exception with error code, message, and cause")
    void shouldCreateExceptionWithErrorCodeMessageAndCause() {
        Throwable cause = new RuntimeException("Parameter validation failed");
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_client", "Client authentication failed", cause);

        assertThat(exception.getErrorCode()).isEqualTo("invalid_client");
        assertThat(exception.getErrorDescription()).isEqualTo("Client authentication failed");
        assertThat(exception.getHttpStatus()).isEqualTo(401);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should create exception with full details")
    void shouldCreateExceptionWithFullDetails() {
        Throwable cause = new RuntimeException("Grant expired");
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_grant", "Grant invalid", "Authorization code has expired", cause, 400);

        assertThat(exception.getErrorCode()).isEqualTo("invalid_grant");
        assertThat(exception.getMessage()).isEqualTo("Grant invalid");
        assertThat(exception.getErrorDescription()).isEqualTo("Authorization code has expired");
        assertThat(exception.getHttpStatus()).isEqualTo(400);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should wrap OAuth2TokenException correctly")
    void shouldWrapOAuth2TokenExceptionCorrectly() {
        OAuth2TokenException cause = new OAuth2TokenException(
                OAuth2RfcErrorCode.INVALID_SCOPE,
                "Scope exceeds granted scope");
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(cause);

        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0403");
        assertThat(exception.getErrorDescription()).isEqualTo("OAuth 2.0 Token error: Scope exceeds granted scope");
        assertThat(exception.getHttpStatus()).isEqualTo(400);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should determine correct HTTP status for invalid_client")
    void shouldDetermineCorrectHttpStatusForInvalidClient() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_client", "Client auth failed");

        assertThat(exception.getHttpStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("Should determine correct HTTP status for unauthorized_client")
    void shouldDetermineCorrectHttpStatusForUnauthorizedClient() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "unauthorized_client", "Client not authorized");

        assertThat(exception.getHttpStatus()).isEqualTo(403);
    }

    @Test
    @DisplayName("Should determine correct HTTP status for invalid_request")
    void shouldDetermineCorrectHttpStatusForInvalidRequest() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_request", "Malformed request");

        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should determine correct HTTP status for invalid_grant")
    void shouldDetermineCorrectHttpStatusForInvalidGrant() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_grant", "Grant invalid");

        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should determine correct HTTP status for invalid_scope")
    void shouldDetermineCorrectHttpStatusForInvalidScope() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_scope", "Scope invalid");

        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should determine default HTTP status for unknown error code")
    void shouldDetermineDefaultHttpStatusForUnknownErrorCode() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "unknown_error", "Unknown error");

        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should determine default HTTP status for null error code")
    void shouldDetermineDefaultHttpStatusForNullErrorCode() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                null, "Null error code");

        assertThat(exception.getHttpStatus()).isEqualTo(500);
    }

    @Test
    @DisplayName("Should create invalid_request exception via factory method")
    void shouldCreateInvalidRequestExceptionViaFactoryMethod() {
        FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidRequest(
                "Missing required parameter");

        assertThat(exception.getErrorCode()).isEqualTo("invalid_request");
        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should create invalid_client exception via factory method")
    void shouldCreateInvalidClientExceptionViaFactoryMethod() {
        FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidClient(
                "Client authentication failed");

        assertThat(exception.getErrorCode()).isEqualTo("invalid_client");
        assertThat(exception.getHttpStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("Should create invalid_grant exception via factory method")
    void shouldCreateInvalidGrantExceptionViaFactoryMethod() {
        FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidGrant(
                "Authorization code expired");

        assertThat(exception.getErrorCode()).isEqualTo("invalid_grant");
        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should create invalid_scope exception via factory method")
    void shouldCreateInvalidScopeExceptionViaFactoryMethod() {
        FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.invalidScope(
                "Scope exceeds granted scope");

        assertThat(exception.getErrorCode()).isEqualTo("invalid_scope");
        assertThat(exception.getHttpStatus()).isEqualTo(400);
    }

    @Test
    @DisplayName("Should create unauthorized_client exception via factory method")
    void shouldCreateUnauthorizedClientExceptionViaFactoryMethod() {
        FrameworkOAuth2TokenException exception = FrameworkOAuth2TokenException.unauthorizedClient(
                "Client not authorized for this grant type");

        assertThat(exception.getErrorCode()).isEqualTo("unauthorized_client");
        assertThat(exception.getHttpStatus()).isEqualTo(403);
    }

    @Test
    @DisplayName("Should format toString correctly")
    void shouldFormatToStringCorrectly() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_request", "Bad request");

        String toString = exception.toString();
        assertThat(toString).contains("FrameworkOAuth2TokenException");
        assertThat(toString).contains("errorCode='invalid_request'");
        assertThat(toString).contains("errorDescription='Bad request'");
        assertThat(toString).contains("httpStatus=400");
    }

    @Test
    @DisplayName("Should be instance of RuntimeException")
    void shouldBeInstanceOfRuntimeException() {
        FrameworkOAuth2TokenException exception = new FrameworkOAuth2TokenException(
                "invalid_request", "test");

        assertThat(exception).isInstanceOf(RuntimeException.class);
    }
}
