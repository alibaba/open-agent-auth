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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Auth domain exceptions.
 * <p>
 * This test class validates the functionality of authentication and authorization
 * exceptions in the Framework module.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Auth Exception Test")
class AuthExceptionTest {

    @Test
    @DisplayName("Test FrameworkAuthenticationException with message")
    void testFrameworkAuthenticationExceptionWithMessage() {
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException("Authentication failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: Authentication failed");
        assertThat(exception.getErrorParams()).containsExactly("Authentication failed");
    }

    @Test
    @DisplayName("Test FrameworkAuthenticationException with message and cause")
    void testFrameworkAuthenticationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Invalid credentials");
        FrameworkAuthenticationException exception = new FrameworkAuthenticationException("Authentication failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authentication failed: Authentication failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test FrameworkAuthorizationException with message")
    void testFrameworkAuthorizationExceptionWithMessage() {
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException("Authorization denied");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0102");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization failed: Authorization denied");
        assertThat(exception.getErrorParams()).containsExactly("Authorization denied");
    }

    @Test
    @DisplayName("Test FrameworkAuthorizationException with message and cause")
    void testFrameworkAuthorizationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Insufficient permissions");
        FrameworkAuthorizationException exception = new FrameworkAuthorizationException("Authorization denied", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0102");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework authorization failed: Authorization denied");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test AuthErrorCode properties")
    void testAuthErrorCodeProperties() {
        assertThat(AuthErrorCode.DOMAIN_CODE).isEqualTo("01");
        
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0101");
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getErrorName()).isEqualTo("FrameworkAuthenticationFailed");
        assertThat(AuthErrorCode.AUTHENTICATION_FAILED.getHttpStatus().value()).isEqualTo(401);
        
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0102");
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getErrorName()).isEqualTo("FrameworkAuthorizationFailed");
        assertThat(AuthErrorCode.AUTHORIZATION_FAILED.getHttpStatus().value()).isEqualTo(403);
    }

    @Test
    @DisplayName("Test AuthErrorCode formatMessage")
    void testAuthErrorCodeFormatMessage() {
        String message = AuthErrorCode.AUTHENTICATION_FAILED.formatMessage("user123");
        assertThat(message).isEqualTo("Framework authentication failed: user123");
        
        message = AuthErrorCode.AUTHORIZATION_FAILED.formatMessage("resourceXYZ");
        assertThat(message).isEqualTo("Framework authorization failed: resourceXYZ");
    }
}
