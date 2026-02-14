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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Token domain exceptions.
 * <p>
 * This test class validates the functionality of token generation and validation
 * exceptions in the Framework module.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Token Exception Test")
class TokenExceptionTest {

    @Test
    @DisplayName("Test FrameworkTokenGenerationException with message")
    void testFrameworkTokenGenerationExceptionWithMessage() {
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException("Token generation failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token generation failed: Token generation failed");
        assertThat(exception.getErrorParams()).containsExactly("Token generation failed");
    }

    @Test
    @DisplayName("Test FrameworkTokenGenerationException with message and cause")
    void testFrameworkTokenGenerationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Key generation failed");
        FrameworkTokenGenerationException exception = new FrameworkTokenGenerationException("Token generation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0201");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token generation failed: Token generation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test FrameworkTokenValidationException with message")
    void testFrameworkTokenValidationExceptionWithMessage() {
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException("Token validation failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0202");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token validation failed: Token validation failed");
        assertThat(exception.getErrorParams()).containsExactly("Token validation failed");
    }

    @Test
    @DisplayName("Test FrameworkTokenValidationException with message and cause")
    void testFrameworkTokenValidationExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Invalid signature");
        FrameworkTokenValidationException exception = new FrameworkTokenValidationException("Token validation failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0202");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework token validation failed: Token validation failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test TokenErrorCode properties")
    void testTokenErrorCodeProperties() {
        assertThat(TokenErrorCode.DOMAIN_CODE).isEqualTo("02");
        
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0201");
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getErrorName()).isEqualTo("FrameworkTokenGenerationFailed");
        assertThat(TokenErrorCode.TOKEN_GENERATION_FAILED.getHttpStatus().value()).isEqualTo(500);
        
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0202");
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getErrorName()).isEqualTo("FrameworkTokenValidationFailed");
        assertThat(TokenErrorCode.TOKEN_VALIDATION_FAILED.getHttpStatus().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("Test TokenErrorCode formatMessage")
    void testTokenErrorCodeFormatMessage() {
        String message = TokenErrorCode.TOKEN_GENERATION_FAILED.formatMessage("JWT");
        assertThat(message).isEqualTo("Framework token generation failed: JWT");
        
        message = TokenErrorCode.TOKEN_VALIDATION_FAILED.formatMessage("expired token");
        assertThat(message).isEqualTo("Framework token validation failed: expired token");
    }
}
