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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for OAuth2 domain exceptions.
 * <p>
 * This test class validates the functionality of OAuth2 protocol-related
 * exceptions in the Framework module.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OAuth2 Exception Test")
class OAuth2ExceptionTest {

    @Test
    @DisplayName("Test FrameworkParProcessingException with message")
    void testFrameworkParProcessingExceptionWithMessage() {
        FrameworkParProcessingException exception = new FrameworkParProcessingException("PAR processing failed");
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0401");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework PAR processing failed: PAR processing failed");
        assertThat(exception.getErrorParams()).containsExactly("PAR processing failed");
    }

    @Test
    @DisplayName("Test FrameworkParProcessingException with message and cause")
    void testFrameworkParProcessingExceptionWithMessageAndCause() {
        Throwable cause = new RuntimeException("Invalid PAR request");
        FrameworkParProcessingException exception = new FrameworkParProcessingException("PAR processing failed", cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0401");
        assertThat(exception.getFormattedMessage()).isEqualTo("Framework PAR processing failed: PAR processing failed");
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode properties")
    void testOAuth2ErrorCodeProperties() {
        assertThat(OAuth2ErrorCode.DOMAIN_CODE).isEqualTo("04");
        
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_11_0401");
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getErrorName()).isEqualTo("FrameworkParProcessingFailed");
        assertThat(OAuth2ErrorCode.PAR_PROCESSING_FAILED.getHttpStatus().value()).isEqualTo(500);
    }

    @Test
    @DisplayName("Test OAuth2ErrorCode formatMessage")
    void testOAuth2ErrorCodeFormatMessage() {
        String message = OAuth2ErrorCode.PAR_PROCESSING_FAILED.formatMessage("Invalid request URI");
        assertThat(message).isEqualTo("Framework PAR processing failed: Invalid request URI");
    }
}
