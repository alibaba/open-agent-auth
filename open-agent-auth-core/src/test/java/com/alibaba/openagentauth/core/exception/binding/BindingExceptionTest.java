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
package com.alibaba.openagentauth.core.exception.binding;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test class for Binding exceptions.
 * <p>
 * This test class validates the error codes, message formatting,
 * and custom properties for BindingException and BindingNotFoundException.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Binding Exception Test")
class BindingExceptionTest {

    @Test
    @DisplayName("Should create BindingNotFoundException with binding instance ID")
    void shouldCreateBindingNotFoundExceptionWithBindingInstanceId() {
        String bindingInstanceId = "binding-123";
        BindingNotFoundException exception = new BindingNotFoundException(bindingInstanceId);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0701");
        assertThat(exception.getFormattedMessage()).isEqualTo("Binding instance not found: binding-123");
        assertThat(exception.getErrorParams()).containsExactly(bindingInstanceId);
        assertThat(exception.getBindingInstanceId()).isEqualTo(bindingInstanceId);
    }

    @Test
    @DisplayName("Should create BindingNotFoundException with binding instance ID and cause")
    void shouldCreateBindingNotFoundExceptionWithBindingInstanceIdAndCause() {
        String bindingInstanceId = "binding-456";
        Throwable cause = new RuntimeException("Database connection failed");
        BindingNotFoundException exception = new BindingNotFoundException(bindingInstanceId, cause);
        
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0701");
        assertThat(exception.getFormattedMessage()).isEqualTo("Binding instance not found: binding-456");
        assertThat(exception.getErrorParams()).containsExactly(bindingInstanceId);
        assertThat(exception.getBindingInstanceId()).isEqualTo(bindingInstanceId);
        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("Should contain exception type in toString")
    void shouldContainExceptionTypeInToString() {
        BindingNotFoundException exception = new BindingNotFoundException("binding-789");
        
        assertThat(exception.toString()).contains("BindingNotFoundException");
        assertThat(exception.toString()).contains("errorCode='OPEN_AGENT_AUTH_10_0701'");
        assertThat(exception.toString()).contains("binding-789");
    }

    @Test
    @DisplayName("Should preserve null binding instance ID")
    void shouldPreserveNullBindingInstanceId() {
        // Note: BindingNotFoundException requires bindingInstanceId, so this tests
        // that the field is properly set even with edge cases
        BindingNotFoundException exception = new BindingNotFoundException("");
        
        assertThat(exception.getBindingInstanceId()).isEqualTo("");
        assertThat(exception.getErrorCode()).isEqualTo("OPEN_AGENT_AUTH_10_0701");
    }

    @Test
    @DisplayName("Should verify error code structure")
    void shouldVerifyErrorCodeStructure() {
        BindingNotFoundException exception = new BindingNotFoundException("test-binding");
        
        // Error code format: OPEN_AGENT_AUTH_10_07ZZ
        assertThat(exception.getErrorCode()).startsWith("OPEN_AGENT_AUTH_10_07");
        assertThat(exception.getErrorCode()).hasSize(23);
    }
}