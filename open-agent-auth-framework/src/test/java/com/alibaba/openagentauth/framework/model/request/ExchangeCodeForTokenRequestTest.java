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
package com.alibaba.openagentauth.framework.model.request;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link ExchangeCodeForTokenRequest.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, required field validation,
 * optional field settings, and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("ExchangeCodeForTokenRequest.Builder Tests")
class ExchangeCodeForTokenRequestTest {

    private static final String TEST_CODE = "authorization-code-abc123";
    private static final String TEST_STATE = "state-xyz789";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_CLIENT_ID = "test-client-id";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state(TEST_STATE)
                .redirectUri(TEST_REDIRECT_URI)
                .clientId(TEST_CLIENT_ID)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getCode()).isEqualTo(TEST_CODE);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        ExchangeCodeForTokenRequest.Builder builder = ExchangeCodeForTokenRequest.builder();

        // When
        ExchangeCodeForTokenRequest request = builder
                .code(TEST_CODE)
                .state(TEST_STATE)
                .clientId(TEST_CLIENT_ID)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getCode()).isEqualTo(TEST_CODE);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
    }

    @Test
    @DisplayName("Should throw exception when code is null")
    void shouldThrowExceptionWhenCodeIsNull() {
        // When & Then
        assertThatThrownBy(() -> ExchangeCodeForTokenRequest.builder()
                .code(null)
                .state(TEST_STATE)
                .clientId(TEST_CLIENT_ID)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("code is required");
    }

    @Test
    @DisplayName("Should throw exception when code is empty")
    void shouldThrowExceptionWhenCodeIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> ExchangeCodeForTokenRequest.builder()
                .code("")
                .state(TEST_STATE)
                .clientId(TEST_CLIENT_ID)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("code is required");
    }

    @Test
    @DisplayName("Should throw exception when state is null")
    void shouldThrowExceptionWhenStateIsNull() {
        // When & Then
        assertThatThrownBy(() -> ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state(null)
                .clientId(TEST_CLIENT_ID)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("state is required");
    }

    @Test
    @DisplayName("Should throw exception when state is empty")
    void shouldThrowExceptionWhenStateIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state("")
                .clientId(TEST_CLIENT_ID)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("state is required");
    }

    @Test
    @DisplayName("Should throw exception when clientId is null")
    void shouldThrowExceptionWhenClientIdIsNull() {
        // When & Then
        assertThatThrownBy(() -> ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state(TEST_STATE)
                .clientId(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId is required");
    }

    @Test
    @DisplayName("Should throw exception when clientId is empty")
    void shouldThrowExceptionWhenClientIdIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state(TEST_STATE)
                .clientId("")
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("clientId is required");
    }

    @Test
    @DisplayName("Should build instance with optional field set to null")
    void shouldBuildInstanceWithOptionalFieldSetToNullWhenOptionalFieldIsSetToNull() {
        // Given
        ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state(TEST_STATE)
                .redirectUri(null)
                .clientId(TEST_CLIENT_ID)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getCode()).isEqualTo(TEST_CODE);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
        assertThat(request.getRedirectUri()).isNull();
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
    }

    @Test
    @DisplayName("Should build instance without optional field")
    void shouldBuildInstanceWithoutOptionalFieldWhenOptionalFieldIsNotSet() {
        // Given
        ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                .code(TEST_CODE)
                .state(TEST_STATE)
                .clientId(TEST_CLIENT_ID)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getCode()).isEqualTo(TEST_CODE);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
        assertThat(request.getRedirectUri()).isNull();
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        ExchangeCodeForTokenRequest.Builder builder1 = ExchangeCodeForTokenRequest.builder();
        ExchangeCodeForTokenRequest.Builder builder2 = ExchangeCodeForTokenRequest.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        ExchangeCodeForTokenRequest.Builder builder = ExchangeCodeForTokenRequest.builder();

        // When
        ExchangeCodeForTokenRequest request1 = builder
                .code("code-1")
                .state("state-1")
                .clientId("client-1")
                .build();

        ExchangeCodeForTokenRequest request2 = builder
                .code("code-2")
                .state("state-2")
                .clientId("client-2")
                .build();

        // Then
        assertThat(request1).isNotNull();
        assertThat(request2).isNotNull();
        assertThat(request1.getCode()).isEqualTo("code-1");
        assertThat(request2.getCode()).isEqualTo("code-2");
        assertThat(request1.getState()).isEqualTo("state-1");
        assertThat(request2.getState()).isEqualTo("state-2");
    }
}
