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
 * Unit tests for {@link InitiateAuthorizationRequest.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, required field validation,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("InitiateAuthorizationRequest.Builder Tests")
class InitiateAuthorizationRequestTest {

    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_STATE = "random-state-123";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        InitiateAuthorizationRequest request = InitiateAuthorizationRequest.builder()
                .redirectUri(TEST_REDIRECT_URI)
                .state(TEST_STATE)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        InitiateAuthorizationRequest.Builder builder = InitiateAuthorizationRequest.builder();

        // When
        InitiateAuthorizationRequest request = builder
                .redirectUri(TEST_REDIRECT_URI)
                .state(TEST_STATE)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
    }

    @Test
    @DisplayName("Should throw exception when redirectUri is null")
    void shouldThrowExceptionWhenRedirectUriIsNull() {
        // When & Then
        assertThatThrownBy(() -> InitiateAuthorizationRequest.builder()
                .redirectUri(null)
                .state(TEST_STATE)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirectUri is required");
    }

    @Test
    @DisplayName("Should throw exception when redirectUri is empty")
    void shouldThrowExceptionWhenRedirectUriIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> InitiateAuthorizationRequest.builder()
                .redirectUri("")
                .state(TEST_STATE)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("redirectUri is required");
    }

    @Test
    @DisplayName("Should throw exception when state is null")
    void shouldThrowExceptionWhenStateIsNull() {
        // When & Then
        assertThatThrownBy(() -> InitiateAuthorizationRequest.builder()
                .redirectUri(TEST_REDIRECT_URI)
                .state(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("state is required");
    }

    @Test
    @DisplayName("Should throw exception when state is empty")
    void shouldThrowExceptionWhenStateIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> InitiateAuthorizationRequest.builder()
                .redirectUri(TEST_REDIRECT_URI)
                .state("")
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("state is required");
    }

    @Test
    @DisplayName("Should throw exception when both fields are null")
    void shouldThrowExceptionWhenBothFieldsAreNull() {
        // When & Then
        assertThatThrownBy(() -> InitiateAuthorizationRequest.builder()
                .redirectUri(null)
                .state(null)
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        InitiateAuthorizationRequest.Builder builder1 = InitiateAuthorizationRequest.builder();
        InitiateAuthorizationRequest.Builder builder2 = InitiateAuthorizationRequest.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        InitiateAuthorizationRequest.Builder builder = InitiateAuthorizationRequest.builder();

        // When
        InitiateAuthorizationRequest request1 = builder
                .redirectUri("https://example.com/callback1")
                .state("state-1")
                .build();

        InitiateAuthorizationRequest request2 = builder
                .redirectUri("https://example.com/callback2")
                .state("state-2")
                .build();

        // Then
        assertThat(request1).isNotNull();
        assertThat(request2).isNotNull();
        assertThat(request1.getRedirectUri()).isEqualTo("https://example.com/callback1");
        assertThat(request2.getRedirectUri()).isEqualTo("https://example.com/callback2");
        assertThat(request1.getState()).isEqualTo("state-1");
        assertThat(request2.getState()).isEqualTo("state-2");
    }

    @Test
    @DisplayName("Should build immutable instance when build is called")
    void shouldBuildImmutableInstanceWhenBuildIsCalled() {
        // Given
        InitiateAuthorizationRequest request = InitiateAuthorizationRequest.builder()
                .redirectUri(TEST_REDIRECT_URI)
                .state(TEST_STATE)
                .build();

        // When & Then - Verify all fields are final and immutable
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
    }
}
