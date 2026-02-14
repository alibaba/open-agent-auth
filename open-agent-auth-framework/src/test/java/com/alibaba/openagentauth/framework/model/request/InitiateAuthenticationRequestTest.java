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

/**
 * Unit tests for {@link InitiateAuthenticationRequest.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, optional field settings,
 * and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("InitiateAuthenticationRequest.Builder Tests")
class InitiateAuthenticationRequestTest {

    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_SCOPE = "openid profile email";
    private static final String TEST_STATE = "random-state-123";
    private static final String TEST_NONCE = "random-nonce-456";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        InitiateAuthenticationRequest request = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .state(TEST_STATE)
                .nonce(TEST_NONCE)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getScope()).isEqualTo(TEST_SCOPE);
        assertThat(request.getState()).isEqualTo(TEST_STATE);
        assertThat(request.getNonce()).isEqualTo(TEST_NONCE);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        InitiateAuthenticationRequest.Builder builder = InitiateAuthenticationRequest.builder();

        // When
        InitiateAuthenticationRequest request = builder
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getScope()).isEqualTo(TEST_SCOPE);
    }

    @Test
    @DisplayName("Should build instance with only required fields")
    void shouldBuildInstanceWithOnlyRequiredFieldsWhenOnlyRequiredFieldsAreSet() {
        // Given
        InitiateAuthenticationRequest request = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getScope()).isEqualTo(TEST_SCOPE);
        assertThat(request.getState()).isNull();
        assertThat(request.getNonce()).isNull();
    }

    @Test
    @DisplayName("Should build instance with optional fields set to null")
    void shouldBuildInstanceWithOptionalFieldsSetToNullWhenOptionalFieldsAreSetToNull() {
        // Given
        InitiateAuthenticationRequest request = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .state(null)
                .nonce(null)
                .build();

        // Then
        assertThat(request).isNotNull();
        assertThat(request.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(request.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(request.getScope()).isEqualTo(TEST_SCOPE);
        assertThat(request.getState()).isNull();
        assertThat(request.getNonce()).isNull();
    }

    @Test
    @DisplayName("Should allow setting state after build")
    void shouldAllowSettingStateAfterBuildWhenStateIsSet() {
        // Given
        InitiateAuthenticationRequest request = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .build();

        // When
        request.setState(TEST_STATE);

        // Then
        assertThat(request.getState()).isEqualTo(TEST_STATE);
    }

    @Test
    @DisplayName("Should allow setting nonce after build")
    void shouldAllowSettingNonceAfterBuildWhenNonceIsSet() {
        // Given
        InitiateAuthenticationRequest request = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .build();

        // When
        request.setNonce(TEST_NONCE);

        // Then
        assertThat(request.getNonce()).isEqualTo(TEST_NONCE);
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        InitiateAuthenticationRequest.Builder builder1 = InitiateAuthenticationRequest.builder();
        InitiateAuthenticationRequest.Builder builder2 = InitiateAuthenticationRequest.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        InitiateAuthenticationRequest.Builder builder = InitiateAuthenticationRequest.builder();

        // When
        InitiateAuthenticationRequest request1 = builder
                .clientId("client-1")
                .redirectUri("https://example.com/callback1")
                .scope("openid")
                .state("state-1")
                .build();

        InitiateAuthenticationRequest request2 = builder
                .clientId("client-2")
                .redirectUri("https://example.com/callback2")
                .scope("openid profile")
                .state("state-2")
                .build();

        // Then
        assertThat(request1).isNotNull();
        assertThat(request2).isNotNull();
        assertThat(request1.getClientId()).isEqualTo("client-1");
        assertThat(request2.getClientId()).isEqualTo("client-2");
        assertThat(request1.getState()).isEqualTo("state-1");
        assertThat(request2.getState()).isEqualTo("state-2");
    }

    @Test
    @DisplayName("Should handle different scope values")
    void shouldHandleDifferentScopeValuesWhenDifferentScopesAreSet() {
        // Given
        InitiateAuthenticationRequest request1 = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope("openid")
                .build();

        InitiateAuthenticationRequest request2 = InitiateAuthenticationRequest.builder()
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope("openid profile email")
                .build();

        // Then
        assertThat(request1.getScope()).isEqualTo("openid");
        assertThat(request2.getScope()).isEqualTo("openid profile email");
    }
}
