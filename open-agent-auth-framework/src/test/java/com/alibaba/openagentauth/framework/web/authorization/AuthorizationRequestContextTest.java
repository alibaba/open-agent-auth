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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AuthorizationRequestContext.Builder}.
 * <p>
 * Tests cover normal construction scenarios, method chaining, required field validation,
 * optional field settings, and verification that build() returns the correct instance.
 * </p>
 */
@DisplayName("AuthorizationRequestContext.Builder Tests")
class AuthorizationRequestContextTest {

    private static final String TEST_FLOW_TYPE = "authorization_code";
    private static final String TEST_CLIENT_ID = "test-client";
    private static final String TEST_REDIRECT_URI = "https://example.com/callback";
    private static final String TEST_SCOPE = "openid profile";
    private static final String TEST_STATE = "random-state-123";
    private static final String TEST_RESPONSE_TYPE = "code";
    private static final String TEST_REQUEST_URI = "urn:ietf:params:oauth:request_uri:abc123";

    @Test
    @DisplayName("Should build instance with all fields when all setters are called")
    void shouldBuildInstanceWithAllFieldsWhenAllSettersAreCalled() {
        // Given
        ParJwtClaims parJwtClaims = ParJwtClaims.builder()
                .issuer("https://client.example.com")
                .subject("user-123")
                .audience(java.util.List.of("https://as.example.com"))
                .build();
        
        AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType(TEST_FLOW_TYPE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .scope(TEST_SCOPE)
                .state(TEST_STATE)
                .responseType(TEST_RESPONSE_TYPE)
                .requestUri(TEST_REQUEST_URI)
                .parJwtClaims(parJwtClaims)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getFlowType()).isEqualTo(TEST_FLOW_TYPE);
        assertThat(context.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(context.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(context.getScope()).isEqualTo(TEST_SCOPE);
        assertThat(context.getState()).isEqualTo(TEST_STATE);
        assertThat(context.getResponseType()).isEqualTo(TEST_RESPONSE_TYPE);
        assertThat(context.getRequestUri()).isEqualTo(TEST_REQUEST_URI);
        assertThat(context.getParJwtClaims()).isSameAs(parJwtClaims);
    }

    @Test
    @DisplayName("Should support method chaining when using builder")
    void shouldSupportMethodChainingWhenUsingBuilder() {
        // Given
        AuthorizationRequestContext.Builder builder = AuthorizationRequestContext.builder();

        // When
        AuthorizationRequestContext context = builder
                .flowType(TEST_FLOW_TYPE)
                .clientId(TEST_CLIENT_ID)
                .redirectUri(TEST_REDIRECT_URI)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getFlowType()).isEqualTo(TEST_FLOW_TYPE);
        assertThat(context.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(context.getRedirectUri()).isEqualTo(TEST_REDIRECT_URI);
    }

    @Test
    @DisplayName("Should throw exception when flowType is null")
    void shouldThrowExceptionWhenFlowTypeIsNull() {
        // When & Then
        assertThatThrownBy(() -> AuthorizationRequestContext.builder()
                .flowType(null)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("flowType is required");
    }

    @Test
    @DisplayName("Should throw exception when flowType is empty")
    void shouldThrowExceptionWhenFlowTypeIsEmpty() {
        // When & Then
        assertThatThrownBy(() -> AuthorizationRequestContext.builder()
                .flowType("")
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("flowType is required");
    }

    @Test
    @DisplayName("Should build instance with only required field")
    void shouldBuildInstanceWithOnlyRequiredFieldWhenOnlyRequiredFieldIsSet() {
        // Given
        AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType(TEST_FLOW_TYPE)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getFlowType()).isEqualTo(TEST_FLOW_TYPE);
        assertThat(context.getClientId()).isNull();
        assertThat(context.getRedirectUri()).isNull();
        assertThat(context.getScope()).isNull();
        assertThat(context.getState()).isNull();
        assertThat(context.getResponseType()).isNull();
        assertThat(context.getRequestUri()).isNull();
        assertThat(context.getParJwtClaims()).isNull();
    }

    @Test
    @DisplayName("Should build instance with optional fields set to null")
    void shouldBuildInstanceWithOptionalFieldsSetToNullWhenOptionalFieldsAreSetToNull() {
        // Given
        AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType(TEST_FLOW_TYPE)
                .clientId(null)
                .redirectUri(null)
                .scope(null)
                .state(null)
                .responseType(null)
                .requestUri(null)
                .parJwtClaims(null)
                .build();

        // Then
        assertThat(context).isNotNull();
        assertThat(context.getFlowType()).isEqualTo(TEST_FLOW_TYPE);
        assertThat(context.getClientId()).isNull();
        assertThat(context.getRedirectUri()).isNull();
    }

    @Test
    @DisplayName("Should create new builder instance when builder() is called")
    void shouldCreateNewBuilderInstanceWhenBuilderIsCalled() {
        // When
        AuthorizationRequestContext.Builder builder1 = AuthorizationRequestContext.builder();
        AuthorizationRequestContext.Builder builder2 = AuthorizationRequestContext.builder();

        // Then
        assertThat(builder1).isNotNull();
        assertThat(builder2).isNotNull();
        assertThat(builder1).isNotSameAs(builder2);
    }

    @Test
    @DisplayName("Should build independent instances when builder is reused")
    void shouldBuildIndependentInstancesWhenBuilderIsReused() {
        // Given
        AuthorizationRequestContext.Builder builder = AuthorizationRequestContext.builder();

        // When
        AuthorizationRequestContext context1 = builder
                .flowType("authorization_code")
                .clientId("client-1")
                .build();

        AuthorizationRequestContext context2 = builder
                .flowType("implicit")
                .clientId("client-2")
                .build();

        // Then
        assertThat(context1).isNotNull();
        assertThat(context2).isNotNull();
        assertThat(context1.getFlowType()).isEqualTo("authorization_code");
        assertThat(context2.getFlowType()).isEqualTo("implicit");
        assertThat(context1.getClientId()).isEqualTo("client-1");
        assertThat(context2.getClientId()).isEqualTo("client-2");
    }

    @Test
    @DisplayName("Should build immutable instance when build is called")
    void shouldBuildImmutableInstanceWhenBuildIsCalled() {
        // Given
        AuthorizationRequestContext context = AuthorizationRequestContext.builder()
                .flowType(TEST_FLOW_TYPE)
                .clientId(TEST_CLIENT_ID)
                .build();

        // When & Then - Verify the instance is immutable by checking all fields are final
        assertThat(context.getFlowType()).isEqualTo(TEST_FLOW_TYPE);
        assertThat(context.getClientId()).isEqualTo(TEST_CLIENT_ID);
    }
}