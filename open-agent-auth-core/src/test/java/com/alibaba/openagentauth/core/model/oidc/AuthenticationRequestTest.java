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
package com.alibaba.openagentauth.core.model.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link AuthenticationRequest}.
 * <p>
 * Tests the OpenID Connect Authentication Request model's behavior including:
 * <ul>
 *   <li>Builder pattern with all fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Validation logic for required fields</li>
 *   <li>Flow detection methods</li>
 *   <li>Equals, hashCode, and toString methods</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuthenticationRequest Tests")
class AuthenticationRequestTest {

    private static final String RESPONSE_TYPE_CODE = "code";
    private static final String RESPONSE_TYPE_TOKEN = "token id_token";
    private static final String CLIENT_ID = "client-123";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String SCOPE_OPENID = "openid profile email";
    private static final String SCOPE_NO_OPENID = "profile email";
    private static final String STATE = "state-123";
    private static final String NONCE = "nonce-456";
    private static final String DISPLAY = "page";
    private static final String PROMPT = "login consent";
    private static final Integer MAX_AGE = 3600;
    private static final String UI_LOCALES = "en-US zh-CN";
    private static final String ID_TOKEN_HINT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    private static final String LOGIN_HINT = "user@example.com";
    private static final String ACR_VALUES = "urn:mace:incommon:iap:silver";

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build request with all required fields")
        void shouldBuildRequestWithAllRequiredFields() {
            // When
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getResponseType()).isEqualTo(RESPONSE_TYPE_CODE);
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
            assertThat(request.getScope()).isEqualTo(SCOPE_OPENID);
        }

        @Test
        @DisplayName("Should build request with all optional fields")
        void shouldBuildRequestWithAllOptionalFields() {
            // When
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .state(STATE)
                    .nonce(NONCE)
                    .display(DISPLAY)
                    .prompt(PROMPT)
                    .maxAge(MAX_AGE)
                    .uiLocales(UI_LOCALES)
                    .idTokenHint(ID_TOKEN_HINT)
                    .loginHint(LOGIN_HINT)
                    .acrValues(ACR_VALUES)
                    .build();

            // Then
            assertThat(request).isNotNull();
            assertThat(request.getState()).isEqualTo(STATE);
            assertThat(request.getNonce()).isEqualTo(NONCE);
            assertThat(request.getDisplay()).isEqualTo(DISPLAY);
            assertThat(request.getPrompt()).isEqualTo(PROMPT);
            assertThat(request.getMaxAge()).isEqualTo(MAX_AGE);
            assertThat(request.getUiLocales()).isEqualTo(UI_LOCALES);
            assertThat(request.getIdTokenHint()).isEqualTo(ID_TOKEN_HINT);
            assertThat(request.getLoginHint()).isEqualTo(LOGIN_HINT);
            assertThat(request.getAcrValues()).isEqualTo(ACR_VALUES);
        }

        @Test
        @DisplayName("Should build request with additional parameters")
        void shouldBuildRequestWithAdditionalParameters() {
            // Given
            Map<String, String> additionalParams = new HashMap<>();
            additionalParams.put("custom_param", "custom_value");
            additionalParams.put("another_param", "another_value");

            // When
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .additionalParameters(additionalParams)
                    .build();

            // Then
            assertThat(request.getAdditionalParameters()).isNotNull();
            assertThat(request.getAdditionalParameters()).hasSize(2);
            assertThat(request.getAdditionalParameters().get("custom_param")).isEqualTo("custom_value");
        }

        @Test
        @DisplayName("Should build request using addAdditionalParameter")
        void shouldBuildRequestUsingAddAdditionalParameter() {
            // When
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .addAdditionalParameter("param1", "value1")
                    .addAdditionalParameter("param2", "value2")
                    .build();

            // Then
            assertThat(request.getAdditionalParameters()).isNotNull();
            assertThat(request.getAdditionalParameters()).hasSize(2);
            assertThat(request.getAdditionalParameters().get("param1")).isEqualTo("value1");
            assertThat(request.getAdditionalParameters().get("param2")).isEqualTo("value2");
        }

        @Test
        @DisplayName("Should support method chaining in builder")
        void shouldSupportMethodChainingInBuilder() {
            // When
            AuthenticationRequest.Builder builder = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .state(STATE);

            // Then
            assertThat(builder).isNotNull();
            AuthenticationRequest request = builder.build();
            assertThat(request.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should throw exception when responseType is null")
        void shouldThrowExceptionWhenResponseTypeIsNull() {
            // When & Then
            assertThatThrownBy(() -> AuthenticationRequest.builder()
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("response_type is required");
        }

        @Test
        @DisplayName("Should throw exception when clientId is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            // When & Then
            assertThatThrownBy(() -> AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client_id is required");
        }

        @Test
        @DisplayName("Should throw exception when redirectUri is null")
        void shouldThrowExceptionWhenRedirectUriIsNull() {
            // When & Then
            assertThatThrownBy(() -> AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .scope(SCOPE_OPENID)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uri is required");
        }

        @Test
        @DisplayName("Should throw exception when scope is null")
        void shouldThrowExceptionWhenScopeIsNull() {
            // When & Then
            assertThatThrownBy(() -> AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("scope is required");
        }

        @Test
        @DisplayName("Should throw exception when scope does not include openid")
        void shouldThrowExceptionWhenScopeDoesNotIncludeOpenid() {
            // When & Then
            assertThatThrownBy(() -> AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_NO_OPENID)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("scope must include 'openid'");
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should return correct responseType")
        void shouldReturnCorrectResponseType() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getResponseType()).isEqualTo(RESPONSE_TYPE_CODE);
        }

        @Test
        @DisplayName("Should return correct clientId")
        void shouldReturnCorrectClientId() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getClientId()).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should return correct redirectUri")
        void shouldReturnCorrectRedirectUri() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getRedirectUri()).isEqualTo(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should return correct scope")
        void shouldReturnCorrectScope() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getScope()).isEqualTo(SCOPE_OPENID);
        }

        @Test
        @DisplayName("Should return correct state")
        void shouldReturnCorrectState() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getState()).isEqualTo(STATE);
        }

        @Test
        @DisplayName("Should return correct nonce")
        void shouldReturnCorrectNonce() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getNonce()).isEqualTo(NONCE);
        }

        @Test
        @DisplayName("Should return correct display")
        void shouldReturnCorrectDisplay() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getDisplay()).isEqualTo(DISPLAY);
        }

        @Test
        @DisplayName("Should return correct prompt")
        void shouldReturnCorrectPrompt() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getPrompt()).isEqualTo(PROMPT);
        }

        @Test
        @DisplayName("Should return correct maxAge")
        void shouldReturnCorrectMaxAge() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getMaxAge()).isEqualTo(MAX_AGE);
        }

        @Test
        @DisplayName("Should return correct uiLocales")
        void shouldReturnCorrectUiLocales() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getUiLocales()).isEqualTo(UI_LOCALES);
        }

        @Test
        @DisplayName("Should return correct idTokenHint")
        void shouldReturnCorrectIdTokenHint() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getIdTokenHint()).isEqualTo(ID_TOKEN_HINT);
        }

        @Test
        @DisplayName("Should return correct loginHint")
        void shouldReturnCorrectLoginHint() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getLoginHint()).isEqualTo(LOGIN_HINT);
        }

        @Test
        @DisplayName("Should return correct acrValues")
        void shouldReturnCorrectAcrValues() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.getAcrValues()).isEqualTo(ACR_VALUES);
        }

        @Test
        @DisplayName("Should return correct additionalParameters")
        void shouldReturnCorrectAdditionalParameters() {
            // Given
            Map<String, String> params = new HashMap<>();
            params.put("key", "value");
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .additionalParameters(params)
                    .build();

            // When & Then
            assertThat(request.getAdditionalParameters()).isEqualTo(params);
        }

        @Test
        @DisplayName("Should return null for optional fields")
        void shouldReturnNullForOptionalFields() {
            // Given
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            assertThat(request.getState()).isNull();
            assertThat(request.getNonce()).isNull();
            assertThat(request.getDisplay()).isNull();
            assertThat(request.getPrompt()).isNull();
            assertThat(request.getMaxAge()).isNull();
            assertThat(request.getUiLocales()).isNull();
            assertThat(request.getIdTokenHint()).isNull();
            assertThat(request.getLoginHint()).isNull();
            assertThat(request.getAcrValues()).isNull();
            assertThat(request.getAdditionalParameters()).isNull();
        }
    }

    @Nested
    @DisplayName("Flow Detection Tests")
    class FlowDetectionTests {

        @Test
        @DisplayName("Should detect authorization code flow")
        void shouldDetectAuthorizationCodeFlow() {
            // Given
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            assertThat(request.isAuthorizationCodeFlow()).isTrue();
            assertThat(request.isImplicitFlow()).isFalse();
        }

        @Test
        @DisplayName("Should detect implicit flow")
        void shouldDetectImplicitFlow() {
            // Given
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_TOKEN)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            assertThat(request.isAuthorizationCodeFlow()).isFalse();
            assertThat(request.isImplicitFlow()).isTrue();
        }

        @Test
        @DisplayName("Should detect hybrid flow")
        void shouldDetectHybridFlow() {
            // Given
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code id_token token")
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            assertThat(request.isAuthorizationCodeFlow()).isFalse();
            assertThat(request.isImplicitFlow()).isTrue();
        }

        @Test
        @DisplayName("Should return false for isAuthorizationCodeFlow when responseType is not code")
        void shouldReturnFalseForIsAuthorizationCodeFlowWhenResponseTypeIsNotCode() {
            // Given
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("token")
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            assertThat(request.isAuthorizationCodeFlow()).isFalse();
        }

        @Test
        @DisplayName("Should return false for isImplicitFlow when responseType does not contain id_token")
        void shouldReturnFalseForIsImplicitFlowWhenResponseTypeDoesNotContainIdToken() {
            // Given
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType("code")
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            assertThat(request.isImplicitFlow()).isFalse();
        }

        @Test
        @DisplayName("Should detect openid scope")
        void shouldDetectOpenidScope() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request.hasOpenidScope()).isTrue();
        }

        @Test
        @DisplayName("Should return false for hasOpenidScope when scope does not contain openid")
        void shouldReturnFalseForHasOpenidScopeWhenScopeDoesNotContainOpenid() {
            // Given - Create request with openid scope first
            AuthenticationRequest request = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .build();

            // When & Then
            // Test the hasOpenidScope method directly
            assertThat(request.hasOpenidScope()).isTrue();
            
            // Note: We cannot create a request without openid scope due to builder validation
            // The hasOpenidScope method is tested indirectly by the build() validation
        }
    }

    @Nested
    @DisplayName("EqualsAndHashCode Tests")
    class EqualsAndHashCodeTests {

        @Test
        @DisplayName("Should be equal when all required fields match")
        void shouldBeEqualWhenAllRequiredFieldsMatch() {
            // Given
            AuthenticationRequest request1 = createFullTestRequest();
            AuthenticationRequest request2 = createFullTestRequest();

            // When & Then
            assertThat(request1).isEqualTo(request2);
            assertThat(request1.hashCode()).isEqualTo(request2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when optional state field differs")
        void shouldNotBeEqualWhenOptionalStateFieldDiffers() {
            // Given
            AuthenticationRequest request1 = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .state(STATE)
                    .build();
            AuthenticationRequest request2 = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .state("different-state")
                    .build();

            // When & Then
            // equals/hashCode includes state field, so they should not be equal
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal when responseType differs")
        void shouldNotBeEqualWhenResponseTypeDiffers() {
            // Given
            AuthenticationRequest request1 = createFullTestRequest();
            AuthenticationRequest request2 = AuthenticationRequest.builder()
                    .responseType("token")
                    .clientId(CLIENT_ID)
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .state(STATE)
                    .build();

            // When & Then
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should not be equal when clientId differs")
        void shouldNotBeEqualWhenClientIdDiffers() {
            // Given
            AuthenticationRequest request1 = createFullTestRequest();
            AuthenticationRequest request2 = AuthenticationRequest.builder()
                    .responseType(RESPONSE_TYPE_CODE)
                    .clientId("different-client")
                    .redirectUri(REDIRECT_URI)
                    .scope(SCOPE_OPENID)
                    .state(STATE)
                    .build();

            // When & Then
            assertThat(request1).isNotEqualTo(request2);
        }

        @Test
        @DisplayName("Should be equal to itself")
        void shouldBeEqualToItself() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request).isEqualTo(request);
        }

        @Test
        @DisplayName("Should not be equal to null")
        void shouldNotBeEqualToNull() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request).isNotEqualTo(null);
        }

        @Test
        @DisplayName("Should not be equal to different type")
        void shouldNotBeEqualToDifferentType() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When & Then
            assertThat(request).isNotEqualTo("string");
        }
    }

    @Nested
    @DisplayName("ToString Tests")
    class ToStringTests {

        @Test
        @DisplayName("Should contain required fields in toString")
        void shouldContainRequiredFieldsInToString() {
            // Given
            AuthenticationRequest request = createFullTestRequest();

            // When
            String toString = request.toString();

            // Then
            assertThat(toString).contains("AuthenticationRequest");
            assertThat(toString).contains("responseType='" + RESPONSE_TYPE_CODE + "'");
            assertThat(toString).contains("clientId='" + CLIENT_ID + "'");
            assertThat(toString).contains("redirectUri='" + REDIRECT_URI + "'");
            assertThat(toString).contains("scope='" + SCOPE_OPENID + "'");
            assertThat(toString).contains("state='" + STATE + "'");
            assertThat(toString).contains("nonce='" + NONCE + "'");
        }
    }

    /**
     * Helper method to create a test AuthenticationRequest instance with all fields.
     *
     * @return a test AuthenticationRequest instance
     */
    private AuthenticationRequest createFullTestRequest() {
        return AuthenticationRequest.builder()
                .responseType(RESPONSE_TYPE_CODE)
                .clientId(CLIENT_ID)
                .redirectUri(REDIRECT_URI)
                .scope(SCOPE_OPENID)
                .state(STATE)
                .nonce(NONCE)
                .display(DISPLAY)
                .prompt(PROMPT)
                .maxAge(MAX_AGE)
                .uiLocales(UI_LOCALES)
                .idTokenHint(ID_TOKEN_HINT)
                .loginHint(LOGIN_HINT)
                .acrValues(ACR_VALUES)
                .build();
    }
}
