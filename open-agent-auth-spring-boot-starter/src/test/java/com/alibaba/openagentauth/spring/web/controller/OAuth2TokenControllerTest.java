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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest;
import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.spring.util.OAuth2ClientAuthenticator;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2TokenController}.
 * <p>
 * Tests the OAuth 2.0 Token controller's behavior including:
 * <ul>
 *   <li>Successful token issuance with Basic Auth</li>
 *   <li>Client authentication (RFC 6749 Section 2.3.1)</li>
 *   <li>Authorization code grant flow</li>
 *   <li>Error handling for invalid requests</li>
 *   <li>Exception handling</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2TokenController Tests")
class OAuth2TokenControllerTest {

    @Mock
    private FrameworkOAuth2TokenServer tokenServer;

    @Mock
    private OAuth2ClientStore clientStore;

    @Mock
    private OAuth2ClientAuthenticator clientAuthenticator;

    private OAuth2TokenController controller;

    private static final String GRANT_TYPE = "authorization_code";
    private static final String CODE = "auth-code-123";
    private static final String REDIRECT_URI = "https://example.com/callback";
    private static final String CLIENT_ID = "client-456";
    private static final String CLIENT_SECRET = "secret-789";
    private static final String ACCESS_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.access";
    private static final String TOKEN_TYPE = "Bearer";
    private static final int EXPIRES_IN = 3600;
    private static final String SCOPE = "openid profile";

    @BeforeEach
    void setUp() {
        controller = new OAuth2TokenController(tokenServer, clientStore, clientAuthenticator);
        
        // Mock client authenticator to return valid client ID
        lenient().when(clientAuthenticator.authenticateClient(any(), any(), eq(clientStore)))
                .thenReturn(CLIENT_ID);
        
        // Setup default client in DCR store with lenient() to avoid UnnecessaryStubbingException
        // for tests that don't use this client (e.g., missing auth header tests)
        OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .tokenEndpointAuthMethod("client_secret_basic")
                .build();
        lenient().when(clientStore.retrieve(CLIENT_ID)).thenReturn(client);
    }

    private String buildBasicAuthHeader(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }

    /**
     * Builds a MultiValueMap representing a standard token request body.
     */
    private MultiValueMap<String, String> buildTokenRequestBody(String grantType, String code, String redirectUri) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        if (grantType != null) body.add("grant_type", grantType);
        if (code != null) body.add("code", code);
        if (redirectUri != null) body.add("redirect_uri", redirectUri);
        return body;
    }

    @Nested
    @DisplayName("Token Endpoint Tests")
    class TokenEndpointTests {

        @Test
        @DisplayName("Should issue token successfully with valid Basic Auth")
        void shouldIssueTokenSuccessfullyWithValidBasicAuth() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn((long) EXPIRES_IN)
                    .scope(SCOPE)
                    .build();
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(tokenResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.token(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("access_token")).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getBody().get("token_type")).isEqualTo(TOKEN_TYPE);
            assertThat(response.getBody().get("expires_in")).isEqualTo((long) EXPIRES_IN);
            assertThat(response.getBody().get("scope")).isEqualTo(SCOPE);
            
            verify(tokenServer).issueToken(any(TokenRequest.class), eq(CLIENT_ID));
        }

        @Test
        @DisplayName("Should include id_token in response when present")
        void shouldIncludeIdTokenInResponseWhenPresent() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            String idToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.id_token";
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn((long) EXPIRES_IN)
                    .scope(SCOPE)
                    .idToken(idToken)
                    .build();
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(tokenResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.token(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("id_token")).isEqualTo(idToken);
            assertThat(response.getBody().get("access_token")).isEqualTo(ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should not include id_token in response when not present")
        void shouldNotIncludeIdTokenInResponseWhenNotPresent() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn((long) EXPIRES_IN)
                    .scope(SCOPE)
                    .build();
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(tokenResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.token(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody()).doesNotContainKey("id_token");
        }

        @Test
        @DisplayName("Should issue token with null scope when scope is not provided")
        void shouldIssueTokenWithNullScopeWhenScopeIsNotProvided() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn((long) EXPIRES_IN)
                    .scope(null)
                    .build();
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(tokenResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controller.token(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("access_token")).isEqualTo(ACCESS_TOKEN);
            assertThat(response.getBody().get("token_type")).isEqualTo(TOKEN_TYPE);
            assertThat(response.getBody().get("expires_in")).isEqualTo((long) EXPIRES_IN);
            assertThat(response.getBody().get("scope")).isNull();
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when OAuth2 exception occurs")
        void shouldReturnBadRequestWhenOAuth2ExceptionOccurs() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_grant", "Invalid authorization code"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                    .hasFieldOrPropertyWithValue("errorDescription", "Invalid authorization code");
        }

        @Test
        @DisplayName("Should throw RuntimeException when unexpected exception occurs")
        void shouldReturnInternalServerErrorWhenUnexpectedExceptionOccurs() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenThrow(new RuntimeException("Unexpected error"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Unexpected error");
        }
    }

    @Nested
    @DisplayName("Client Authentication Tests")
    class ClientAuthenticationTests {

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when Authorization header is missing")
        void shouldReturnBadRequestWhenAuthorizationHeaderIsMissing() {
            // Given
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(isNull(), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Authorization header is missing"));
            
            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, null))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Authorization header is missing");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when Authorization header has invalid scheme")
        void shouldReturnBadRequestWhenAuthorizationHeaderHasInvalidScheme() {
            // Given
            String invalidAuthHeader = "Bearer " + buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET).substring(6);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(invalidAuthHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Only Basic authentication is supported"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, invalidAuthHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Only Basic authentication is supported");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when Authorization header has invalid Base64")
        void shouldReturnBadRequestWhenAuthorizationHeaderHasInvalidBase64() {
            // Given
            String invalidAuthHeader = "Basic invalid_base64!!!";
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(invalidAuthHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Invalid Base64 encoding"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, invalidAuthHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Invalid Base64 encoding");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when credentials format is invalid")
        void shouldReturnBadRequestWhenCredentialsFormatIsInvalid() {
            // Given
            String credentials = "invalid_credentials_without_colon";
            String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String authHeader = "Basic " + encoded;
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(authHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Invalid credentials format"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Invalid credentials format");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client ID is empty")
        void shouldReturnBadRequestWhenClientIdIsEmpty() {
            // Given
            String credentials = ":" + CLIENT_SECRET;
            String encoded = Base64.getEncoder().encodeToString(credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String authHeader = "Basic " + encoded;
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(authHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Client ID is required"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Client ID is required");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client is not registered")
        void shouldReturnBadRequestWhenClientIsNotRegistered() {
            // Given
            String unregisteredClientId = "unregistered-client";
            String authHeader = buildBasicAuthHeader(unregisteredClientId, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(authHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Client not registered"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Client not registered");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client secret is invalid")
        void shouldReturnBadRequestWhenClientSecretIsInvalid() {
            // Given
            String wrongSecret = "wrong-secret";
            String authHeader = buildBasicAuthHeader(CLIENT_ID, wrongSecret);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(authHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Invalid client secret"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Invalid client secret");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client has no secret configured")
        void shouldReturnBadRequestWhenClientHasNoSecretConfigured() {
            // Given
            String publicClientId = "public-client";
            String authHeader = buildBasicAuthHeader(publicClientId, "any-secret");
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(authHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Client is not configured for authentication"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Client is not configured for authentication");
        }

        @Test
        @DisplayName("Should throw FrameworkOAuth2TokenException when client uses unsupported auth method")
        void shouldReturnBadRequestWhenClientUsesUnsupportedAuthMethod() {
            // Given
            String jwtAuthClientId = "jwt-auth-client";
            String authHeader = buildBasicAuthHeader(jwtAuthClientId, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            when(clientAuthenticator.authenticateClient(eq(authHeader), any(), eq(clientStore)))
                    .thenThrow(new FrameworkOAuth2TokenException("invalid_client", "Client authentication failed: Unsupported authentication method: private_key_jwt"));

            // When & Then
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client")
                    .hasFieldOrPropertyWithValue("errorDescription", "Client authentication failed: Unsupported authentication method: private_key_jwt");
        }
    }

    @Nested
    @DisplayName("Basic Auth Fallback Tests (null clientAuthenticator)")
    class BasicAuthFallbackTests {

        private OAuth2TokenController controllerWithoutAuthenticator;

        @BeforeEach
        void setUp() {
            controllerWithoutAuthenticator = new OAuth2TokenController(tokenServer, clientStore, null);
        }

        @Test
        @DisplayName("Should authenticate via Basic Auth when clientAuthenticator is null")
        void shouldAuthenticateViaBasicAuthWhenClientAuthenticatorIsNull() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);

            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn((long) EXPIRES_IN)
                    .scope(SCOPE)
                    .build();
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(tokenResponse);

            // When
            ResponseEntity<Map<String, Object>> response = controllerWithoutAuthenticator.token(requestBody, authHeader);

            // Then
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().get("access_token")).isEqualTo(ACCESS_TOKEN);
        }

        @Test
        @DisplayName("Should throw exception when Basic Auth header is missing and clientAuthenticator is null")
        void shouldThrowExceptionWhenBasicAuthHeaderIsMissingAndClientAuthenticatorIsNull() {
            // Given
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controllerWithoutAuthenticator.token(requestBody, null))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client");
        }

        @Test
        @DisplayName("Should throw exception when client secret is wrong and clientAuthenticator is null")
        void shouldThrowExceptionWhenClientSecretIsWrongAndClientAuthenticatorIsNull() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, "wrong-secret");
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);

            // When & Then
            assertThatThrownBy(() -> controllerWithoutAuthenticator.token(requestBody, authHeader))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasFieldOrPropertyWithValue("errorCode", "invalid_client");
        }
    }

    @Nested
    @DisplayName("Token Request Tests")
    class TokenRequestTests {

        @Test
        @DisplayName("Should build token request with all parameters")
        void shouldBuildTokenRequestWithAllParameters() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, REDIRECT_URI);
            
            TokenResponse tokenResponse = TokenResponse.builder()
                    .accessToken(ACCESS_TOKEN)
                    .tokenType(TOKEN_TYPE)
                    .expiresIn((long) EXPIRES_IN)
                    .scope(SCOPE)
                    .build();
            when(tokenServer.issueToken(any(TokenRequest.class), eq(CLIENT_ID)))
                    .thenReturn(tokenResponse);

            // When
            controller.token(requestBody, authHeader);

            // Then
            verify(tokenServer).issueToken(any(TokenRequest.class), eq(CLIENT_ID));
        }

        @Test
        @DisplayName("Should throw IllegalStateException when code is null")
        void shouldHandleTokenRequestWithNullCode() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, null, REDIRECT_URI);

            // When & Then - TokenRequest.Builder throws IllegalStateException for null code
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("Should throw IllegalStateException when redirect URI is null")
        void shouldHandleTokenRequestWithNullRedirectUri() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody(GRANT_TYPE, CODE, null);

            // When & Then - TokenRequest.Builder throws IllegalStateException for null redirectUri
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(IllegalStateException.class);
        }

        @Test
        @DisplayName("Should throw IllegalStateException when grant type is not authorization_code")
        void shouldHandleTokenRequestWithDifferentGrantTypes() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            MultiValueMap<String, String> requestBody = buildTokenRequestBody("refresh_token", CODE, REDIRECT_URI);

            // When & Then - TokenRequest.Builder throws IllegalStateException for non-authorization_code grant type
            assertThatThrownBy(() -> controller.token(requestBody, authHeader))
                    .isInstanceOf(IllegalStateException.class);
        }
    }
}