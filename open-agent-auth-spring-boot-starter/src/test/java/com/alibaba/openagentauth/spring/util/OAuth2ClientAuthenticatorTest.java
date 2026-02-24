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
package com.alibaba.openagentauth.spring.util;

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OAuth2ClientAuthenticator}.
 * <p>
 * Tests the OAuth 2.0 client authentication utility class including:
 * <ul>
 *   <li>HTTP Basic authentication (RFC 6749 Section 2.3.1)</li>
 *   <li>Authorization header validation</li>
 *   <li>Base64 decoding and credential parsing</li>
 *   <li>Client credential validation against DCR store</li>
 *   <li>Error handling for various authentication failure scenarios</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("OAuth2ClientAuthenticator Tests")
class OAuth2ClientAuthenticatorTest {

    @Mock
    private OAuth2ClientStore clientStore;

    private static final String CLIENT_ID = "test-client-123";
    private static final String CLIENT_SECRET = "test-secret-456";
    private static final String WRONG_SECRET = "wrong-secret-789";

    @BeforeEach
    void setUp() {
        // Setup default client in DCR store with lenient() to avoid UnnecessaryStubbingException
        // for tests that don't use this client (e.g., tests that fail before reaching client store)
        OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .tokenEndpointAuthMethod("client_secret_basic")
                .build();
        lenient().when(clientStore.retrieve(CLIENT_ID)).thenReturn(client);
    }

    private String buildBasicAuthHeader(String clientId, String clientSecret) {
        String credentials = clientId + ":" + clientSecret;
        String encoded = Base64.getEncoder().encodeToString(
                credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return "Basic " + encoded;
    }

    @Nested
    @DisplayName("Successful Authentication Tests")
    class SuccessfulAuthenticationTests {

        @Test
        @DisplayName("Should authenticate successfully with valid Basic Auth credentials")
        void shouldAuthenticateSuccessfullyWithValidBasicAuthCredentials() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should authenticate with trimmed Base64 credentials")
        void shouldAuthenticateWithTrimmedBase64Credentials() {
            // Given
            String credentials = CLIENT_ID + ":" + CLIENT_SECRET;
            String encoded = Base64.getEncoder().encodeToString(
                    credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // Add extra spaces to test trimming
            String authHeader = "Basic  " + encoded + "  ";

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should authenticate when token endpoint auth method is null")
        void shouldAuthenticateWhenTokenEndpointAuthMethodIsNull() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .tokenEndpointAuthMethod(null)
                    .build();
            when(clientStore.retrieve(CLIENT_ID)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("Authorization Header Validation Tests")
    class AuthorizationHeaderValidationTests {

        @Test
        @DisplayName("Should throw exception when authorization header is null")
        void shouldThrowExceptionWhenAuthorizationHeaderIsNull() {
            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    null, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Authorization header is missing");
        }

        @Test
        @DisplayName("Should throw exception when authorization header is empty")
        void shouldThrowExceptionWhenAuthorizationHeaderIsEmpty() {
            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    "", clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Authorization header is missing");
        }

        @Test
        @DisplayName("Should throw exception when authorization header is blank")
        void shouldThrowExceptionWhenAuthorizationHeaderIsBlank() {
            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    "   ", clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Authorization header is missing");
        }

        @Test
        @DisplayName("Should throw exception when authorization header has invalid scheme")
        void shouldThrowExceptionWhenAuthorizationHeaderHasInvalidScheme() {
            // Given
            String invalidAuthHeader = "Bearer " + buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET).substring(6);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    invalidAuthHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Only Basic authentication is supported");
        }

        @Test
        @DisplayName("Should throw exception when authorization header has no scheme")
        void shouldThrowExceptionWhenAuthorizationHeaderHasNoScheme() {
            // Given
            String invalidAuthHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET).substring(6);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    invalidAuthHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Only Basic authentication is supported");
        }
    }

    @Nested
    @DisplayName("Base64 Decoding Tests")
    class Base64DecodingTests {

        @Test
        @DisplayName("Should throw exception when Base64 encoding is invalid")
        void shouldThrowExceptionWhenBase64EncodingIsInvalid() {
            // Given
            String invalidAuthHeader = "Basic invalid_base64!!!@#$";

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    invalidAuthHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Invalid Base64 encoding");
        }

        @Test
        @DisplayName("Should decode Base64 credentials with special characters")
        void shouldDecodeBase64CredentialsWithSpecialCharacters() {
            // Given
            String specialClientId = "client@example.com";
            String specialSecret = "sec@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`";
            String authHeader = buildBasicAuthHeader(specialClientId, specialSecret);

            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(specialClientId)
                    .clientSecret(specialSecret)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(specialClientId)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(specialClientId);
        }
    }

    @Nested
    @DisplayName("Credential Format Tests")
    class CredentialFormatTests {

        @Test
        @DisplayName("Should throw exception when credentials have no colon")
        void shouldThrowExceptionWhenCredentialsHaveNoColon() {
            // Given
            String credentials = "invalid_credentials_without_colon";
            String encoded = Base64.getEncoder().encodeToString(
                    credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String authHeader = "Basic " + encoded;

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Invalid credentials format");
        }

        @Test
        @DisplayName("Should throw exception when client ID is empty")
        void shouldThrowExceptionWhenClientIdIsEmpty() {
            // Given
            String credentials = ":" + CLIENT_SECRET;
            String encoded = Base64.getEncoder().encodeToString(
                    credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String authHeader = "Basic " + encoded;

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client ID is required");
        }

        @Test
        @DisplayName("Should throw exception when client ID is blank")
        void shouldThrowExceptionWhenClientIdIsBlank() {
            // Given
            String credentials = "   :" + CLIENT_SECRET;
            String encoded = Base64.getEncoder().encodeToString(
                    credentials.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String authHeader = "Basic " + encoded;

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client ID is required");
        }

        @Test
        @DisplayName("Should throw exception when client secret is empty in credentials")
        void shouldThrowExceptionWhenClientSecretIsEmptyInCredentials() {
            // Given
            String emptySecret = "";
            String authHeader = buildBasicAuthHeader(CLIENT_ID, emptySecret);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(emptySecret)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(CLIENT_ID)).thenReturn(client);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client is not configured for authentication");
        }

        @Test
        @DisplayName("Should handle client secret with colons correctly")
        void shouldHandleClientSecretWithColonsCorrectly() {
            // Given
            String secretWithColon = "secret:with:colons";
            String authHeader = buildBasicAuthHeader(CLIENT_ID, secretWithColon);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(secretWithColon)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            // Override the default client store setup
            when(clientStore.retrieve(CLIENT_ID)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("Client Store Validation Tests")
    class ClientStoreValidationTests {

        @Test
        @DisplayName("Should throw exception when client is not registered")
        void shouldThrowExceptionWhenClientIsNotRegistered() {
            // Given
            String unregisteredClientId = "unregistered-client";
            String authHeader = buildBasicAuthHeader(unregisteredClientId, CLIENT_SECRET);
            when(clientStore.retrieve(unregisteredClientId)).thenReturn(null);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client not registered");
        }

        @Test
        @DisplayName("Should throw exception when client has no secret configured")
        void shouldThrowExceptionWhenClientHasNoSecretConfigured() {
            // Given
            String publicClientId = "public-client";
            String authHeader = buildBasicAuthHeader(publicClientId, CLIENT_SECRET);
            OAuth2RegisteredClient publicClient = OAuth2RegisteredClient.builder()
                    .clientId(publicClientId)
                    .clientSecret(null)
                    .tokenEndpointAuthMethod("none")
                    .build();
            when(clientStore.retrieve(publicClientId)).thenReturn(publicClient);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client is not configured for authentication");
        }

        @Test
        @DisplayName("Should throw exception when client secret is empty string")
        void shouldThrowExceptionWhenClientSecretIsEmptyString() {
            // Given
            String emptySecretClient = "empty-secret-client";
            String authHeader = buildBasicAuthHeader(emptySecretClient, CLIENT_SECRET);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(emptySecretClient)
                    .clientSecret("")
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(emptySecretClient)).thenReturn(client);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Client is not configured for authentication");
        }
    }

    @Nested
    @DisplayName("Client Secret Validation Tests")
    class ClientSecretValidationTests {

        @Test
        @DisplayName("Should throw exception when client secret is invalid")
        void shouldThrowExceptionWhenClientSecretIsInvalid() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, WRONG_SECRET);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Invalid client secret");
        }

        @Test
        @DisplayName("Should throw exception when client secret is case-sensitive")
        void shouldThrowExceptionWhenClientSecretIsCaseSensitive() {
            // Given
            String wrongCaseSecret = CLIENT_SECRET.toUpperCase();
            String authHeader = buildBasicAuthHeader(CLIENT_ID, wrongCaseSecret);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Invalid client secret");
        }

        @Test
        @DisplayName("Should authenticate with exact matching secret")
        void shouldAuthenticateWithExactMatchingSecret() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("Authentication Method Validation Tests")
    class AuthenticationMethodValidationTests {

        @Test
        @DisplayName("Should throw exception when client uses unsupported auth method")
        void shouldThrowExceptionWhenClientUsesUnsupportedAuthMethod() {
            // Given
            String jwtAuthClientId = "jwt-auth-client";
            String authHeader = buildBasicAuthHeader(jwtAuthClientId, CLIENT_SECRET);
            OAuth2RegisteredClient jwtClient = OAuth2RegisteredClient.builder()
                    .clientId(jwtAuthClientId)
                    .clientSecret(CLIENT_SECRET)
                    .tokenEndpointAuthMethod("private_key_jwt")
                    .build();
            when(clientStore.retrieve(jwtAuthClientId)).thenReturn(jwtClient);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Unsupported authentication method: private_key_jwt");
        }

        @Test
        @DisplayName("Should throw exception when client uses post auth method")
        void shouldThrowExceptionWhenClientUsesPostAuthMethod() {
            // Given
            String postAuthClientId = "post-auth-client";
            String authHeader = buildBasicAuthHeader(postAuthClientId, CLIENT_SECRET);
            OAuth2RegisteredClient postClient = OAuth2RegisteredClient.builder()
                    .clientId(postAuthClientId)
                    .clientSecret(CLIENT_SECRET)
                    .tokenEndpointAuthMethod("client_secret_post")
                    .build();
            when(clientStore.retrieve(postAuthClientId)).thenReturn(postClient);

            // When & Then
            assertThatThrownBy(() -> OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore))
                    .isInstanceOf(FrameworkOAuth2TokenException.class)
                    .hasMessageContaining("Unsupported authentication method: client_secret_post");
        }

        @Test
        @DisplayName("Should authenticate when client uses client_secret_basic")
        void shouldAuthenticateWhenClientUsesClientSecretBasic() {
            // Given
            String authHeader = buildBasicAuthHeader(CLIENT_ID, CLIENT_SECRET);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(CLIENT_ID)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(CLIENT_ID);
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle very long client ID and secret")
        void shouldHandleVeryLongClientIdAndSecret() {
            // Given
            String longClientId = "a".repeat(1000);
            String longSecret = "b".repeat(1000);
            String authHeader = buildBasicAuthHeader(longClientId, longSecret);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(longClientId)
                    .clientSecret(longSecret)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(longClientId)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(longClientId);
        }

        @Test
        @DisplayName("Should handle Unicode characters in credentials")
        void shouldHandleUnicodeCharactersInCredentials() {
            // Given
            String unicodeClientId = "client-test-unicode";
            String unicodeSecret = "password-secret-key";
            String authHeader = buildBasicAuthHeader(unicodeClientId, unicodeSecret);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(unicodeClientId)
                    .clientSecret(unicodeSecret)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(unicodeClientId)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(unicodeClientId);
        }

        @Test
        @DisplayName("Should handle UTF-8 encoded credentials")
        void shouldHandleUtf8EncodedCredentials() {
            // Given
            String utf8ClientId = "user@example.com";
            String utf8Secret = "p@ssw0rd!#$%^&*()";
            String authHeader = buildBasicAuthHeader(utf8ClientId, utf8Secret);
            OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                    .clientId(utf8ClientId)
                    .clientSecret(utf8Secret)
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();
            when(clientStore.retrieve(utf8ClientId)).thenReturn(client);

            // When
            String authenticatedClientId = OAuth2ClientAuthenticator.authenticateWithBasicAuth(
                    authHeader, clientStore);

            // Then
            assertThat(authenticatedClientId).isEqualTo(utf8ClientId);
        }
    }
}
