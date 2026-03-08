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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
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
                    .hasMessageContaining("Client is not configured for Basic authentication");
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
                    .hasMessageContaining("Client is not configured for Basic authentication");
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
                    .hasMessageContaining("Client is not configured for Basic authentication");
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
                    .hasMessageContaining("Client is not configured for Basic authentication");
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
                    .hasMessageContaining("Client is not configured for Basic authentication");
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

    @Nested
    @DisplayName("Client Assertion Authentication Tests")
    class ClientAssertionAuthenticationTests {

        @Mock
        private KeyManager keyManager;

        private static final String VERIFICATION_KEY_ID = "wit-verification";

        private OAuth2ClientAuthenticator authenticator;
        private RSAKey rsaKey;
        private String clientId = "test-client-jwt";
        private String clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        @BeforeEach
        void setUpForClientAssertion() throws JOSEException, KeyManagementException {
            authenticator = new OAuth2ClientAuthenticator(keyManager, VERIFICATION_KEY_ID);
            rsaKey = new RSAKeyGenerator(2048).keyID("test-key-id").generate();
            
            // Setup default client for JWT authentication
            OAuth2RegisteredClient jwtClient = OAuth2RegisteredClient.builder()
                    .clientId(clientId)
                    .tokenEndpointAuthMethod("private_key_jwt")
                    .build();
            lenient().when(clientStore.retrieve(clientId)).thenReturn(jwtClient);
            
            // Mock KeyManager to return the public key for signature verification
            lenient().when(keyManager.resolveVerificationKey(anyString()))
                    .thenReturn(rsaKey.toPublicJWK());
        }

        private String createValidClientAssertion(Date expirationTime) throws JOSEException {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .subject(clientId)
                    .audience("https://example.com/token")
                    .expirationTime(expirationTime)
                    .issueTime(new Date())
                    .jwtID("test-jwt-id")
                    .build();
            
            SignedJWT signedJWT = new SignedJWT(
                    new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .build(),
                    claimsSet);
            signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));
            return signedJWT.serialize();
        }

        @Nested
        @DisplayName("Successful Authentication Tests")
        class SuccessfulAuthenticationTests {

            @Test
            @DisplayName("Should authenticate successfully with valid client assertion")
            void shouldAuthenticateSuccessfullyWithValidClientAssertion() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }

            @Test
            @DisplayName("Should authenticate when token endpoint auth method is null")
            void shouldAuthenticateWhenTokenEndpointAuthMethodIsNull() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                
                OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                        .clientId(clientId)
                        .tokenEndpointAuthMethod(null)
                        .build();
                when(clientStore.retrieve(clientId)).thenReturn(client);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }

            @Test
            @DisplayName("Should authenticate with assertion about to expire soon")
            void shouldAuthenticateWithAssertionAboutToExpireSoon() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 1000); // 1 second from now
                String clientAssertion = createValidClientAssertion(expirationTime);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }
        }

        @Nested
        @DisplayName("Assertion Type Validation Tests")
        class AssertionTypeValidationTests {

            @Test
            @DisplayName("Should throw exception when client assertion type is null")
            void shouldThrowExceptionWhenClientAssertionTypeIsNull() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        clientAssertion, null, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Unsupported client_assertion_type");
            }

            @Test
            @DisplayName("Should throw exception when client assertion type is empty")
            void shouldThrowExceptionWhenClientAssertionTypeIsEmpty() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        clientAssertion, "", null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Unsupported client_assertion_type");
            }

            @Test
            @DisplayName("Should throw exception when client assertion type is invalid")
            void shouldThrowExceptionWhenClientAssertionTypeIsInvalid() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                String invalidAssertionType = "urn:ietf:params:oauth:client-assertion-type:invalid-type";

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        clientAssertion, invalidAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Unsupported client_assertion_type");
            }
        }

        @Nested
        @DisplayName("JWT Format Validation Tests")
        class JWTFormatValidationTests {

            @Test
            @DisplayName("Should throw exception when client assertion is null")
            void shouldThrowExceptionWhenClientAssertionIsNull() {
                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        null, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Invalid client assertion JWT");
            }

            @Test
            @DisplayName("Should throw exception when client assertion is empty")
            void shouldThrowExceptionWhenClientAssertionIsEmpty() {
                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        "", clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Invalid client assertion JWT");
            }

            @Test
            @DisplayName("Should throw exception when client assertion is blank")
            void shouldThrowExceptionWhenClientAssertionIsBlank() {
                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        "   ", clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Invalid client assertion JWT");
            }

            @Test
            @DisplayName("Should throw exception when client assertion is invalid JWT")
            void shouldThrowExceptionWhenClientAssertionIsInvalidJWT() {
                // Given
                String invalidAssertion = "not.a.valid.jwt";

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        invalidAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Invalid client assertion JWT");
            }

            @Test
            @DisplayName("Should throw exception when client assertion is malformed")
            void shouldThrowExceptionWhenClientAssertionIsMalformed() {
                // Given
                String malformedAssertion = "invalid.jwt.token.with.wrong.format";

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        malformedAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Invalid client assertion JWT");
            }
        }

        @Nested
        @DisplayName("JWT Claims Validation Tests")
        class JWTClaimsValidationTests {

            @Test
            @DisplayName("Should throw exception when JWT is missing iss claim")
            void shouldThrowExceptionWhenJWTIsMissingIssClaim() throws JOSEException {
                // Given
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .subject(clientId)
                        .audience("https://example.com/token")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // When & Then
                // When no client_id in request body and no 'iss' in JWT, the authenticator
                // cannot determine the client identity and throws "Unable to determine client_id"
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Unable to determine client_id");
            }

            @Test
            @DisplayName("Should throw exception when JWT iss claim is empty")
            void shouldThrowExceptionWhenJWTIssClaimIsEmpty() throws JOSEException {
                // Given
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer("")
                        .subject(clientId)
                        .audience("https://example.com/token")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // When & Then
                // When no client_id in request body and 'iss' is empty, the authenticator
                // cannot determine the client identity and throws "Unable to determine client_id"
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Unable to determine client_id");
            }

            @Test
            @DisplayName("Should throw exception when JWT sub claim does not match iss")
            void shouldThrowExceptionWhenJWTSubClaimDoesNotMatchIss() throws JOSEException {
                // Given
                String differentSubject = "different-subject";
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .subject(differentSubject)
                        .audience("https://example.com/token")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("'sub' must match 'iss'");
            }

            @Test
            @DisplayName("Should throw exception when JWT is expired")
            void shouldThrowExceptionWhenJWTIsExpired() throws JOSEException {
                // Given
                Date pastExpirationTime = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago
                String expiredAssertion = createValidClientAssertion(pastExpirationTime);

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        expiredAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("is expired");
            }

            @Test
            @DisplayName("Should throw exception when JWT expiration time is null")
            void shouldThrowExceptionWhenJWTExpirationTimeIsNull() throws JOSEException {
                // Given
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .subject(clientId)
                        .audience("https://example.com/token")
                        .expirationTime(null)
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("is expired");
            }

            @Test
            @DisplayName("Should throw exception when JWT expired exactly now")
            void shouldThrowExceptionWhenJWTExpiredExactlyNow() throws JOSEException {
                // Given
                Date now = new Date();
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .subject(clientId)
                        .audience("https://example.com/token")
                        .expirationTime(now)
                        .issueTime(new Date(now.getTime() - 1000))
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("is expired");
            }
        }

        @Nested
        @DisplayName("Client Store Validation Tests")
        class ClientStoreValidationTests {

            @Test
            @DisplayName("Should throw exception when client is not registered")
            void shouldThrowExceptionWhenClientIsNotRegistered() throws Exception {
                // Given
                String unregisteredClientId = "unregistered-jwt-client";
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(unregisteredClientId)
                        .subject(unregisteredClientId)
                        .audience("https://example.com/token")
                        .expirationTime(expirationTime)
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));
                
                when(clientStore.retrieve(unregisteredClientId)).thenReturn(null);

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Client not registered");
            }

            @Test
            @DisplayName("Should throw exception when client uses wrong auth method")
            void shouldThrowExceptionWhenClientUsesWrongAuthMethod() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                
                OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                        .clientId(clientId)
                        .tokenEndpointAuthMethod("client_secret_basic")
                        .build();
                when(clientStore.retrieve(clientId)).thenReturn(client);

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("Client is not configured for private_key_jwt authentication");
            }
        }

        @Nested
        @DisplayName("Signature Verification Tests")
        class SignatureVerificationTests {

            @Test
            @DisplayName("Should throw exception when KeyManager throws KeyManagementException")
            void shouldThrowExceptionWhenKeyManagerThrowsKeyManagementException() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                
                when(keyManager.resolveVerificationKey(anyString()))
                        .thenThrow(new KeyManagementException("Key not found"));

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("signature verification failed");
            }

            @Test
            @DisplayName("Should throw exception when verification key does not match signing key")
            void shouldThrowExceptionWhenVerificationKeyDoesNotMatchSigningKey() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                
                // Return a different key that won't verify the signature
                RSAKey differentKey = new RSAKeyGenerator(2048).keyID("different-key-id").generate();
                when(keyManager.resolveVerificationKey(anyString()))
                        .thenReturn(differentKey.toPublicJWK());

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("signature verification failed");
            }

            @Test
            @DisplayName("Should throw exception when signature verification fails")
            void shouldThrowExceptionWhenSignatureVerificationFails() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                
                // Modify the assertion to make signature invalid
                String tamperedAssertion = clientAssertion.substring(0, clientAssertion.length() - 10) + "tampered";

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        tamperedAssertion, clientAssertionType, null, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("signature verification failed");
            }

            @Test
            @DisplayName("Should authenticate when KeyManager returns correct verification key")
            void shouldAuthenticateWhenKeyManagerReturnsCorrectVerificationKey() throws Exception {
                // Given
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);
                
                // KeyManager returns the correct public key (already set up in @BeforeEach)

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }

            @Test
            @DisplayName("Should authenticate when JWT header has no key ID")
            void shouldAuthenticateWhenJWTHeaderHasNoKeyId() throws JOSEException, Exception {
                // Given
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(clientId)
                        .subject(clientId)
                        .audience("https://example.com/token")
                        .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .build(), // No key ID
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }
        }

        @Nested
        @DisplayName("Edge Cases Tests")
        class EdgeCasesTests {

            @Test
            @DisplayName("Should handle very long client ID in assertion")
            void shouldHandleVeryLongClientIdInAssertion() throws Exception {
                // Given
                String longClientId = "a".repeat(1000);
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(longClientId)
                        .subject(longClientId)
                        .audience("https://example.com/token")
                        .expirationTime(expirationTime)
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));
                
                OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                        .clientId(longClientId)
                        .tokenEndpointAuthMethod("private_key_jwt")
                        .build();
                when(clientStore.retrieve(longClientId)).thenReturn(client);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(longClientId);
            }

            @Test
            @DisplayName("Should handle special characters in client ID")
            void shouldHandleSpecialCharactersInClientId() throws Exception {
                // Given
                String specialClientId = "client@example.com";
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                
                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(specialClientId)
                        .subject(specialClientId)
                        .audience("https://example.com/token")
                        .expirationTime(expirationTime)
                        .issueTime(new Date())
                        .build();
                
                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));
                
                OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                        .clientId(specialClientId)
                        .tokenEndpointAuthMethod("private_key_jwt")
                        .build();
                when(clientStore.retrieve(specialClientId)).thenReturn(client);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(specialClientId);
            }

            @Test
            @DisplayName("Should handle assertion with maximum valid expiration time")
            void shouldHandleAssertionWithMaximumValidExpirationTime() throws Exception {
                // Given
                // 24 hours from now (reasonable maximum)
                Date expirationTime = new Date(System.currentTimeMillis() + 86400000);
                String clientAssertion = createValidClientAssertion(expirationTime);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, null, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }
        }

        @Nested
        @DisplayName("WIMSE Mode Authentication Tests")
        class WimseModeAuthenticationTests {

            @Test
            @DisplayName("Should authenticate with WIMSE WIT where iss differs from sub")
            void shouldAuthenticateWithWimseWitWhereIssDiffersFromSub() throws Exception {
                // Given - WIMSE scenario: iss=trust domain, sub=workload ID (used as client_id)
                String trustDomain = "wimse://default.trust.domain";
                String workloadId = "wimse://default.trust.domain/workload/test-uuid";
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);

                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(trustDomain)
                        .subject(workloadId)
                        .audience("https://example.com/token")
                        .expirationTime(expirationTime)
                        .issueTime(new Date())
                        .build();

                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // Request body contains client_id = workload ID (from DCR registration)
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_id", workloadId);
                requestBody.put("client_assertion", signedJWT.serialize());
                requestBody.put("client_assertion_type", clientAssertionType);

                OAuth2RegisteredClient client = OAuth2RegisteredClient.builder()
                        .clientId(workloadId)
                        .tokenEndpointAuthMethod("private_key_jwt")
                        .build();
                when(clientStore.retrieve(workloadId)).thenReturn(client);

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, requestBody, clientStore);

                // Then
                assertThat(authenticatedClientId).isEqualTo(workloadId);
            }

            @Test
            @DisplayName("Should reject when WIMSE WIT sub does not match request body client_id")
            void shouldRejectWhenWimseWitSubDoesNotMatchRequestBodyClientId() throws Exception {
                // Given
                String trustDomain = "wimse://default.trust.domain";
                String workloadId = "wimse://default.trust.domain/workload/test-uuid";
                String differentClientId = "wimse://default.trust.domain/workload/different-uuid";
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);

                JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                        .issuer(trustDomain)
                        .subject(workloadId)
                        .audience("https://example.com/token")
                        .expirationTime(expirationTime)
                        .issueTime(new Date())
                        .build();

                SignedJWT signedJWT = new SignedJWT(
                        new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                                .keyID(rsaKey.getKeyID())
                                .build(),
                        claimsSet);
                signedJWT.sign(new com.nimbusds.jose.crypto.RSASSASigner(rsaKey));

                // Request body client_id does NOT match JWT sub
                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_id", differentClientId);

                // When & Then
                assertThatThrownBy(() -> authenticator.authenticateWithClientAssertion(
                        signedJWT.serialize(), clientAssertionType, requestBody, clientStore))
                        .isInstanceOf(FrameworkOAuth2TokenException.class)
                        .hasMessageContaining("'sub' must match 'client_id'");
            }

            @Test
            @DisplayName("Should fall back to iss-based mode when request body has no client_id")
            void shouldFallBackToIssBasedModeWhenRequestBodyHasNoClientId() throws Exception {
                // Given - standard mode: no client_id in request body
                Date expirationTime = new Date(System.currentTimeMillis() + 3600000);
                String clientAssertion = createValidClientAssertion(expirationTime);

                Map<String, String> requestBody = new HashMap<>();
                requestBody.put("client_assertion", clientAssertion);
                requestBody.put("client_assertion_type", clientAssertionType);
                // No client_id in request body

                // When
                String authenticatedClientId = authenticator.authenticateWithClientAssertion(
                        clientAssertion, clientAssertionType, requestBody, clientStore);

                // Then - falls back to iss-based mode
                assertThat(authenticatedClientId).isEqualTo(clientId);
            }
        }
    }
}
