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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.server;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.authenticator.OAuth2DcrAuthenticator;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2DcrServer}.
 * <p>
 * This test class provides comprehensive coverage for the DefaultOAuth2DcrServer implementation,
 * covering all public methods and edge cases including error handling.
 * </p>
 */
@DisplayName("DefaultOAuth2DcrServer Tests")
class DefaultOAuth2DcrServerTest {

    private OAuth2DcrClientStore mockClientStore;
    private OAuth2DcrAuthenticator mockAuthenticator;
    private DefaultOAuth2DcrServer server;

    @BeforeEach
    void setUp() {
        mockClientStore = mock(OAuth2DcrClientStore.class);
        mockAuthenticator = mock(OAuth2DcrAuthenticator.class);
        server = new DefaultOAuth2DcrServer(mockClientStore);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create server with client store")
        void shouldCreateServerWithClientStore() {
            DefaultOAuth2DcrServer newServer = new DefaultOAuth2DcrServer(mockClientStore);
            assertThat(newServer).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when client store is null")
        void shouldThrowExceptionWhenClientStoreIsNull() {
            assertThatThrownBy(() -> new DefaultOAuth2DcrServer(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client store");
        }

        @Test
        @DisplayName("Should create server with client store and authenticators")
        void shouldCreateServerWithClientStoreAndAuthenticators() {
            List<OAuth2DcrAuthenticator> authenticators = new ArrayList<>();
            authenticators.add(mockAuthenticator);
            
            DefaultOAuth2DcrServer newServer = new DefaultOAuth2DcrServer(mockClientStore, authenticators);
            assertThat(newServer).isNotNull();
        }

        @Test
        @DisplayName("Should create server with null authenticators list")
        void shouldCreateServerWithNullAuthenticatorsList() {
            DefaultOAuth2DcrServer newServer = new DefaultOAuth2DcrServer(mockClientStore, null);
            assertThat(newServer).isNotNull();
        }
    }

    @Nested
    @DisplayName("registerClient Tests")
    class RegisterClientTests {

        @Test
        @DisplayName("Should register client successfully")
        void shouldRegisterClientSuccessfully() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .grantTypes(Arrays.asList("authorization_code"))
                .responseTypes(Arrays.asList("code"))
                .tokenEndpointAuthMethod("client_secret_basic")
                .scope("read write")
                .build();

            DcrResponse response = server.registerClient(request);

            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isNotNull();
            assertThat(response.getClientSecret()).isNotNull();
            assertThat(response.getClientName()).isEqualTo("Test Client");
            assertThat(response.getRedirectUris()).containsExactly("https://example.com/callback");
            assertThat(response.getClientIdIssuedAt()).isGreaterThan(0);
            assertThat(response.getRegistrationAccessToken()).isNotNull();
            assertThat(response.getRegistrationClientUri()).startsWith("/register/");

            verify(mockClientStore, times(1)).store(
                anyString(), 
                anyString(), 
                eq(request), 
                any(DcrResponse.class)
            );
        }

        @Test
        @DisplayName("Should register client without client_secret when auth method is none")
        void shouldRegisterClientWithoutClientSecretWhenAuthMethodIsNone() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .tokenEndpointAuthMethod("none")
                .build();

            DcrResponse response = server.registerClient(request);

            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isNotNull();
            assertThat(response.getClientSecret()).isNull();
        }

        @Test
        @DisplayName("Should register client without client_secret when auth method is private_key_jwt")
        void shouldRegisterClientWithoutClientSecretWhenAuthMethodIsPrivateKeyJwt() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .tokenEndpointAuthMethod("private_key_jwt")
                .build();

            DcrResponse response = server.registerClient(request);

            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isNotNull();
            assertThat(response.getClientSecret()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> server.registerClient(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("DCR request");
            
            verify(mockClientStore, never()).store(anyString(), anyString(), any(), any());
        }

        @Test
        @DisplayName("Should throw exception when redirect_uris is null")
        void shouldThrowExceptionWhenRedirectUrisIsNull() {
            assertThatThrownBy(() -> DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(null)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("redirect_uris is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when redirect_uris is empty")
        void shouldThrowExceptionWhenRedirectUrisIsEmpty() {
            assertThatThrownBy(() -> DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Collections.emptyList())
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("redirect_uris is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when redirect_uris contains empty value")
        void shouldThrowExceptionWhenRedirectUrisContainsEmptyValue() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback", ""))
                .build();

            assertThatThrownBy(() -> server.registerClient(request))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("redirect_uris contains empty value");
            
            verify(mockClientStore, never()).store(anyString(), anyString(), any(), any());
        }

        @Test
        @DisplayName("Should throw exception when token_endpoint_auth_method is invalid")
        void shouldThrowExceptionWhenTokenEndpointAuthMethodIsInvalid() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .tokenEndpointAuthMethod("invalid_method")
                .build();

            assertThatThrownBy(() -> server.registerClient(request))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Invalid token_endpoint_auth_method");
            
            verify(mockClientStore, never()).store(anyString(), anyString(), any(), any());
        }

        @Test
        @DisplayName("Should use authenticator when available")
        void shouldUseAuthenticatorWhenAvailable() {
            List<OAuth2DcrAuthenticator> authenticators = new ArrayList<>();
            authenticators.add(mockAuthenticator);
            when(mockAuthenticator.canAuthenticate(any())).thenReturn(true);
            when(mockAuthenticator.authenticate(any())).thenReturn("authenticated-subject");

            DefaultOAuth2DcrServer serverWithAuth = new DefaultOAuth2DcrServer(mockClientStore, authenticators);

            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            serverWithAuth.registerClient(request);

            verify(mockAuthenticator, times(1)).canAuthenticate(any());
            verify(mockAuthenticator, times(1)).authenticate(any());
        }

        @Test
        @DisplayName("Should handle storage exception")
        void shouldHandleStorageException() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            doThrow(new RuntimeException("Storage error"))
                .when(mockClientStore).store(anyString(), anyString(), any(DcrRequest.class), any());

            assertThatThrownBy(() -> server.registerClient(request))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Failed to register client");
        }
    }

    @Nested
    @DisplayName("readClient Tests")
    class ReadClientTests {

        @Test
        @DisplayName("Should read client successfully")
        void shouldReadClientSuccessfully() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrResponse storedResponse = DcrResponse.builder()
                .clientId(clientId)
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(storedResponse);

            DcrResponse response = server.readClient(clientId, registrationAccessToken);

            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isEqualTo(clientId);
            assertThat(response.getClientName()).isEqualTo("Test Client");

            verify(mockClientStore, times(1)).validateToken(clientId, registrationAccessToken);
            verify(mockClientStore, times(1)).retrieve(clientId);
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            assertThatThrownBy(() -> server.readClient(null, "token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client ID");
            
            verify(mockClientStore, never()).validateToken(anyString(), anyString());
        }

        @Test
        @DisplayName("Should throw exception when registration access token is null")
        void shouldThrowExceptionWhenRegistrationAccessTokenIsNull() {
            assertThatThrownBy(() -> server.readClient("client", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Registration access token");
            
            verify(mockClientStore, never()).validateToken(anyString(), anyString());
        }

        @Test
        @DisplayName("Should throw exception when token is invalid")
        void shouldThrowExceptionWhenTokenIsInvalid() {
            String clientId = "client-123";
            String registrationAccessToken = "invalid-token";

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(false);

            assertThatThrownBy(() -> server.readClient(clientId, registrationAccessToken))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Invalid registration access token");

            verify(mockClientStore, times(1)).validateToken(clientId, registrationAccessToken);
            verify(mockClientStore, never()).retrieve(anyString());
        }

        @Test
        @DisplayName("Should throw exception when client not found")
        void shouldThrowExceptionWhenClientNotFound() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(null);

            assertThatThrownBy(() -> server.readClient(clientId, registrationAccessToken))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Client not found");

            verify(mockClientStore, times(1)).validateToken(clientId, registrationAccessToken);
            verify(mockClientStore, times(1)).retrieve(clientId);
        }

        @Test
        @DisplayName("Should handle storage exception")
        void shouldHandleStorageException() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            when(mockClientStore.validateToken(clientId, registrationAccessToken))
                .thenThrow(new RuntimeException("Storage error"));

            assertThatThrownBy(() -> server.readClient(clientId, registrationAccessToken))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Failed to read client");
        }
    }

    @Nested
    @DisplayName("updateClient Tests")
    class UpdateClientTests {

        @Test
        @DisplayName("Should update client successfully")
        void shouldUpdateClientSuccessfully() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrResponse existingResponse = DcrResponse.builder()
                .clientId(clientId)
                .clientName("Old Name")
                .redirectUris(Arrays.asList("https://old.example.com/callback"))
                .grantTypes(Arrays.asList("authorization_code"))
                .responseTypes(Arrays.asList("code"))
                .tokenEndpointAuthMethod("client_secret_basic")
                .scope("read")
                .clientIdIssuedAt(1234567890L)
                .clientSecret("secret")
                .registrationAccessToken(registrationAccessToken)
                .registrationClientUri("/register/" + clientId)
                .build();

            DcrRequest updateRequest = DcrRequest.builder()
                .clientName("New Name")
                .redirectUris(Arrays.asList("https://new.example.com/callback"))
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(existingResponse);

            DcrResponse updatedResponse = server.updateClient(clientId, registrationAccessToken, updateRequest);

            assertThat(updatedResponse).isNotNull();
            assertThat(updatedResponse.getClientId()).isEqualTo(clientId);
            assertThat(updatedResponse.getClientName()).isEqualTo("New Name");
            assertThat(updatedResponse.getRedirectUris()).containsExactly("https://new.example.com/callback");
            assertThat(updatedResponse.getClientSecret()).isEqualTo("secret");
            assertThat(updatedResponse.getClientIdIssuedAt()).isEqualTo(1234567890L);

            verify(mockClientStore, times(1)).update(eq(clientId), eq(updateRequest), any(DcrResponse.class));
        }

        @Test
        @DisplayName("Should update client with partial update")
        void shouldUpdateClientWithPartialUpdate() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrResponse existingResponse = DcrResponse.builder()
                .clientId(clientId)
                .clientName("Old Name")
                .redirectUris(Arrays.asList("https://old.example.com/callback"))
                .grantTypes(Arrays.asList("authorization_code"))
                .responseTypes(Arrays.asList("code"))
                .tokenEndpointAuthMethod("client_secret_basic")
                .scope("read")
                .clientIdIssuedAt(1234567890L)
                .clientSecret("secret")
                .registrationAccessToken(registrationAccessToken)
                .registrationClientUri("/register/" + clientId)
                .build();

            DcrRequest updateRequest = DcrRequest.builder()
                .clientName("New Name")
                .redirectUris(Arrays.asList("https://old.example.com/callback"))
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(existingResponse);

            DcrResponse updatedResponse = server.updateClient(clientId, registrationAccessToken, updateRequest);

            assertThat(updatedResponse).isNotNull();
            assertThat(updatedResponse.getClientName()).isEqualTo("New Name");
            assertThat(updatedResponse.getRedirectUris()).containsExactly("https://old.example.com/callback");
            assertThat(updatedResponse.getScope()).isEqualTo("read");
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            DcrRequest request = DcrRequest.builder()
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();
            
            assertThatThrownBy(() -> server.updateClient(null, "token", request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client ID");
        }

        @Test
        @DisplayName("Should throw exception when registration access token is null")
        void shouldThrowExceptionWhenRegistrationAccessTokenIsNull() {
            DcrRequest request = DcrRequest.builder()
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();
            
            assertThatThrownBy(() -> server.updateClient("client", null, request))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Registration access token");
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            assertThatThrownBy(() -> server.updateClient("client", "token", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("DCR request");
        }

        @Test
        @DisplayName("Should throw exception when redirect_uris contains empty value in update")
        void shouldThrowExceptionWhenRedirectUrisContainsEmptyValueInUpdate() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrResponse existingResponse = DcrResponse.builder()
                .clientId(clientId)
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            DcrRequest updateRequest = DcrRequest.builder()
                .redirectUris(Arrays.asList("https://new.example.com/callback", ""))
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(existingResponse);

            assertThatThrownBy(() -> server.updateClient(clientId, registrationAccessToken, updateRequest))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("redirect_uris contains empty value");

            verify(mockClientStore, never()).update(anyString(), any(), any());
        }

        @Test
        @DisplayName("Should throw exception when token_endpoint_auth_method is invalid in update")
        void shouldThrowExceptionWhenTokenEndpointAuthMethodIsInvalidInUpdate() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrResponse existingResponse = DcrResponse.builder()
                .clientId(clientId)
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            DcrRequest updateRequest = DcrRequest.builder()
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .tokenEndpointAuthMethod("invalid_method")
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(existingResponse);

            assertThatThrownBy(() -> server.updateClient(clientId, registrationAccessToken, updateRequest))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Invalid token_endpoint_auth_method");

            verify(mockClientStore, never()).update(anyString(), any(), any());
        }

        @Test
        @DisplayName("Should handle storage exception")
        void shouldHandleStorageException() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrRequest updateRequest = DcrRequest.builder()
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken))
                .thenThrow(new RuntimeException("Storage error"));

            assertThatThrownBy(() -> server.updateClient(clientId, registrationAccessToken, updateRequest))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Failed to update client");
        }
    }

    @Nested
    @DisplayName("deleteClient Tests")
    class DeleteClientTests {

        @Test
        @DisplayName("Should delete client successfully")
        void shouldDeleteClientSuccessfully() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            DcrResponse storedResponse = DcrResponse.builder()
                .clientId(clientId)
                .clientName("Test Client")
                .build();

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(storedResponse);

            server.deleteClient(clientId, registrationAccessToken);

            verify(mockClientStore, times(1)).validateToken(clientId, registrationAccessToken);
            verify(mockClientStore, times(1)).retrieve(clientId);
            verify(mockClientStore, times(1)).delete(clientId);
        }

        @Test
        @DisplayName("Should throw exception when client ID is null")
        void shouldThrowExceptionWhenClientIdIsNull() {
            assertThatThrownBy(() -> server.deleteClient(null, "token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client ID");
            
            verify(mockClientStore, never()).delete(anyString());
        }

        @Test
        @DisplayName("Should throw exception when registration access token is null")
        void shouldThrowExceptionWhenRegistrationAccessTokenIsNull() {
            assertThatThrownBy(() -> server.deleteClient("client", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Registration access token");
            
            verify(mockClientStore, never()).delete(anyString());
        }

        @Test
        @DisplayName("Should throw exception when token is invalid")
        void shouldThrowExceptionWhenTokenIsInvalid() {
            String clientId = "client-123";
            String registrationAccessToken = "invalid-token";

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(false);

            assertThatThrownBy(() -> server.deleteClient(clientId, registrationAccessToken))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Invalid registration access token");

            verify(mockClientStore, times(1)).validateToken(clientId, registrationAccessToken);
            verify(mockClientStore, never()).delete(anyString());
        }

        @Test
        @DisplayName("Should throw exception when client not found")
        void shouldThrowExceptionWhenClientNotFound() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            when(mockClientStore.validateToken(clientId, registrationAccessToken)).thenReturn(true);
            when(mockClientStore.retrieve(clientId)).thenReturn(null);

            assertThatThrownBy(() -> server.deleteClient(clientId, registrationAccessToken))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Client not found");

            verify(mockClientStore, times(1)).validateToken(clientId, registrationAccessToken);
            verify(mockClientStore, times(1)).retrieve(clientId);
            verify(mockClientStore, never()).delete(anyString());
        }

        @Test
        @DisplayName("Should handle storage exception")
        void shouldHandleStorageException() {
            String clientId = "client-123";
            String registrationAccessToken = "token-456";

            when(mockClientStore.validateToken(clientId, registrationAccessToken))
                .thenThrow(new RuntimeException("Storage error"));

            assertThatThrownBy(() -> server.deleteClient(clientId, registrationAccessToken))
                .isInstanceOf(DcrException.class)
                .hasMessageContaining("Failed to delete client");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should generate unique client IDs")
        void shouldGenerateUniqueClientIds() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            DcrResponse response1 = server.registerClient(request);
            DcrResponse response2 = server.registerClient(request);

            assertThat(response1.getClientId()).isNotEqualTo(response2.getClientId());
        }

        @Test
        @DisplayName("Should generate unique client secrets")
        void shouldGenerateUniqueClientSecrets() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            DcrResponse response1 = server.registerClient(request);
            DcrResponse response2 = server.registerClient(request);

            assertThat(response1.getClientSecret()).isNotEqualTo(response2.getClientSecret());
        }

        @Test
        @DisplayName("Should generate unique registration access tokens")
        void shouldGenerateUniqueRegistrationAccessTokens() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            DcrResponse response1 = server.registerClient(request);
            DcrResponse response2 = server.registerClient(request);

            assertThat(response1.getRegistrationAccessToken()).isNotEqualTo(response2.getRegistrationAccessToken());
        }

        @Test
        @DisplayName("Should handle multiple redirect URIs")
        void shouldHandleMultipleRedirectUris() {
            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList(
                    "https://example.com/callback1",
                    "https://example.com/callback2",
                    "https://example.com/callback3"
                ))
                .build();

            DcrResponse response = server.registerClient(request);

            assertThat(response.getRedirectUris()).hasSize(3);
            assertThat(response.getRedirectUris()).containsExactlyInAnyOrder(
                "https://example.com/callback1",
                "https://example.com/callback2",
                "https://example.com/callback3"
            );
        }

        @Test
        @DisplayName("Should use default authentication when no authenticator matches")
        void shouldUseDefaultAuthenticationWhenNoAuthenticatorMatches() {
            List<OAuth2DcrAuthenticator> authenticators = new ArrayList<>();
            authenticators.add(mockAuthenticator);
            when(mockAuthenticator.canAuthenticate(any())).thenReturn(false);

            DefaultOAuth2DcrServer serverWithAuth = new DefaultOAuth2DcrServer(mockClientStore, authenticators);

            DcrRequest request = DcrRequest.builder()
                .clientName("Test Client")
                .redirectUris(Arrays.asList("https://example.com/callback"))
                .build();

            serverWithAuth.registerClient(request);

            verify(mockAuthenticator, times(1)).canAuthenticate(any());
            verify(mockAuthenticator, never()).authenticate(any());
        }

        @Test
        @DisplayName("Should support all valid auth methods")
        void shouldSupportAllValidAuthMethods() {
            String[] validMethods = {
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "private_key_jwt",
                "none"
            };

            for (String method : validMethods) {
                DcrRequest request = DcrRequest.builder()
                    .clientName("Test Client")
                    .redirectUris(Arrays.asList("https://example.com/callback"))
                    .tokenEndpointAuthMethod(method)
                    .build();

                DcrResponse response = server.registerClient(request);

                assertThat(response).isNotNull();
                assertThat(response.getTokenEndpointAuthMethod()).isEqualTo(method);
            }
        }
    }
}
