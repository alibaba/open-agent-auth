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
package com.alibaba.openagentauth.core.protocol.oauth2.client.store;

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryOAuth2ClientStore}.
 * <p>
 * This test class validates the in-memory OAuth 2.0 client store implementation,
 * covering client registration, retrieval, and existence checking.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("InMemoryOAuth2ClientStore Tests")
class InMemoryOAuth2ClientStoreTest {

    private InMemoryOAuth2ClientStore clientStore;

    @BeforeEach
    void setUp() {
        clientStore = new InMemoryOAuth2ClientStore();
    }

    @Nested
    @DisplayName("Register Client Tests")
    class RegisterClientTests {

        @Test
        @DisplayName("Should register client and retrieve it successfully")
        void shouldRegisterClientAndRetrieveItSuccessfully() {
            OAuth2RegisteredClient client = createTestClient("test-client", "Test Client");

            clientStore.register(client);
            OAuth2RegisteredClient retrieved = clientStore.retrieve("test-client");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo("test-client");
            assertThat(retrieved.getClientName()).isEqualTo("Test Client");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when registering null client")
        void shouldThrowIllegalArgumentExceptionWhenRegisteringNullClient() {
            assertThatThrownBy(() -> clientStore.register(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client");
        }

        @Test
        @DisplayName("Should throw IllegalStateException when building client with null clientId")
        void shouldThrowIllegalStateExceptionWhenBuildingClientWithNullClientId() {
            assertThatThrownBy(() -> OAuth2RegisteredClient.builder()
                .clientSecret("secret")
                .clientName("Test Client")
                .redirectUris(List.of("http://localhost/callback"))
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client_id is REQUIRED");
        }

        @Test
        @DisplayName("Should throw IllegalStateException when building client with empty clientId")
        void shouldThrowIllegalStateExceptionWhenBuildingClientWithEmptyClientId() {
            assertThatThrownBy(() -> OAuth2RegisteredClient.builder()
                .clientId("")
                .clientSecret("secret")
                .clientName("Test Client")
                .redirectUris(List.of("http://localhost/callback"))
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("client_id is REQUIRED");
        }

        @Test
        @DisplayName("Should overwrite existing client when registering with same clientId")
        void shouldOverwriteExistingClientWhenRegisteringWithSameClientId() {
            OAuth2RegisteredClient client1 = createTestClient("test-client", "Original Client");
            OAuth2RegisteredClient client2 = createTestClient("test-client", "Updated Client");

            clientStore.register(client1);
            clientStore.register(client2);

            OAuth2RegisteredClient retrieved = clientStore.retrieve("test-client");
            assertThat(retrieved.getClientName()).isEqualTo("Updated Client");
        }
    }

    @Nested
    @DisplayName("Retrieve Client Tests")
    class RetrieveClientTests {

        @Test
        @DisplayName("Should return null when retrieving non-existent clientId")
        void shouldReturnNullWhenRetrievingNonExistentClientId() {
            OAuth2RegisteredClient retrieved = clientStore.retrieve("non-existent-client");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null when retrieving with null clientId")
        void shouldReturnNullWhenRetrievingWithNullClientId() {
            OAuth2RegisteredClient retrieved = clientStore.retrieve(null);

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return correct client after registration")
        void shouldReturnCorrectClientAfterRegistration() {
            OAuth2RegisteredClient client = createTestClient("test-client", "Test Client");
            clientStore.register(client);

            OAuth2RegisteredClient retrieved = clientStore.retrieve("test-client");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo("test-client");
            assertThat(retrieved.getClientSecret()).isEqualTo("secret");
            assertThat(retrieved.getClientName()).isEqualTo("Test Client");
        }
    }

    @Nested
    @DisplayName("Retrieve By Client Name Tests")
    class RetrieveByClientNameTests {

        @Test
        @DisplayName("Should retrieve client by name successfully")
        void shouldRetrieveClientByNameSuccessfully() {
            OAuth2RegisteredClient client = createTestClient("test-client", "Test Client");
            clientStore.register(client);

            OAuth2RegisteredClient retrieved = clientStore.retrieveByClientName("Test Client");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo("test-client");
            assertThat(retrieved.getClientName()).isEqualTo("Test Client");
        }

        @Test
        @DisplayName("Should return null when clientName is null")
        void shouldReturnNullWhenClientNameIsNull() {
            OAuth2RegisteredClient retrieved = clientStore.retrieveByClientName(null);

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null when clientName is empty")
        void shouldReturnNullWhenClientNameIsEmpty() {
            OAuth2RegisteredClient retrieved = clientStore.retrieveByClientName("");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null when clientName is blank")
        void shouldReturnNullWhenClientNameIsBlank() {
            OAuth2RegisteredClient retrieved = clientStore.retrieveByClientName("   ");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null when client name does not exist")
        void shouldReturnNullWhenClientNameDoesNotExist() {
            OAuth2RegisteredClient retrieved = clientStore.retrieveByClientName("Non-existent Client");

            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should retrieve first matching client when multiple clients have same name")
        void shouldRetrieveFirstMatchingClientWhenMultipleClientsHaveSameName() {
            OAuth2RegisteredClient client1 = createTestClient("client-1", "Same Name");
            OAuth2RegisteredClient client2 = createTestClient("client-2", "Same Name");
            clientStore.register(client1);
            clientStore.register(client2);

            OAuth2RegisteredClient retrieved = clientStore.retrieveByClientName("Same Name");

            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isIn("client-1", "client-2");
        }
    }

    @Nested
    @DisplayName("Exists Client Tests")
    class ExistsClientTests {

        @Test
        @DisplayName("Should return true when client exists")
        void shouldReturnTrueWhenClientExists() {
            OAuth2RegisteredClient client = createTestClient("test-client", "Test Client");
            clientStore.register(client);

            boolean exists = clientStore.exists("test-client");

            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("Should return false when client does not exist")
        void shouldReturnFalseWhenClientDoesNotExist() {
            boolean exists = clientStore.exists("non-existent-client");

            assertThat(exists).isFalse();
        }

        @Test
        @DisplayName("Should return false when checking existence with null clientId")
        void shouldReturnFalseWhenCheckingExistenceWithNullClientId() {
            boolean exists = clientStore.exists(null);

            assertThat(exists).isFalse();
        }

        @Test
        @DisplayName("Should return false when checking existence with empty clientId")
        void shouldReturnFalseWhenCheckingExistenceWithEmptyClientId() {
            boolean exists = clientStore.exists("");

            assertThat(exists).isFalse();
        }
    }

    @Nested
    @DisplayName("Multiple Clients Tests")
    class MultipleClientsTests {

        @Test
        @DisplayName("Should register and retrieve multiple clients")
        void shouldRegisterAndRetrieveMultipleClients() {
            OAuth2RegisteredClient client1 = createTestClient("client-1", "Client 1");
            OAuth2RegisteredClient client2 = createTestClient("client-2", "Client 2");
            OAuth2RegisteredClient client3 = createTestClient("client-3", "Client 3");

            clientStore.register(client1);
            clientStore.register(client2);
            clientStore.register(client3);

            assertThat(clientStore.exists("client-1")).isTrue();
            assertThat(clientStore.exists("client-2")).isTrue();
            assertThat(clientStore.exists("client-3")).isTrue();
            assertThat(clientStore.exists("client-4")).isFalse();
        }

        @Test
        @DisplayName("Should retrieve each client correctly by clientId")
        void shouldRetrieveEachClientCorrectlyByClientId() {
            OAuth2RegisteredClient client1 = createTestClient("client-1", "Client 1");
            OAuth2RegisteredClient client2 = createTestClient("client-2", "Client 2");

            clientStore.register(client1);
            clientStore.register(client2);

            OAuth2RegisteredClient retrieved1 = clientStore.retrieve("client-1");
            OAuth2RegisteredClient retrieved2 = clientStore.retrieve("client-2");

            assertThat(retrieved1.getClientName()).isEqualTo("Client 1");
            assertThat(retrieved2.getClientName()).isEqualTo("Client 2");
        }

        @Test
        @DisplayName("Should retrieve each client correctly by clientName")
        void shouldRetrieveEachClientCorrectlyByClientName() {
            OAuth2RegisteredClient client1 = createTestClient("client-1", "Client 1");
            OAuth2RegisteredClient client2 = createTestClient("client-2", "Client 2");

            clientStore.register(client1);
            clientStore.register(client2);

            OAuth2RegisteredClient retrieved1 = clientStore.retrieveByClientName("Client 1");
            OAuth2RegisteredClient retrieved2 = clientStore.retrieveByClientName("Client 2");

            assertThat(retrieved1.getClientId()).isEqualTo("client-1");
            assertThat(retrieved2.getClientId()).isEqualTo("client-2");
        }
    }

    @Nested
    @DisplayName("DCR Store Method Tests")
    class DcrStoreMethodTests {

        private static final String CLIENT_ID = "dcr-client-123";
        private static final String REGISTRATION_TOKEN = "reg-token-abc";
        private static final String REDIRECT_URI = "https://example.com/callback";

        private DcrRequest createTestDcrRequest() {
            return DcrRequest.builder()
                    .redirectUris(List.of(REDIRECT_URI))
                    .clientName("DCR Test Client")
                    .grantTypes(List.of("authorization_code"))
                    .responseTypes(List.of("code"))
                    .tokenEndpointAuthMethod("private_key_jwt")
                    .scope("openid profile")
                    .build();
        }

        private DcrResponse createTestDcrResponse(String clientId) {
            return DcrResponse.builder()
                    .clientId(clientId)
                    .clientSecret("dcr-secret")
                    .clientName("DCR Test Client")
                    .redirectUris(List.of(REDIRECT_URI))
                    .grantTypes(List.of("authorization_code"))
                    .responseTypes(List.of("code"))
                    .tokenEndpointAuthMethod("private_key_jwt")
                    .scope("openid profile")
                    .registrationAccessToken(REGISTRATION_TOKEN)
                    .registrationClientUri("/register/" + clientId)
                    .clientIdIssuedAt(System.currentTimeMillis() / 1000)
                    .clientSecretExpiresAt(0L)
                    .build();
        }

        @Test
        @DisplayName("Should store DCR client and retrieve via retrieve()")
        void shouldStoreDcrClientAndRetrieveViaRetrieve() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse(CLIENT_ID);

            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, request, response);

            OAuth2RegisteredClient retrieved = clientStore.retrieve(CLIENT_ID);
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(retrieved.getClientName()).isEqualTo("DCR Test Client");
        }

        @Test
        @DisplayName("Should store DCR client and retrieve DcrResponse")
        void shouldStoreDcrClientAndRetrieveDcrResponse() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse(CLIENT_ID);

            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, request, response);

            DcrResponse retrieved = clientStore.retrieveDcrResponse(CLIENT_ID);
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(retrieved.getClientSecret()).isEqualTo("dcr-secret");
            assertThat(retrieved.getRegistrationAccessToken()).isEqualTo(REGISTRATION_TOKEN);
        }

        @Test
        @DisplayName("Should return null when retrieving DcrResponse for non-existent client")
        void shouldReturnNullWhenRetrievingDcrResponseForNonExistentClient() {
            DcrResponse retrieved = clientStore.retrieveDcrResponse("non-existent");
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should retrieve DCR client by registration access token")
        void shouldRetrieveDcrClientByRegistrationAccessToken() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse(CLIENT_ID);

            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, request, response);

            DcrResponse retrieved = clientStore.retrieveByToken(REGISTRATION_TOKEN);
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo(CLIENT_ID);
        }

        @Test
        @DisplayName("Should return null when retrieving by non-existent token")
        void shouldReturnNullWhenRetrievingByNonExistentToken() {
            DcrResponse retrieved = clientStore.retrieveByToken("non-existent-token");
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should update existing DCR client registration")
        void shouldUpdateExistingDcrClientRegistration() {
            DcrRequest originalRequest = createTestDcrRequest();
            DcrResponse originalResponse = createTestDcrResponse(CLIENT_ID);
            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, originalRequest, originalResponse);

            DcrRequest updatedRequest = DcrRequest.builder()
                    .redirectUris(List.of("https://updated.example.com/callback"))
                    .clientName("Updated DCR Client")
                    .build();
            DcrResponse updatedResponse = DcrResponse.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret("updated-secret")
                    .clientName("Updated DCR Client")
                    .redirectUris(List.of("https://updated.example.com/callback"))
                    .build();

            clientStore.update(CLIENT_ID, updatedRequest, updatedResponse);

            DcrResponse retrieved = clientStore.retrieveDcrResponse(CLIENT_ID);
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientName()).isEqualTo("Updated DCR Client");
            assertThat(retrieved.getClientSecret()).isEqualTo("updated-secret");

            OAuth2RegisteredClient registeredClient = clientStore.retrieve(CLIENT_ID);
            assertThat(registeredClient).isNotNull();
            assertThat(registeredClient.getClientName()).isEqualTo("Updated DCR Client");
        }

        @Test
        @DisplayName("Should not update non-existent client")
        void shouldNotUpdateNonExistentClient() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse("non-existent");

            clientStore.update("non-existent", request, response);

            assertThat(clientStore.retrieve("non-existent")).isNull();
            assertThat(clientStore.retrieveDcrResponse("non-existent")).isNull();
        }

        @Test
        @DisplayName("Should delete DCR client and all associated data")
        void shouldDeleteDcrClientAndAllAssociatedData() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse(CLIENT_ID);
            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, request, response);

            assertThat(clientStore.retrieve(CLIENT_ID)).isNotNull();
            assertThat(clientStore.retrieveDcrResponse(CLIENT_ID)).isNotNull();
            assertThat(clientStore.retrieveByToken(REGISTRATION_TOKEN)).isNotNull();

            clientStore.delete(CLIENT_ID);

            assertThat(clientStore.retrieve(CLIENT_ID)).isNull();
            assertThat(clientStore.retrieveDcrResponse(CLIENT_ID)).isNull();
            assertThat(clientStore.retrieveByToken(REGISTRATION_TOKEN)).isNull();
            assertThat(clientStore.exists(CLIENT_ID)).isFalse();
        }

        @Test
        @DisplayName("Should handle delete of non-existent client gracefully")
        void shouldHandleDeleteOfNonExistentClientGracefully() {
            clientStore.delete("non-existent");
            assertThat(clientStore.exists("non-existent")).isFalse();
        }

        @Test
        @DisplayName("Should validate token successfully for stored client")
        void shouldValidateTokenSuccessfullyForStoredClient() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse(CLIENT_ID);
            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, request, response);

            assertThat(clientStore.validateToken(CLIENT_ID, REGISTRATION_TOKEN)).isTrue();
        }

        @Test
        @DisplayName("Should reject invalid registration access token")
        void shouldRejectInvalidRegistrationAccessToken() {
            DcrRequest request = createTestDcrRequest();
            DcrResponse response = createTestDcrResponse(CLIENT_ID);
            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, request, response);

            assertThat(clientStore.validateToken(CLIENT_ID, "wrong-token")).isFalse();
        }

        @Test
        @DisplayName("Should reject token validation for non-existent client")
        void shouldRejectTokenValidationForNonExistentClient() {
            assertThat(clientStore.validateToken("non-existent", REGISTRATION_TOKEN)).isFalse();
        }

        @Test
        @DisplayName("Should coexist with pre-registered clients in same store")
        void shouldCoexistWithPreRegisteredClientsInSameStore() {
            OAuth2RegisteredClient preRegistered = createTestClient("pre-registered", "Pre-Registered Client");
            clientStore.register(preRegistered);

            DcrRequest dcrRequest = createTestDcrRequest();
            DcrResponse dcrResponse = createTestDcrResponse(CLIENT_ID);
            clientStore.store(CLIENT_ID, REGISTRATION_TOKEN, dcrRequest, dcrResponse);

            assertThat(clientStore.retrieve("pre-registered")).isNotNull();
            assertThat(clientStore.retrieve("pre-registered").getClientName()).isEqualTo("Pre-Registered Client");

            assertThat(clientStore.retrieve(CLIENT_ID)).isNotNull();
            assertThat(clientStore.retrieve(CLIENT_ID).getClientName()).isEqualTo("DCR Test Client");

            assertThat(clientStore.exists("pre-registered")).isTrue();
            assertThat(clientStore.exists(CLIENT_ID)).isTrue();
        }

        @Test
        @DisplayName("Should handle multiple DCR clients with separate tokens")
        void shouldHandleMultipleDcrClientsWithSeparateTokens() {
            String clientId1 = "dcr-client-1";
            String clientId2 = "dcr-client-2";
            String token1 = "token-1";
            String token2 = "token-2";

            DcrRequest request = createTestDcrRequest();
            DcrResponse response1 = createTestDcrResponse(clientId1);
            DcrResponse response2 = DcrResponse.builder()
                    .clientId(clientId2)
                    .clientSecret("secret-2")
                    .clientName("DCR Client 2")
                    .redirectUris(List.of(REDIRECT_URI))
                    .build();

            clientStore.store(clientId1, token1, request, response1);
            clientStore.store(clientId2, token2, request, response2);

            assertThat(clientStore.retrieveByToken(token1).getClientId()).isEqualTo(clientId1);
            assertThat(clientStore.retrieveByToken(token2).getClientId()).isEqualTo(clientId2);

            assertThat(clientStore.validateToken(clientId1, token1)).isTrue();
            assertThat(clientStore.validateToken(clientId1, token2)).isFalse();
            assertThat(clientStore.validateToken(clientId2, token2)).isTrue();
            assertThat(clientStore.validateToken(clientId2, token1)).isFalse();
        }
    }

    // Helper method to create a test OAuth2RegisteredClient
    private OAuth2RegisteredClient createTestClient(String clientId, String clientName) {
        return OAuth2RegisteredClient.builder()
            .clientId(clientId)
            .clientSecret("secret")
            .clientName(clientName)
            .redirectUris(List.of("http://localhost/callback"))
            .grantTypes(List.of("authorization_code"))
            .responseTypes(List.of("code"))
            .tokenEndpointAuthMethod("client_secret_basic")
            .scope("openid profile")
            .build();
    }
}
