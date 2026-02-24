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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.store;

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link InMemoryOAuth2DcrClientStore}.
 * <p>
 * This test class validates the in-memory storage implementation for OAuth 2.0 Dynamic Client Registration.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
 */
@DisplayName("InMemoryOAuth2DcrClientStore Tests")
class InMemoryOAuth2DcrClientStoreTest {

    private InMemoryOAuth2DcrClientStore store;

    private static final String TEST_CLIENT_ID = "test-client-123";
    private static final String TEST_CLIENT_SECRET = "test-secret-456";
    private static final String TEST_CLIENT_NAME = "Test Client";
    private static final String TEST_SCOPE = "read write";
    private static final String TEST_AUTH_METHOD = "client_secret_basic";

    private static final List<String> TEST_REDIRECT_URIS = Arrays.asList(
            "https://example.com/callback",
            "https://example.com/redirect"
    );

    private static final List<String> TEST_GRANT_TYPES = Arrays.asList(
            "authorization_code",
            "refresh_token"
    );

    private static final List<String> TEST_RESPONSE_TYPES = Arrays.asList("code");

    @BeforeEach
    void setUp() {
        store = new InMemoryOAuth2DcrClientStore();
    }

    @AfterEach
    void tearDown() {
        if (store != null) {
            store.clear();
        }
    }

    @Nested
    @DisplayName("register() - Register Client")
    class RegisterClient {

        @Test
        @DisplayName("Should successfully register client and retrieve by clientId")
        void shouldSuccessfullyRegisterClientAndRetrieveByClientId() {
            // Arrange
            OAuth2RegisteredClient client = createTestClient();

            // Act
            store.register(client);
            OAuth2RegisteredClient retrieved = store.retrieve(TEST_CLIENT_ID);

            // Assert
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(retrieved.getClientSecret()).isEqualTo(TEST_CLIENT_SECRET);
            assertThat(retrieved.getClientName()).isEqualTo(TEST_CLIENT_NAME);
            assertThat(retrieved.getScope()).isEqualTo(TEST_SCOPE);
            assertThat(retrieved.getRedirectUris()).isEqualTo(TEST_REDIRECT_URIS);
            assertThat(retrieved.getGrantTypes()).isEqualTo(TEST_GRANT_TYPES);
            assertThat(retrieved.getResponseTypes()).isEqualTo(TEST_RESPONSE_TYPES);
            assertThat(retrieved.getTokenEndpointAuthMethod()).isEqualTo(TEST_AUTH_METHOD);
        }

        @Test
        @DisplayName("Should successfully register client and retrieve by clientName")
        void shouldSuccessfullyRegisterClientAndRetrieveByClientName() {
            // Arrange
            OAuth2RegisteredClient client = createTestClient();

            // Act
            store.register(client);
            OAuth2RegisteredClient retrieved = store.retrieveByClientName(TEST_CLIENT_NAME);

            // Assert
            assertThat(retrieved).isNotNull();
            assertThat(retrieved.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(retrieved.getClientName()).isEqualTo(TEST_CLIENT_NAME);
        }

        @Test
        @DisplayName("Should return true for exists() after successful registration")
        void shouldReturnTrueForExistsAfterSuccessfulRegistration() {
            // Arrange
            OAuth2RegisteredClient client = createTestClient();

            // Act
            store.register(client);
            boolean exists = store.exists(TEST_CLIENT_ID);

            // Assert
            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("Should throw exception when registering null client")
        void shouldThrowExceptionWhenRegisteringNullClient() {
            // Act & Assert
            assertThatThrownBy(() -> store.register(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Client");
        }

        @Test
        @DisplayName("Should successfully retrieve synthetic DcrResponse after registration")
        void shouldSuccessfullyRetrieveSyntheticDcrResponseAfterRegistration() {
            // Arrange
            OAuth2RegisteredClient client = createTestClient();

            // Act
            store.register(client);
            DcrResponse response = store.retrieveDcrResponse(TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isEqualTo(TEST_CLIENT_ID);
            assertThat(response.getClientSecret()).isEqualTo(TEST_CLIENT_SECRET);
            assertThat(response.getClientName()).isEqualTo(TEST_CLIENT_NAME);
            assertThat(response.getRedirectUris()).isEqualTo(TEST_REDIRECT_URIS);
            assertThat(response.getGrantTypes()).isEqualTo(TEST_GRANT_TYPES);
            assertThat(response.getResponseTypes()).isEqualTo(TEST_RESPONSE_TYPES);
            assertThat(response.getTokenEndpointAuthMethod()).isEqualTo(TEST_AUTH_METHOD);
            assertThat(response.getScope()).isEqualTo(TEST_SCOPE);
            assertThat(response.getClientSecretExpiresAt()).isEqualTo(0L);
            assertThat(response.getClientIdIssuedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should overwrite existing client when registering with same clientId")
        void shouldOverwriteExistingClientWhenRegisteringWithSameClientId() {
            // Arrange
            OAuth2RegisteredClient client1 = createTestClient();
            OAuth2RegisteredClient client2 = OAuth2RegisteredClient.builder()
                    .clientId(TEST_CLIENT_ID)
                    .clientSecret("new-secret")
                    .clientName("New Client Name")
                    .scope("new-scope")
                    .redirectUris(Arrays.asList("https://new-example.com/callback"))
                    .grantTypes(Arrays.asList("password"))
                    .responseTypes(Arrays.asList("token"))
                    .tokenEndpointAuthMethod("client_secret_post")
                    .build();

            // Act
            store.register(client1);
            store.register(client2);

            // Assert
            assertThat(store.size()).isEqualTo(1);
            OAuth2RegisteredClient retrieved = store.retrieve(TEST_CLIENT_ID);
            assertThat(retrieved.getClientSecret()).isEqualTo("new-secret");
            assertThat(retrieved.getClientName()).isEqualTo("New Client Name");
            assertThat(retrieved.getScope()).isEqualTo("new-scope");
        }

        @Test
        @DisplayName("Should throw exception when building client with null clientId")
        void shouldThrowExceptionWhenBuildingClientWithNullClientId() {
            assertThatThrownBy(() -> OAuth2RegisteredClient.builder()
                    .clientId(null)
                    .clientSecret(TEST_CLIENT_SECRET)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("client_id is REQUIRED");
        }

        @Test
        @DisplayName("Should return null when retrieving by non-existent clientName")
        void shouldReturnNullWhenRetrievingByNonExistentClientName() {
            // Act
            OAuth2RegisteredClient retrieved = store.retrieveByClientName("non-existent-client");

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return false for exists() when client not registered")
        void shouldReturnFalseForExistsWhenClientNotRegistered() {
            // Act
            boolean exists = store.exists(TEST_CLIENT_ID);

            // Assert
            assertThat(exists).isFalse();
        }

        @Test
        @DisplayName("Should return null for retrieve() when client not registered")
        void shouldReturnNullForRetrieveWhenClientNotRegistered() {
            // Act
            OAuth2RegisteredClient retrieved = store.retrieve(TEST_CLIENT_ID);

            // Assert
            assertThat(retrieved).isNull();
        }

        @Test
        @DisplayName("Should return null for retrieveDcrResponse() when client not registered")
        void shouldReturnNullForRetrieveDcrResponseWhenClientNotRegistered() {
            // Act
            DcrResponse response = store.retrieveDcrResponse(TEST_CLIENT_ID);

            // Assert
            assertThat(response).isNull();
        }
    }

    @Nested
    @DisplayName("clear() - Clear Storage")
    class ClearStorage {

        @Test
        @DisplayName("Should clear all registered clients")
        void shouldClearAllRegisteredClients() {
            // Arrange
            store.register(createTestClient());
            store.register(OAuth2RegisteredClient.builder()
                    .clientId("client-2")
                    .clientSecret("secret-2")
                    .build());
            assertThat(store.size()).isEqualTo(2);

            // Act
            store.clear();

            // Assert
            assertThat(store.size()).isEqualTo(0);
            assertThat(store.retrieve(TEST_CLIENT_ID)).isNull();
        }
    }

    @Nested
    @DisplayName("size() - Get Storage Size")
    class GetStorageSize {

        @Test
        @DisplayName("Should return correct storage size")
        void shouldReturnCorrectStorageSize() {
            // Arrange
            assertThat(store.size()).isEqualTo(0);

            store.register(createTestClient());
            assertThat(store.size()).isEqualTo(1);

            store.register(OAuth2RegisteredClient.builder()
                    .clientId("client-2")
                    .clientSecret("secret-2")
                    .build());
            assertThat(store.size()).isEqualTo(2);
        }
    }

    // Helper methods

    private OAuth2RegisteredClient createTestClient() {
        return OAuth2RegisteredClient.builder()
                .clientId(TEST_CLIENT_ID)
                .clientSecret(TEST_CLIENT_SECRET)
                .clientName(TEST_CLIENT_NAME)
                .scope(TEST_SCOPE)
                .redirectUris(TEST_REDIRECT_URIS)
                .grantTypes(TEST_GRANT_TYPES)
                .responseTypes(TEST_RESPONSE_TYPES)
                .tokenEndpointAuthMethod(TEST_AUTH_METHOD)
                .build();
    }
}
