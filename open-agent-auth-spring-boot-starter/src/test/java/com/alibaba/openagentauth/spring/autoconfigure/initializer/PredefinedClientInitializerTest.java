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
package com.alibaba.openagentauth.spring.autoconfigure.initializer;

import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link PredefinedClientInitializer}.
 * <p>
 * Tests the auto-registration of OAuth 2.0 clients from static configuration.
 * </p>
 *
 * @since 1.0
 */
@ExtendWith(MockitoExtension.class)
class PredefinedClientInitializerTest {

    @Mock
    private OAuth2ClientStore clientStore;

    private PredefinedClientInitializer initializer;

    @BeforeEach
    void setUp() {
        initializer = new PredefinedClientInitializer(clientStore, new OpenAgentAuthProperties());
    }

    @Test
    void initializeClients_whenAutoRegisterClientsDisabled_shouldNotCallRegister() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setEnabled(false);
        initializer = new PredefinedClientInitializer(clientStore, properties);

        // Act
        initializer.initializeClients();

        // Assert
        verify(clientStore, never()).register(any());
    }

    @Test
    void initializeClients_whenOAuth2ServerIsNull_shouldNotCallRegister() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().setOAuth2Server(null);
        initializer = new PredefinedClientInitializer(clientStore, properties);

        // Act
        initializer.initializeClients();

        // Assert
        verify(clientStore, never()).register(any());
    }

    @Test
    void initializeClients_whenClientsListEmpty_shouldNotCallRegister() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setEnabled(true);
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setClients(List.of());
        initializer = new PredefinedClientInitializer(clientStore, properties);

        // Act
        initializer.initializeClients();

        // Assert
        verify(clientStore, never()).register(any());
    }

    @Test
    void initializeClients_whenSingleClient_shouldRegisterOnceWithCorrectParams() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setEnabled(true);

        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties clientConfig =
            new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        clientConfig.setClientName("test-client");
        clientConfig.setClientId("test-client-id");
        clientConfig.setClientSecret("test-secret");
        clientConfig.setRedirectUris(List.of("https://example.com/callback"));
        clientConfig.setGrantTypes(List.of("authorization_code", "refresh_token"));
        clientConfig.setResponseTypes(List.of("code"));
        clientConfig.setTokenEndpointAuthMethod("client_secret_basic");
        clientConfig.setScopes(List.of("openid", "profile", "email"));

        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setClients(List.of(clientConfig));
        initializer = new PredefinedClientInitializer(clientStore, properties);

        // Act
        initializer.initializeClients();

        // Assert
        ArgumentCaptor<OAuth2RegisteredClient> captor = ArgumentCaptor.forClass(OAuth2RegisteredClient.class);
        verify(clientStore, times(1)).register(captor.capture());

        OAuth2RegisteredClient registeredClient = captor.getValue();
        assertThat(registeredClient.getClientId()).isEqualTo("test-client-id");
        assertThat(registeredClient.getClientSecret()).isEqualTo("test-secret");
        assertThat(registeredClient.getClientName()).isEqualTo("test-client");
        assertThat(registeredClient.getRedirectUris()).containsExactly("https://example.com/callback");
        assertThat(registeredClient.getGrantTypes()).containsExactly("authorization_code", "refresh_token");
        assertThat(registeredClient.getResponseTypes()).containsExactly("code");
        assertThat(registeredClient.getTokenEndpointAuthMethod()).isEqualTo("client_secret_basic");
        assertThat(registeredClient.getScope()).isEqualTo("openid profile email");
    }

    @Test
    void initializeClients_whenMultipleClients_shouldRegisterAllClients() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setEnabled(true);

        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties client1 =
            new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        client1.setClientName("client-1");
        client1.setClientId("client-id-1");
        client1.setClientSecret("secret-1");
        client1.setRedirectUris(List.of("https://client1.example.com/callback"));
        client1.setGrantTypes(List.of("authorization_code"));
        client1.setResponseTypes(List.of("code"));
        client1.setTokenEndpointAuthMethod("client_secret_basic");
        client1.setScopes(List.of("openid"));

        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties client2 =
            new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        client2.setClientName("client-2");
        client2.setClientId("client-id-2");
        client2.setClientSecret("secret-2");
        client2.setRedirectUris(List.of("https://client2.example.com/callback"));
        client2.setGrantTypes(List.of("client_credentials"));
        client2.setResponseTypes(List.of());
        client2.setTokenEndpointAuthMethod("client_secret_post");
        client2.setScopes(List.of("api.read", "api.write"));

        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setClients(List.of(client1, client2));
        initializer = new PredefinedClientInitializer(clientStore, properties);

        // Act
        initializer.initializeClients();

        // Assert
        ArgumentCaptor<OAuth2RegisteredClient> captor = ArgumentCaptor.forClass(OAuth2RegisteredClient.class);
        verify(clientStore, times(2)).register(captor.capture());

        List<OAuth2RegisteredClient> registeredClients = captor.getAllValues();
        assertThat(registeredClients).hasSize(2);

        assertThat(registeredClients.get(0).getClientId()).isEqualTo("client-id-1");
        assertThat(registeredClients.get(0).getClientName()).isEqualTo("client-1");

        assertThat(registeredClients.get(1).getClientId()).isEqualTo("client-id-2");
        assertThat(registeredClients.get(1).getClientName()).isEqualTo("client-2");
    }

    @Test
    void initializeClients_whenClientIdNull_shouldUseClientNameAsClientId() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setEnabled(true);

        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties clientConfig =
            new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        clientConfig.setClientName("my-client");
        clientConfig.setClientId(null);
        clientConfig.setClientSecret("my-secret");
        clientConfig.setRedirectUris(List.of("https://example.com/callback"));
        clientConfig.setGrantTypes(List.of("authorization_code"));
        clientConfig.setResponseTypes(List.of("code"));
        clientConfig.setTokenEndpointAuthMethod("client_secret_basic");
        clientConfig.setScopes(List.of("openid"));

        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setClients(List.of(clientConfig));
        initializer = new PredefinedClientInitializer(clientStore, properties);

        // Act
        initializer.initializeClients();

        // Assert
        ArgumentCaptor<OAuth2RegisteredClient> captor = ArgumentCaptor.forClass(OAuth2RegisteredClient.class);
        verify(clientStore, times(1)).register(captor.capture());

        OAuth2RegisteredClient registeredClient = captor.getValue();
        assertThat(registeredClient.getClientId()).isEqualTo("my-client");
        assertThat(registeredClient.getClientName()).isEqualTo("my-client");
    }

    @Test
    void initializeClients_whenRegisterFails_shouldThrowRuntimeException() {
        // Arrange
        OpenAgentAuthProperties properties = new OpenAgentAuthProperties();
        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setEnabled(true);

        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties clientConfig =
            new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        clientConfig.setClientName("failing-client");
        clientConfig.setClientId("failing-client-id");
        clientConfig.setClientSecret("secret");
        clientConfig.setRedirectUris(List.of("https://example.com/callback"));
        clientConfig.setGrantTypes(List.of("authorization_code"));
        clientConfig.setResponseTypes(List.of("code"));
        clientConfig.setTokenEndpointAuthMethod("client_secret_basic");
        clientConfig.setScopes(List.of("openid"));

        properties.getCapabilities().getOAuth2Server().getAutoRegisterClients().setClients(List.of(clientConfig));
        initializer = new PredefinedClientInitializer(clientStore, properties);

        doThrow(new IllegalArgumentException("Registration failed")).when(clientStore).register(any());

        // Act & Assert
        assertThatThrownBy(() -> initializer.initializeClients())
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Failed to auto-register client: failing-client")
            .hasCauseInstanceOf(IllegalArgumentException.class);
    }
}
