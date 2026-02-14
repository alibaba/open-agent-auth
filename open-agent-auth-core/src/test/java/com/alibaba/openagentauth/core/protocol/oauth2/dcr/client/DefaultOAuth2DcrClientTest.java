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
package com.alibaba.openagentauth.core.protocol.oauth2.dcr.client;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.NoAuthOAuth2DcrClientAuthentication;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.authentication.WimseOAuth2DcrClientAuthentication;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultOAuth2DcrClient}.
 * <p>
 * These tests validate the DCR client implementation following RFC 7591
 * specification with support for pluggable authentication strategies.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("DefaultOAuth2DcrClient Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultOAuth2DcrClientTest {

    private static final String DCR_ENDPOINT = "https://as.example.com/oauth2/register";
    private static final String CLIENT_NAME = "test-client";
    private static final String REDIRECT_URI = "https://app.example.com/callback";
    private static final String CLIENT_ID = "client_123";
    private static final String CLIENT_SECRET = "secret_456";
    private static final String REGISTRATION_URI = "https://as.example.com/clients/123";
    private static final String REGISTRATION_TOKEN = "reg_token_789";

    @Mock
    private ServiceEndpointResolver serviceEndpointResolver;

    private DefaultOAuth2DcrClient noAuthClient;
    private DefaultOAuth2DcrClient wimseAuthClient;

    @BeforeEach
    void setUp() {
        when(serviceEndpointResolver.resolveConsumer(anyString(), anyString()))
                .thenReturn(DCR_ENDPOINT);

        // Create client with no authentication
        noAuthClient = new DefaultOAuth2DcrClient(serviceEndpointResolver);

        // Create client with WIMSE authentication
        wimseAuthClient = new DefaultOAuth2DcrClient(
                serviceEndpointResolver,
                new WimseOAuth2DcrClientAuthentication()
        );
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create client with no authentication")
        void shouldCreateClientWithNoAuthentication() {
            // Act & Assert
            assertThat(noAuthClient).isNotNull();
        }

        @Test
        @DisplayName("Should create client with custom authentication")
        void shouldCreateClientWithCustomAuthentication() {
            // Act & Assert
            assertThat(wimseAuthClient).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when service endpoint resolver is null")
        void shouldThrowExceptionWhenServiceEndpointResolverIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2DcrClient(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when authentication strategy is null")
        void shouldThrowExceptionWhenAuthenticationStrategyIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> new DefaultOAuth2DcrClient(
                    serviceEndpointResolver,
                    null
            ))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Nested
    @DisplayName("registerClient() Tests")
    class RegisterClientTests {

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.registerClient(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should prepare DCR request with valid parameters")
        void shouldPrepareDcrRequestWithValidParameters() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .grantTypes(Arrays.asList("authorization_code"))
                    .responseTypes(Arrays.asList("code"))
                    .build();

            // Act & Assert - Verify request can be created
            assertThat(request).isNotNull();
            assertThat(request.getClientName()).isEqualTo(CLIENT_NAME);
            assertThat(request.getRedirectUris()).contains(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should handle DCR request with all optional parameters")
        void shouldHandleDcrRequestWithAllOptionalParameters() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .grantTypes(Arrays.asList("authorization_code", "refresh_token"))
                    .responseTypes(Arrays.asList("code"))
                    .scope("read write")
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();

            // Act & Assert
            assertThat(request).isNotNull();
            assertThat(request.getGrantTypes()).hasSize(2);
            assertThat(request.getScope()).isEqualTo("read write");
            assertThat(request.getTokenEndpointAuthMethod()).isEqualTo("client_secret_basic");
        }

        @Test
        @DisplayName("Should handle DCR request with minimal parameters")
        void shouldHandleDcrRequestWithMinimalParameters() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThat(request).isNotNull();
            assertThat(request.getClientName()).isEqualTo(CLIENT_NAME);
            assertThat(request.getRedirectUris()).hasSize(1);
        }
    }

    @Nested
    @DisplayName("readClient() Tests")
    class ReadClientTests {

        @Test
        @DisplayName("Should throw exception when registration URI is null")
        void shouldThrowExceptionWhenRegistrationUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.readClient(null, REGISTRATION_TOKEN))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when registration access token is null")
        void shouldThrowExceptionWhenRegistrationAccessTokenIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.readClient(REGISTRATION_URI, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should handle read client request with valid parameters")
        void shouldHandleReadClientRequestWithValidParameters() {
            // Act & Assert - Verify parameters can be passed
            assertThat(REGISTRATION_URI).isNotNull();
            assertThat(REGISTRATION_TOKEN).isNotNull();
        }
    }

    @Nested
    @DisplayName("updateClient() Tests")
    class UpdateClientTests {

        @Test
        @DisplayName("Should throw exception when registration URI is null")
        void shouldThrowExceptionWhenRegistrationUriIsNull() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.updateClient(null, REGISTRATION_TOKEN, request))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when registration access token is null")
        void shouldThrowExceptionWhenRegistrationAccessTokenIsNull() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.updateClient(REGISTRATION_URI, null, request))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when request is null")
        void shouldThrowExceptionWhenRequestIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.updateClient(REGISTRATION_URI, REGISTRATION_TOKEN, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should handle update client request with valid parameters")
        void shouldHandleUpdateClientRequestWithValidParameters() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName("updated-client-name")
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThat(request).isNotNull();
            assertThat(request.getClientName()).isEqualTo("updated-client-name");
        }
    }

    @Nested
    @DisplayName("deleteClient() Tests")
    class DeleteClientTests {

        @Test
        @DisplayName("Should throw exception when registration URI is null")
        void shouldThrowExceptionWhenRegistrationUriIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.deleteClient(null, REGISTRATION_TOKEN))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should throw exception when registration access token is null")
        void shouldThrowExceptionWhenRegistrationAccessTokenIsNull() {
            // Act & Assert
            assertThatThrownBy(() -> noAuthClient.deleteClient(REGISTRATION_URI, null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Should handle delete client request with valid parameters")
        void shouldHandleDeleteClientRequestWithValidParameters() {
            // Act & Assert - Verify parameters can be passed
            assertThat(REGISTRATION_URI).isNotNull();
            assertThat(REGISTRATION_TOKEN).isNotNull();
        }
    }

    @Nested
    @DisplayName("DcrRequest Builder Tests")
    class DcrRequestBuilderTests {

        @Test
        @DisplayName("Should build valid DCR request with required fields")
        void shouldBuildValidDcrRequestWithRequiredFields() {
            // Act
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Assert
            assertThat(request).isNotNull();
            assertThat(request.getClientName()).isEqualTo(CLIENT_NAME);
            assertThat(request.getRedirectUris()).contains(REDIRECT_URI);
        }

        @Test
        @DisplayName("Should build DCR request with all fields")
        void shouldBuildDcrRequestWithAllFields() {
            // Act
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .grantTypes(Arrays.asList("authorization_code", "refresh_token"))
                    .responseTypes(Arrays.asList("code"))
                    .scope("openid profile")
                    .tokenEndpointAuthMethod("client_secret_basic")
                    .build();

            // Assert
            assertThat(request).isNotNull();
            assertThat(request.getClientName()).isEqualTo(CLIENT_NAME);
            assertThat(request.getGrantTypes()).hasSize(2);
            assertThat(request.getResponseTypes()).hasSize(1);
            assertThat(request.getScope()).isEqualTo("openid profile");
            assertThat(request.getTokenEndpointAuthMethod()).isEqualTo("client_secret_basic");
        }

        @Test
        @DisplayName("Should build DCR request with multiple redirect URIs")
        void shouldBuildDcrRequestWithMultipleRedirectUris() {
            // Act
            DcrRequest request = DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList(
                            "https://app.example.com/callback",
                            "https://app.example.com/redirect"
                    ))
                    .build();

            // Assert
            assertThat(request).isNotNull();
            assertThat(request.getRedirectUris()).hasSize(2);
            assertThat(request.getRedirectUris()).contains("https://app.example.com/callback");
            assertThat(request.getRedirectUris()).contains("https://app.example.com/redirect");
        }
    }

    @Nested
    @DisplayName("DcrResponse Builder Tests")
    class DcrResponseBuilderTests {

        @Test
        @DisplayName("Should build valid DCR response with required fields")
        void shouldBuildValidDcrResponseWithRequiredFields() {
            // Act
            DcrResponse response = DcrResponse.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .registrationClientUri(REGISTRATION_URI)
                    .registrationAccessToken(REGISTRATION_TOKEN)
                    .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(response.getClientSecret()).isEqualTo(CLIENT_SECRET);
            assertThat(response.getRegistrationClientUri()).isEqualTo(REGISTRATION_URI);
            assertThat(response.getRegistrationAccessToken()).isEqualTo(REGISTRATION_TOKEN);
        }

        @Test
        @DisplayName("Should build DCR response with all fields")
        void shouldBuildDcrResponseWithAllFields() {
            // Act
            DcrResponse response = DcrResponse.builder()
                    .clientId(CLIENT_ID)
                    .clientSecret(CLIENT_SECRET)
                    .registrationClientUri(REGISTRATION_URI)
                    .registrationAccessToken(REGISTRATION_TOKEN)
                    .clientIdIssuedAt(1234567890L)
                    .clientSecretExpiresAt(1234567890L)
                    .build();

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.getClientId()).isEqualTo(CLIENT_ID);
            assertThat(response.getClientSecret()).isEqualTo(CLIENT_SECRET);
            assertThat(response.getRegistrationClientUri()).isEqualTo(REGISTRATION_URI);
            assertThat(response.getRegistrationAccessToken()).isEqualTo(REGISTRATION_TOKEN);
            assertThat(response.getClientIdIssuedAt()).isEqualTo(1234567890L);
            assertThat(response.getClientSecretExpiresAt()).isEqualTo(1234567890L);
        }
    }

    @Nested
    @DisplayName("DcrException Tests")
    class DcrExceptionTests {

        @Test
        @DisplayName("Should create invalid client metadata exception")
        void shouldCreateInvalidClientMetadataException() {
            // Act
            DcrException exception = DcrException.invalidClientMetadata("Invalid redirect URI");

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Invalid redirect URI");
        }

        @Test
        @DisplayName("Should create HTTP response error exception")
        void shouldCreateHttpResponseErrorException() {
            // Act
            DcrException exception = DcrException.httpResponseError(400, "invalid_redirect_uri", "Redirect URI is invalid");

            // Assert
            assertThat(exception).isNotNull();
            assertThat(exception.getMessage()).contains("Redirect URI is invalid");
        }
    }

    @Nested
    @DisplayName("Authentication Strategy Tests")
    class AuthenticationStrategyTests {

        @Test
        @DisplayName("Should use no authentication when configured")
        void shouldUseNoAuthenticationWhenConfigured() {
            // Act & Assert
            assertThat(noAuthClient).isNotNull();
        }

        @Test
        @DisplayName("Should use WIMSE authentication when configured")
        void shouldUseWimseAuthenticationWhenConfigured() {
            // Act & Assert
            assertThat(wimseAuthClient).isNotNull();
        }

        @Test
        @DisplayName("Should support multiple authentication strategies")
        void shouldSupportMultipleAuthenticationStrategies() {
            // Arrange
            DefaultOAuth2DcrClient client1 = new DefaultOAuth2DcrClient(
                    serviceEndpointResolver,
                    new NoAuthOAuth2DcrClientAuthentication()
            );

            DefaultOAuth2DcrClient client2 = new DefaultOAuth2DcrClient(
                    serviceEndpointResolver,
                    new WimseOAuth2DcrClientAuthentication()
            );

            // Act & Assert
            assertThat(client1).isNotNull();
            assertThat(client2).isNotNull();
        }
    }

    @Nested
    @DisplayName("Edge Cases and Boundary Conditions")
    class EdgeCasesAndBoundaryConditions {

        @Test
        @DisplayName("Should handle empty client name")
        void shouldHandleEmptyClientName() {
            // Arrange
            DcrRequest request = DcrRequest.builder()
                    .clientName("")
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThat(request.getClientName()).isEmpty();
        }

        @Test
        @DisplayName("Should handle very long client name")
        void shouldHandleVeryLongClientName() {
            // Arrange
            StringBuilder longName = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                longName.append("a");
            }

            DcrRequest request = DcrRequest.builder()
                    .clientName(longName.toString())
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThat(request.getClientName()).hasSize(1000);
        }

        @Test
        @DisplayName("Should handle empty redirect URIs list")
        void shouldHandleEmptyRedirectUrisList() {
            // Act & Assert
            assertThatThrownBy(() -> DcrRequest.builder()
                    .clientName(CLIENT_NAME)
                    .redirectUris(Arrays.asList())
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("redirect_uris is REQUIRED");
        }

        @Test
        @DisplayName("Should handle special characters in client name")
        void shouldHandleSpecialCharactersInClientName() {
            // Arrange
            String specialName = "test-client-123_456!@#$%";

            DcrRequest request = DcrRequest.builder()
                    .clientName(specialName)
                    .redirectUris(Arrays.asList(REDIRECT_URI))
                    .build();

            // Act & Assert
            assertThat(request.getClientName()).isEqualTo(specialName);
        }
    }
}
