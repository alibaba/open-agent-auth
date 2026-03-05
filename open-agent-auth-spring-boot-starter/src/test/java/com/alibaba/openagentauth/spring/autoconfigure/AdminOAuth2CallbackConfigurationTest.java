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
package com.alibaba.openagentauth.spring.autoconfigure;

import com.alibaba.openagentauth.core.model.oauth2.token.TokenResponse;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AdminAutoConfiguration.AdminOAuth2CallbackConfiguration}
 * and the {@code AdminFrameworkOAuth2TokenClientAdapter} inner class.
 * <p>
 * These tests cover the fallback OAuth2 callback beans that are created when
 * no role-specific {@link OAuth2CallbackService} is available (e.g., agent-idp role).
 * </p>
 *
 * @since 1.0
 * @see AdminAutoConfiguration
 */
@DisplayName("AdminOAuth2CallbackConfiguration Tests")
@ExtendWith(MockitoExtension.class)
class AdminOAuth2CallbackConfigurationTest {

    private OpenAgentAuthProperties rootProperties;
    private AdminAutoConfiguration.AdminOAuth2CallbackConfiguration callbackConfiguration;

    @Mock
    private ServiceEndpointResolver serviceEndpointResolver;

    @Mock
    private SessionMappingBizService sessionMappingBizService;

    @BeforeEach
    void setUp() {
        rootProperties = new OpenAgentAuthProperties();
        rootProperties.setEnabled(false);
        rootProperties.getCapabilities().getOAuth2Client().setClientId("test-client-id");
        rootProperties.getCapabilities().getOAuth2Client().setClientSecret("test-client-secret");

        // Configure a User IDP peer so resolveUserIdpServiceName() can find it
        JwksConsumerProperties consumerProps = new JwksConsumerProperties();
        consumerProps.setIssuer("http://localhost:8083");
        rootProperties.getInfrastructures().getJwks().getConsumers()
                .put("agent-user-idp", consumerProps);

        callbackConfiguration = new AdminAutoConfiguration.AdminOAuth2CallbackConfiguration();
    }

    @Nested
    @DisplayName("serviceEndpointResolver() Bean")
    class ServiceEndpointResolverBeanTests {

        @Test
        @DisplayName("Should create ServiceEndpointResolver from properties")
        void shouldCreateServiceEndpointResolverFromProperties() {
            // Act
            ServiceEndpointResolver resolver = callbackConfiguration.serviceEndpointResolver(rootProperties);

            // Assert
            assertThat(resolver).isNotNull();
        }

        @Test
        @DisplayName("Should create resolver with empty service discovery config")
        void shouldCreateResolverWithEmptyServiceDiscoveryConfig() {
            // Arrange - no services configured
            OpenAgentAuthProperties emptyProperties = new OpenAgentAuthProperties();
            emptyProperties.setEnabled(false);

            // Act
            ServiceEndpointResolver resolver = callbackConfiguration.serviceEndpointResolver(emptyProperties);

            // Assert
            assertThat(resolver).isNotNull();
        }
    }

    @Nested
    @DisplayName("frameworkOAuth2TokenClient() Bean")
    class FrameworkOAuth2TokenClientBeanTests {

        @Test
        @DisplayName("Should create FrameworkOAuth2TokenClient with agent-user-idp service")
        void shouldCreateTokenClientWithAgentUserIdpService() {
            // Act
            FrameworkOAuth2TokenClient tokenClient = callbackConfiguration
                    .frameworkOAuth2TokenClient(serviceEndpointResolver, rootProperties);

            // Assert
            assertThat(tokenClient).isNotNull();
        }

        @Test
        @DisplayName("Should create FrameworkOAuth2TokenClient with as-user-idp service")
        void shouldCreateTokenClientWithAsUserIdpService() {
            // Arrange - only as-user-idp configured
            OpenAgentAuthProperties asUserIdpProperties = new OpenAgentAuthProperties();
            asUserIdpProperties.setEnabled(false);
            asUserIdpProperties.getCapabilities().getOAuth2Client().setClientId("test-client");
            asUserIdpProperties.getCapabilities().getOAuth2Client().setClientSecret("test-secret");

            JwksConsumerProperties consumerProps = new JwksConsumerProperties();
            consumerProps.setIssuer("http://localhost:8084");
            asUserIdpProperties.getInfrastructures().getJwks().getConsumers()
                    .put("as-user-idp", consumerProps);

            // Act
            FrameworkOAuth2TokenClient tokenClient = callbackConfiguration
                    .frameworkOAuth2TokenClient(serviceEndpointResolver, asUserIdpProperties);

            // Assert
            assertThat(tokenClient).isNotNull();
        }

        @Test
        @DisplayName("Should throw when no User IDP is configured")
        void shouldThrowWhenNoUserIdpConfigured() {
            // Arrange - no User IDP peers
            OpenAgentAuthProperties noIdpProperties = new OpenAgentAuthProperties();
            noIdpProperties.setEnabled(false);
            noIdpProperties.getCapabilities().getOAuth2Client().setClientId("test-client");

            // Act & Assert
            assertThatThrownBy(() -> callbackConfiguration
                    .frameworkOAuth2TokenClient(serviceEndpointResolver, noIdpProperties))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("No User IDP peer configured");
        }

        @Test
        @DisplayName("Should throw when User IDP has blank issuer")
        void shouldThrowWhenUserIdpHasBlankIssuer() {
            // Arrange - User IDP with blank issuer
            OpenAgentAuthProperties blankIssuerProperties = new OpenAgentAuthProperties();
            blankIssuerProperties.setEnabled(false);
            blankIssuerProperties.getCapabilities().getOAuth2Client().setClientId("test-client");

            JwksConsumerProperties consumerProps = new JwksConsumerProperties();
            consumerProps.setIssuer("   ");
            blankIssuerProperties.getInfrastructures().getJwks().getConsumers()
                    .put("agent-user-idp", consumerProps);

            // Act & Assert
            assertThatThrownBy(() -> callbackConfiguration
                    .frameworkOAuth2TokenClient(serviceEndpointResolver, blankIssuerProperties))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("No User IDP peer configured");
        }
    }

    @Nested
    @DisplayName("callbackService() Bean")
    class CallbackServiceBeanTests {

        @Mock
        private FrameworkOAuth2TokenClient frameworkOAuth2TokenClient;

        @Test
        @DisplayName("Should create OAuth2CallbackService with default callback endpoint")
        void shouldCreateCallbackServiceWithDefaultEndpoint() {
            // Arrange - no custom callback endpoint configured
            OpenAgentAuthProperties defaultProperties = new OpenAgentAuthProperties();
            defaultProperties.setEnabled(false);

            // Act
            OAuth2CallbackService callbackService = callbackConfiguration
                    .callbackService(frameworkOAuth2TokenClient, sessionMappingBizService, defaultProperties);

            // Assert
            assertThat(callbackService).isNotNull();
        }

        @Test
        @DisplayName("Should create OAuth2CallbackService with custom callback endpoint")
        void shouldCreateCallbackServiceWithCustomEndpoint() {
            // Arrange
            rootProperties.getCapabilities().getOAuth2Client().getCallback().setEndpoint("/custom-callback");

            // Act
            OAuth2CallbackService callbackService = callbackConfiguration
                    .callbackService(frameworkOAuth2TokenClient, sessionMappingBizService, rootProperties);

            // Assert
            assertThat(callbackService).isNotNull();
        }

        @Test
        @DisplayName("Should create OAuth2CallbackService with blank callback endpoint falling back to default")
        void shouldCreateCallbackServiceWithBlankEndpointFallingBackToDefault() {
            // Arrange
            rootProperties.getCapabilities().getOAuth2Client().getCallback().setEndpoint("   ");

            // Act
            OAuth2CallbackService callbackService = callbackConfiguration
                    .callbackService(frameworkOAuth2TokenClient, sessionMappingBizService, rootProperties);

            // Assert
            assertThat(callbackService).isNotNull();
        }
    }

    @Nested
    @DisplayName("AdminFrameworkOAuth2TokenClientAdapter Tests")
    class AdapterExchangeCodeForTokenTests {

        @Mock
        private OAuth2TokenClient coreTokenClient;

        @Test
        @DisplayName("Should exchange code for token with idToken present")
        void shouldExchangeCodeForTokenWithIdTokenPresent() {
            // Arrange
            TokenResponse coreResponse = TokenResponse.builder()
                    .accessToken("access-token-123")
                    .tokenType("Bearer")
                    .expiresIn(7200L)
                    .idToken("id-token-abc")
                    .build();
            when(coreTokenClient.exchangeCodeForToken(any())).thenReturn(coreResponse);

            FrameworkOAuth2TokenClient adapter = createAdapterViaConfiguration(coreTokenClient);

            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code("auth-code-xyz")
                    .state("user:random123")
                    .redirectUri("http://localhost:8080/callback")
                    .clientId("test-client-id")
                    .build();

            // Act
            AuthenticationResponse response = adapter.exchangeCodeForToken(request);

            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isSuccess()).isTrue();
            assertThat(response.getIdToken()).isEqualTo("id-token-abc");
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(7200L);
        }

        @Test
        @DisplayName("Should fall back to accessToken when idToken is null")
        void shouldFallBackToAccessTokenWhenIdTokenIsNull() {
            // Arrange
            TokenResponse coreResponse = TokenResponse.builder()
                    .accessToken("access-token-only")
                    .tokenType("Bearer")
                    .expiresIn(3600L)
                    .build();
            when(coreTokenClient.exchangeCodeForToken(any())).thenReturn(coreResponse);

            FrameworkOAuth2TokenClient adapter = createAdapterViaConfiguration(coreTokenClient);

            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code("auth-code-xyz")
                    .state("user:random123")
                    .redirectUri("http://localhost:8080/callback")
                    .clientId("test-client-id")
                    .build();

            // Act
            AuthenticationResponse response = adapter.exchangeCodeForToken(request);

            // Assert
            assertThat(response.getIdToken()).isEqualTo("access-token-only");
        }

        @Test
        @DisplayName("Should use default expiresIn when coreResponse expiresIn is null")
        void shouldUseDefaultExpiresInWhenNull() {
            // Arrange
            TokenResponse coreResponse = TokenResponse.builder()
                    .accessToken("access-token")
                    .tokenType("Bearer")
                    .build();
            when(coreTokenClient.exchangeCodeForToken(any())).thenReturn(coreResponse);

            FrameworkOAuth2TokenClient adapter = createAdapterViaConfiguration(coreTokenClient);

            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code("auth-code")
                    .state("user:state")
                    .redirectUri("http://localhost/callback")
                    .clientId("client")
                    .build();

            // Act
            AuthenticationResponse response = adapter.exchangeCodeForToken(request);

            // Assert
            assertThat(response.getExpiresIn()).isEqualTo(3600L);
        }

        @Test
        @DisplayName("Should correctly map request fields to core TokenRequest")
        void shouldCorrectlyMapRequestFieldsToCoreTokenRequest() {
            // Arrange
            TokenResponse coreResponse = TokenResponse.builder()
                    .accessToken("token")
                    .tokenType("Bearer")
                    .expiresIn(1800L)
                    .idToken("id-token")
                    .build();
            when(coreTokenClient.exchangeCodeForToken(any())).thenReturn(coreResponse);

            FrameworkOAuth2TokenClient adapter = createAdapterViaConfiguration(coreTokenClient);

            ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
                    .code("my-auth-code")
                    .state("user:my-state")
                    .redirectUri("https://example.com/callback")
                    .clientId("my-client-id")
                    .build();

            // Act
            adapter.exchangeCodeForToken(request);

            // Assert - verify the core request was built correctly
            ArgumentCaptor<com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest> captor =
                    ArgumentCaptor.forClass(com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest.class);
            verify(coreTokenClient).exchangeCodeForToken(captor.capture());

            com.alibaba.openagentauth.core.model.oauth2.token.TokenRequest capturedRequest = captor.getValue();
            assertThat(capturedRequest.getGrantType()).isEqualTo("authorization_code");
            assertThat(capturedRequest.getCode()).isEqualTo("my-auth-code");
            assertThat(capturedRequest.getRedirectUri()).isEqualTo("https://example.com/callback");
            assertThat(capturedRequest.getClientId()).isEqualTo("my-client-id");
        }

        /**
         * Creates an {@code AdminFrameworkOAuth2TokenClientAdapter} instance via
         * the configuration's {@code frameworkOAuth2TokenClient()} method.
         * <p>
         * Since the adapter is a private inner class, we cannot instantiate it directly.
         * Instead, we use a custom {@link ServiceEndpointResolver} and inject the mock
         * {@link OAuth2TokenClient} indirectly by leveraging the fact that
         * {@code DefaultOAuth2TokenClient} delegates to the resolver. However, for
         * unit testing the adapter's mapping logic, we use reflection to create the
         * adapter directly with our mock.
         * </p>
         */
        private FrameworkOAuth2TokenClient createAdapterViaConfiguration(OAuth2TokenClient mockTokenClient) {
            try {
                Class<?> adapterClass = Class.forName(
                        "com.alibaba.openagentauth.spring.autoconfigure.AdminAutoConfiguration$AdminFrameworkOAuth2TokenClientAdapter");
                var constructor = adapterClass.getDeclaredConstructor(OAuth2TokenClient.class);
                constructor.setAccessible(true);
                return (FrameworkOAuth2TokenClient) constructor.newInstance(mockTokenClient);
            } catch (Exception e) {
                throw new RuntimeException("Failed to create AdminFrameworkOAuth2TokenClientAdapter via reflection", e);
            }
        }
    }
}
