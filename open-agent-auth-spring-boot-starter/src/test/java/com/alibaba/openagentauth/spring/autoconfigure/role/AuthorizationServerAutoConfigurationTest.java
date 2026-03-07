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
package com.alibaba.openagentauth.spring.autoconfigure.role;

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweDecoder;
import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.DefaultOAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.DefaultOAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.InMemoryOAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.DefaultOAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.InMemoryOAuth2ParRequestStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.OAuth2ParRequestStore;
import com.alibaba.openagentauth.core.protocol.oauth2.token.aoat.AoatTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.aoat.DefaultAoatTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oauth2.token.client.OAuth2TokenClient;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.DefaultOAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.InMemoryUserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.protocol.vc.VcVerifier;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.token.aoat.AoatGenerator;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.framework.actor.AuthorizationServer;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuthorizationServerAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of AuthorizationServerAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AuthorizationServerAutoConfiguration Tests")
class AuthorizationServerAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            TestCoreConfiguration.class,
            com.alibaba.openagentauth.spring.autoconfigure.capability.SharedCapabilityAutoConfiguration.class,
            AuthorizationServerAutoConfiguration.class
        ))
        .withPropertyValues(
            "spring.main.allow-bean-definition-overriding=true",
            "open-agent-auth.enabled=true",
            "open-agent-auth.role=authorization-server",
            "open-agent-auth.roles.authorization-server.enabled=true",
            "open-agent-auth.roles.authorization-server.issuer=http://localhost:8080",
            "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
            "open-agent-auth.infrastructures.key-management.keys.aoat-signing.key-id=aoat-signing-key",
            "open-agent-auth.infrastructures.key-management.keys.aoat-signing.algorithm=RS256",
            "open-agent-auth.infrastructures.key-management.keys.wit-verification.key-id=wit-verification-key",
            "open-agent-auth.infrastructures.key-management.keys.wit-verification.algorithm=ES256",
            "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://localhost:8080",
            "open-agent-auth.infrastructures.service-discovery.services.resource-server.base-url=http://localhost:8080",
            "open-agent-auth.infrastructures.jwks.consumers.as-user-idp.issuer=http://localhost:8080",
            "open-agent-auth.infrastructures.jwks.consumers.as-user-idp.jwks-endpoint=http://localhost:8080/.well-known/jwks.json",
            "open-agent-auth.capabilities.oauth2-client.client-id=test-client-id",
            "open-agent-auth.capabilities.oauth2-client.client-secret=test-client-secret"
        );

    @TestConfiguration
    static class TestCoreConfiguration {
        
        @Bean
        @ConditionalOnMissingBean
        public ServiceEndpointResolver serviceEndpointResolver(ServiceProperties serviceProperties) {
            return new DefaultServiceEndpointResolver(serviceProperties);
        }

        @Bean
        public KeyManager keyManager() {
            return new DefaultKeyManager(
                new InMemoryKeyStore()
            );
        }

        @Bean
        public PromptDecryptionService promptDecryptionService(KeyManager keyManager) {
            try {
                RSAKey rsaKey = (RSAKey) keyManager.getOrGenerateKey(
                    "prompt-encryption-key", 
                    KeyAlgorithm.RS256
                );
                PrivateKey decryptionKey = rsaKey.toRSAPrivateKey();
                return new PromptDecryptionService(
                    new NimbusJweDecoder(decryptionKey),
                    false
                );
            } catch (Exception e) {
                throw new IllegalStateException("Failed to initialize PromptDecryptionService", e);
            }
        }

        @Bean
        public SessionManager sessionManager() {
            return new SessionManager();
        }

        @Bean
        public TrustDomain trustDomain() {
            String trustDomain = "wimse://test.trust.domain";
            return new TrustDomain(trustDomain);
        }



        @Bean
        public FrameworkOAuth2TokenClient frameworkOAuth2TokenClient(
            ServiceEndpointResolver serviceEndpointResolver,
            TokenService tokenService) {
            // Create a mock implementation for testing
            return new FrameworkOAuth2TokenClient() {
                @Override
                public AuthenticationResponse exchangeCodeForToken(
                    ExchangeCodeForTokenRequest request) {
                    // Mock implementation - return a simple response
                    return AuthenticationResponse.builder()
                        .idToken("mock-id-token")
                        .build();
                }
            };
        }

        @Bean
        public TokenService tokenService(
            KeyManager keyManager,
            TrustDomain trustDomain) {
            try {
                JWK signingJWK = (JWK) keyManager.getOrGenerateKey(
                    "wit-signing-key", 
                    KeyAlgorithm.ES256
                );
                return new TokenService(
                    signingJWK, 
                    trustDomain, 
                    JWSAlgorithm.ES256
                );
            } catch (Exception e) {
                throw new IllegalStateException("Failed to initialize WIT signing key", e);
            }
        }

        @Bean
        public WitValidator witValidator(KeyManager keyManager, TrustDomain trustDomain) {
            return new WitValidator(keyManager, "agent-idp-verification-key", trustDomain);
        }

        @Bean
        public IdTokenValidator idTokenValidator(KeyManager keyManager) {
            return new DefaultIdTokenValidator(keyManager, "id-token-signing-key");
        }

        @Bean
        public UserRegistry userRegistry() {
            InMemoryUserRegistry registry = new InMemoryUserRegistry();
            // Add test users
            registry.addUser("testuser", "testpass123", "user_test_001", "testuser@example.com", "Test User");
            registry.addUser("admin", "admin123", "user_admin_001", "admin@example.com", "Admin User");
            return registry;
        }

        @Bean
        public ServiceProperties serviceProperties() {
            ServiceProperties props = 
                new ServiceProperties();
            props.postProcess();
            return props;
        }

        @Bean
        @ConditionalOnMissingBean
        public OAuth2ClientStore oAuth2ClientStore() {
            return new InMemoryOAuth2ClientStore();
        }
    }

    @Nested
    @DisplayName("OAuth2ParRequestStore Bean Tests")
    class OAuth2ParRequestStoreBeanTests {

        @Test
        @DisplayName("Should create OAuth2ParRequestStore bean when not defined")
        void shouldCreateOAuth2ParRequestStoreBeanWhenNotDefined() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.role=authorization-server",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.as-user-idp.issuer=http://as-user-idp:8080",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-client-secret"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ParRequestStore.class);
                    OAuth2ParRequestStore store = context.getBean(OAuth2ParRequestStore.class);
                    assertThat(store).isInstanceOf(InMemoryOAuth2ParRequestStore.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2ParServer Bean Tests")
    class OAuth2ParServerBeanTests {

        @Test
        @DisplayName("Should create OAuth2ParServer bean when not defined")
        void shouldCreateOAuth2ParServerBeanWhenNotDefined() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.role=authorization-server",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.as-user-idp.issuer=http://as-user-idp:8080",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-client-secret"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ParServer.class);
                    OAuth2ParServer server = context.getBean(OAuth2ParServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2ParServer.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2AuthorizationCodeStorage Bean Tests")
    class OAuth2AuthorizationCodeStorageBeanTests {

        @Test
        @DisplayName("Should create OAuth2AuthorizationCodeStorage bean when not defined")
        void shouldCreateOAuth2AuthorizationCodeStorageBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2AuthorizationCodeStorage.class);
                    OAuth2AuthorizationCodeStorage storage = context.getBean(OAuth2AuthorizationCodeStorage.class);
                    assertThat(storage).isInstanceOf(InMemoryOAuth2AuthorizationCodeStorage.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2AuthorizationServer Bean Tests")
    class OAuth2AuthorizationServerBeanTests {

        @Test
        @DisplayName("Should create OAuth2AuthorizationServer bean when not defined")
        void shouldCreateOAuth2AuthorizationServerBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2AuthorizationServer.class);
                    OAuth2AuthorizationServer server = context.getBean(OAuth2AuthorizationServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2AuthorizationServer.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2TokenServer Bean Tests")
    class OAuth2TokenServerBeanTests {

        @Test
        @DisplayName("Should create OAuth2TokenServer bean when not defined")
        void shouldCreateOAuth2TokenServerBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                    OAuth2TokenServer server = context.getBean(OAuth2TokenServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2TokenServer.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2DcrServer Bean Tests")
    class OAuth2DcrServerBeanTests {

        @Test
        @DisplayName("Should create OAuth2DcrServer bean when not defined")
        void shouldCreateOAuth2DcrServerBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2DcrServer.class);
                    OAuth2DcrServer server = context.getBean(OAuth2DcrServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2DcrServer.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2DcrClientStore Bean Tests")
    class OAuth2DcrClientStoreBeanTests {

        @Test
        @DisplayName("Should create OAuth2DcrClientStore bean when not defined")
        void shouldCreateOAuth2DcrClientStoreBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2DcrClientStore.class);
                    OAuth2DcrClientStore store = context.getBean(OAuth2DcrClientStore.class);
                    assertThat(store).isInstanceOf(InMemoryOAuth2ClientStore.class);
                });
        }
    }

    @Nested
    @DisplayName("AoatTokenGenerator Bean Tests")
    class AoatTokenGeneratorBeanTests {

        @Test
        @DisplayName("Should create AoatTokenGenerator bean when not defined")
        void shouldCreateAoatTokenGeneratorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AoatTokenGenerator.class);
                    AoatTokenGenerator generator = context.getBean(AoatTokenGenerator.class);
                    assertThat(generator).isInstanceOf(DefaultAoatTokenGenerator.class);
                });
        }
    }

    @Nested
    @DisplayName("TokenGenerator Bean Tests")
    class TokenGeneratorBeanTests {

        @Test
        @DisplayName("Should create TokenGenerator bean when not defined")
        void shouldCreateTokenGeneratorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    TokenGenerator generator = context.getBean(TokenGenerator.class);
                    assertThat(generator).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("AoatGenerator Bean Tests")
    class AoatGeneratorBeanTests {

        @Test
        @DisplayName("Should create AoatGenerator bean when not defined")
        void shouldCreateAoatGeneratorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AoatGenerator.class);
                    AoatGenerator generator = context.getBean(AoatGenerator.class);
                    assertThat(generator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            contextRunner
                .withPropertyValues("open-agent-auth.roles.authorization-server.issuer=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure().getMessage())
                        .contains("Authorization Server issuer is not configured");
                });
        }
    }

    @Nested
    @DisplayName("VcVerifier Bean Tests")
    class VcVerifierBeanTests {

        @Test
        @DisplayName("Should create VcVerifier bean when not defined")
        void shouldCreateVcVerifierBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(VcVerifier.class);
                    VcVerifier verifier = context.getBean(VcVerifier.class);
                    assertThat(verifier).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("PolicyRegistry Bean Tests")
    class PolicyRegistryBeanTests {

        @Test
        @DisplayName("Should create PolicyRegistry bean when not defined")
        void shouldCreatePolicyRegistryBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(PolicyRegistry.class);
                    PolicyRegistry registry = context.getBean(PolicyRegistry.class);
                    assertThat(registry).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("BindingInstanceStore Bean Tests")
    class BindingInstanceStoreBeanTests {

        @Test
        @DisplayName("Should create BindingInstanceStore bean when not defined")
        void shouldCreateBindingInstanceStoreBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(BindingInstanceStore.class);
                    BindingInstanceStore store = context.getBean(BindingInstanceStore.class);
                    assertThat(store).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("ConsentPageProvider Bean Tests")
    class ConsentPageProviderBeanTests {

        @Test
        @DisplayName("Should create ConsentPageProvider bean when not defined")
        void shouldCreateConsentPageProviderBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(ConsentPageProvider.class);
                    ConsentPageProvider provider = context.getBean(ConsentPageProvider.class);
                    assertThat(provider).isInstanceOf(DefaultConsentPageProvider.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2CallbackController Bean Tests")
    class OAuth2CallbackControllerBeanTests {

        @Test
        @DisplayName("Should create OAuth2CallbackController bean when not defined")
        void shouldCreateOAuth2CallbackControllerBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2CallbackController.class);
                    OAuth2CallbackController controller = context.getBean(OAuth2CallbackController.class);
                    assertThat(controller).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when role is authorization-server")
        void shouldLoadWhenRoleIsAuthorizationServer() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ParServer.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                    assertThat(context).hasSingleBean(AoatTokenGenerator.class);
                });
        }

        @Test
        @DisplayName("Should not load when role is not authorization-server")
        void shouldNotLoadWhenRoleIsNotAuthorizationServer() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.authorization-server.enabled=false",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(OAuth2ParServer.class);
                    assertThat(context).doesNotHaveBean(AoatTokenGenerator.class);
                });
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind AuthorizationServerProperties correctly")
        void shouldBindAuthorizationServerPropertiesCorrectly() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.getCapabilities().getOAuth2Server()).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("New Properties Integration Tests")
    class NewPropertiesIntegrationTests {

        @Test
        @DisplayName("Should bind OperationAuthorizationProperties correctly")
        void shouldBindOperationAuthorizationPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    OperationAuthorizationProperties opAuth = properties.getCapabilities().getOperationAuthorization();
                    assertThat(opAuth).isNotNull();
                    assertThat(opAuth.getPromptEncryption()).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("UserAuthenticationInterceptor Bean Tests")
    class UserAuthenticationInterceptorBeanTests {

        @Test
        @DisplayName("Should create UserAuthenticationInterceptor bean when not defined")
        void shouldCreateUserAuthenticationInterceptorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(UserAuthenticationInterceptor.class);
                    UserAuthenticationInterceptor interceptor = context.getBean(UserAuthenticationInterceptor.class);
                    assertThat(interceptor).isNotNull();
                });
        }

        @Test
        @DisplayName("Should fail when AS User IDP issuer is not configured")
        void shouldFailWhenAsUserIdpIssuerIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.jwks.consumers.as-user-idp.issuer=",
                    "open-agent-auth.infrastructures.jwks.consumers.as-user-idp.jwks-endpoint=http://localhost:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure().getMessage())
                        .contains("AS User IDP issuer configuration not found");
                });
        }
    }

    @Nested
    @DisplayName("OAuth2TokenClient Bean Tests")
    class OAuth2TokenClientBeanTests {

        @Test
        @DisplayName("Should create userAuthenticationTokenClient bean")
        void shouldCreateUserAuthenticationTokenClientBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasBean("userAuthenticationTokenClient");
                    OAuth2TokenClient client = context.getBean("userAuthenticationTokenClient", OAuth2TokenClient.class);
                    assertThat(client).isNotNull();
                });
        }

        @Test
        @DisplayName("Should create agentOperationAuthorizationTokenClient bean")
        void shouldCreateAgentOperationAuthorizationTokenClientBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasBean("agentOperationAuthorizationTokenClient");
                    OAuth2TokenClient client = context.getBean("agentOperationAuthorizationTokenClient", OAuth2TokenClient.class);
                    assertThat(client).isNotNull();
                });
        }

        @Test
        @DisplayName("Should fail when client ID is not configured")
        void shouldFailWhenClientIdIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.capabilities.oauth2-client.client-id=",
                    "open-agent-auth.capabilities.oauth2-client.client-secret=test-secret"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure().getMessage())
                        .contains("OAuth client ID is not configured");
                });
        }
    }

    @Nested
    @DisplayName("SigningKeys Bean Tests")
    class SigningKeysBeanTests {

        @Test
        @DisplayName("Should create signingKeys bean")
        void shouldCreateSigningKeysBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasBean("signingKeys");
                    java.util.List<JWK> keys = context.getBean("signingKeys", java.util.List.class);
                    assertThat(keys).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("AuthorizationServerProvider Bean Tests")
    class AuthorizationServerProviderBeanTests {

        @Test
        @DisplayName("Should create AuthorizationServer provider bean")
        void shouldCreateAuthorizationServerProviderBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationServer.class);
                    AuthorizationServer provider = context.getBean(AuthorizationServer.class);
                    assertThat(provider).isNotNull();
                });
        }

        @Test
        @DisplayName("Should depend on required beans")
        void shouldDependOnRequiredBeans() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationServer.class);
                    assertThat(context).hasSingleBean(OAuth2ParServer.class);
                    assertThat(context).hasSingleBean(OAuth2DcrClientStore.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                });
        }
    }

    @Nested
    @DisplayName("ServiceEndpointResolver Bean Tests")
    class ServiceEndpointResolverBeanTests {

        @Test
        @DisplayName("Should create ServiceEndpointResolver bean")
        void shouldCreateServiceEndpointResolverBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    ServiceEndpointResolver resolver = context.getBean(ServiceEndpointResolver.class);
                    assertThat(resolver).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("SessionMapping Bean Tests")
    class SessionMappingBeanTests {

        @Test
        @DisplayName("Should create SessionMappingStore bean")
        void shouldCreateSessionMappingStoreBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionMappingStore.class);
                    SessionMappingStore store = context.getBean(SessionMappingStore.class);
                    assertThat(store).isNotNull();
                });
        }

        @Test
        @DisplayName("Should create SessionMappingBizService bean")
        void shouldCreateSessionMappingBizServiceBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionMappingBizService.class);
                    SessionMappingBizService service = context.getBean(SessionMappingBizService.class);
                    assertThat(service).isNotNull();
                });
        }
    }
}
