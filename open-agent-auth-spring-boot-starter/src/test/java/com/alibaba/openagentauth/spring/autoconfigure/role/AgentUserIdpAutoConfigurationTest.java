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

import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweDecoder;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.DefaultOAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.InMemoryOAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.spring.autoconfigure.capability.SharedCapabilityAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.UserAuthenticationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyManagementProperties;
import com.alibaba.openagentauth.spring.config.OAuth2AuthorizationConfiguration;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AgentUserIdpAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of AgentUserIdpAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AgentUserIdpAutoConfiguration Tests")
class AgentUserIdpAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            SharedCapabilityAutoConfiguration.class,
            AgentUserIdpAutoConfiguration.class,
            OAuth2AuthorizationConfiguration.class
        ))
        .withUserConfiguration(TestCoreConfiguration.class)
        .withPropertyValues(
            "open-agent-auth.enabled=true",
            "open-agent-auth.roles.agent-user-idp.enabled=true",
            "open-agent-auth.roles.agent-user-idp.issuer=http://localhost:8080",
            "open-agent-auth.capabilities.oauth2-server.enabled=true",
            "open-agent-auth.capabilities.user-authentication.enabled=true",
            "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
            "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
            "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
        );

    @Configuration
    static class TestCoreConfiguration {
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
        public IdTokenValidator idTokenValidator(ServiceProperties serviceProperties) {
            return new DefaultIdTokenValidator(serviceProperties);
        }

        @Bean
        public ServiceProperties serviceProperties() {
            return new ServiceProperties();
        }

        @Bean
        public ServiceEndpointResolver serviceEndpointResolver(ServiceProperties serviceProperties) {
            return new DefaultServiceEndpointResolver(serviceProperties);
        }
    }

    @Nested
    @DisplayName("IdTokenGenerator Bean Tests")
    class IdTokenGeneratorBeanTests {

        @Test
        @DisplayName("Should create IdTokenGenerator bean when not defined")
        void shouldCreateIdTokenGeneratorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    IdTokenGenerator generator = context.getBean(IdTokenGenerator.class);
                    assertThat(generator).isInstanceOf(DefaultIdTokenGenerator.class);
                });
        }

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class,
                    AgentUserIdpAutoConfiguration.class,
                    OAuth2AuthorizationConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.capabilities.user-authentication.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable rootCause = context.getStartupFailure();
                    while (rootCause.getCause() != null) {
                        rootCause = rootCause.getCause();
                    }
                    assertThat(rootCause)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("User IDP issuer is not configured");
                });
        }

        @Test
        @DisplayName("Should depend on KeyManager bean")
        void shouldDependOnKeyManagerBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    assertThat(context).hasSingleBean(KeyManager.class);
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
    @DisplayName("OAuth2ClientStore Bean Tests")
    class OAuth2ClientStoreBeanTests {

        @Test
        @DisplayName("Should create OAuth2ClientStore bean when not defined")
        void shouldCreateOAuth2ClientStoreBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ClientStore.class);
                    OAuth2ClientStore store = context.getBean(OAuth2ClientStore.class);
                    assertThat(store).isInstanceOf(InMemoryOAuth2ClientStore.class);
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

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class,
                    AgentUserIdpAutoConfiguration.class,
                    OAuth2AuthorizationConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.capabilities.user-authentication.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable rootCause = context.getStartupFailure();
                    while (rootCause.getCause() != null) {
                        rootCause = rootCause.getCause();
                    }
                    assertThat(rootCause)
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("User IDP issuer is not configured");
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
                    assertThat(server).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when role is agent-user-idp")
        void shouldLoadWhenRoleIsAgentUserIdp() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                });
        }

        @Test
        @DisplayName("Should not load when role is not agent-user-idp")
        void shouldNotLoadWhenRoleIsNotAgentUserIdp() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    AgentUserIdpAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=resource-server",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    // Check that AgentUserIdpAutoConfiguration beans are not loaded
                    assertThat(context).doesNotHaveBean(IdTokenGenerator.class);
                    assertThat(context).doesNotHaveBean(OAuth2AuthorizationServer.class);
                    assertThat(context).doesNotHaveBean(OAuth2TokenServer.class);
                    assertThat(context).doesNotHaveBean(TokenGenerator.class);
                });
        }
    }

    @Nested
    @DisplayName("New Properties Integration Tests")
    class NewPropertiesIntegrationTests {

        @Test
        @DisplayName("Should bind UserAuthenticationProperties correctly")
        void shouldBindUserAuthenticationPropertiesCorrectly() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    UserAuthenticationProperties userAuth = properties.getCapabilities().getUserAuthentication();
                    assertThat(userAuth).isNotNull();
                });
        }

        @Test
        @DisplayName("Should bind KeyManagementProperties correctly")
        void shouldBindKeyManagementPropertiesCorrectly() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    KeyManagementProperties keyManagement = properties.getInfrastructures().getKeyManagement();
                    assertThat(keyManagement).isNotNull();
                    assertThat(keyManagement.getKeys()).containsKey("id-token-signing");
                });
        }
    }
}