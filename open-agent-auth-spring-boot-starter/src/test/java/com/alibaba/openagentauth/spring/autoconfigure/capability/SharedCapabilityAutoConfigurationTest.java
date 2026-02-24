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
package com.alibaba.openagentauth.spring.autoconfigure.capability;

import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweDecoder;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.DefaultOAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.InMemoryOAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.DefaultOAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultAuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.registry.InMemoryUserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.SessionMappingStore;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
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
 * Unit tests for {@link SharedCapabilityAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of SharedCapabilityAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation for shared capabilities.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("SharedCapabilityAutoConfiguration Tests")
class SharedCapabilityAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            SharedCapabilityAutoConfiguration.class
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
        public ServiceProperties serviceProperties() {
            return new ServiceProperties();
        }
    }

    @Nested
    @DisplayName("SessionMapping Bean Tests")
    class SessionMappingBeanTests {

        @Test
        @DisplayName("Should create SessionMappingStore bean when enabled")
        void shouldCreateSessionMappingStoreBeanWhenEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionMappingStore.class);
                    SessionMappingStore store = context.getBean(SessionMappingStore.class);
                    assertThat(store).isInstanceOf(InMemorySessionMappingStore.class);
                });
        }

        @Test
        @DisplayName("Should create SessionMappingBizService bean when enabled")
        void shouldCreateSessionMappingBizServiceBeanWhenEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(SessionMappingBizService.class);
                    SessionMappingBizService service = context.getBean(SessionMappingBizService.class);
                    assertThat(service).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("IdTokenGenerator Bean Tests")
    class IdTokenGeneratorBeanTests {

        @Test
        @DisplayName("Should create IdTokenGenerator bean when OAuth2Server enabled")
        void shouldCreateIdTokenGeneratorBeanWhenOAuth2ServerEnabled() {
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
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
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
    @DisplayName("TokenGenerator Bean Tests")
    class TokenGeneratorBeanTests {

        @Test
        @DisplayName("Should create TokenGenerator bean when OAuth2Server enabled")
        void shouldCreateTokenGeneratorBeanWhenOAuth2ServerEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    TokenGenerator generator = context.getBean(TokenGenerator.class);
                    assertThat(generator).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("OAuth2Server Bean Tests")
    class OAuth2ServerBeanTests {

        @Test
        @DisplayName("Should create AuthorizationCodeStorage bean when OAuth2Server enabled")
        void shouldCreateAuthorizationCodeStorageBeanWhenOAuth2ServerEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2AuthorizationCodeStorage.class);
                    OAuth2AuthorizationCodeStorage storage = context.getBean(OAuth2AuthorizationCodeStorage.class);
                    assertThat(storage).isInstanceOf(InMemoryOAuth2AuthorizationCodeStorage.class);
                });
        }

        @Test
        @DisplayName("Should create ClientStore bean when OAuth2Server enabled")
        void shouldCreateClientStoreBeanWhenOAuth2ServerEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ClientStore.class);
                    OAuth2ClientStore store = context.getBean(OAuth2ClientStore.class);
                    assertThat(store).isInstanceOf(InMemoryOAuth2ClientStore.class);
                });
        }

        @Test
        @DisplayName("Should create AuthorizationServer bean when OAuth2Server enabled")
        void shouldCreateAuthorizationServerBeanWhenOAuth2ServerEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2AuthorizationServer.class);
                    OAuth2AuthorizationServer server = context.getBean(OAuth2AuthorizationServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2AuthorizationServer.class);
                });
        }

        @Test
        @DisplayName("Should create TokenServer bean when OAuth2Server enabled")
        void shouldCreateTokenServerBeanWhenOAuth2ServerEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                    OAuth2TokenServer server = context.getBean(OAuth2TokenServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2TokenServer.class);
                });
        }
    }

    @Nested
    @DisplayName("UserAuthentication Bean Tests")
    class UserAuthenticationBeanTests {

        @Test
        @DisplayName("Should create UserRegistry bean when UserAuthentication enabled")
        void shouldCreateUserRegistryBeanWhenUserAuthenticationEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(UserRegistry.class);
                    UserRegistry registry = context.getBean(UserRegistry.class);
                    assertThat(registry).isInstanceOf(InMemoryUserRegistry.class);
                });
        }

        @Test
        @DisplayName("Should create AuthenticationProvider bean when UserAuthentication enabled")
        void shouldCreateAuthenticationProviderBeanWhenUserAuthenticationEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthenticationProvider.class);
                    AuthenticationProvider provider = context.getBean(AuthenticationProvider.class);
                    assertThat(provider).isInstanceOf(DefaultAuthenticationProvider.class);
                });
        }
    }

    @Nested
    @DisplayName("UserIdp Bean Tests")
    class UserIdpBeanTests {

        @Test
        @DisplayName("Should create ConsentPageProvider bean when UserAuthentication enabled")
        void shouldCreateConsentPageProviderBeanWhenUserAuthenticationEnabled() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(ConsentPageProvider.class);
                    ConsentPageProvider provider = context.getBean(ConsentPageProvider.class);
                    assertThat(provider).isInstanceOf(DefaultConsentPageProvider.class);
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should not load OAuth2Server beans when capability disabled")
        void shouldNotLoadOAuth2ServerBeansWhenCapabilityDisabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(IdTokenGenerator.class);
                    assertThat(context).doesNotHaveBean(TokenGenerator.class);
                    assertThat(context).doesNotHaveBean(OAuth2AuthorizationCodeStorage.class);
                    assertThat(context).doesNotHaveBean(OAuth2ClientStore.class);
                    assertThat(context).doesNotHaveBean(OAuth2AuthorizationServer.class);
                    assertThat(context).doesNotHaveBean(OAuth2TokenServer.class);
                });
        }

        @Test
        @DisplayName("Should not load UserAuthentication beans when capability disabled")
        void shouldNotLoadUserAuthenticationBeansWhenCapabilityDisabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(UserRegistry.class);
                    assertThat(context).doesNotHaveBean(AuthenticationProvider.class);
                    assertThat(context).doesNotHaveBean(ConsentPageProvider.class);
                    assertThat(context).doesNotHaveBean(UserAuthenticationInterceptor.class);
                });
        }
    }

    @Nested
    @DisplayName("UserIdpRoleCondition Tests")
    class UserIdpRoleConditionTests {

        @Test
        @DisplayName("Should match when agent-user-idp is enabled")
        void shouldMatchWhenAgentUserIdpEnabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    assertThat(context).hasSingleBean(OAuth2AuthorizationServer.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                });
        }

        @Test
        @DisplayName("Should match when as-user-idp is enabled")
        void shouldMatchWhenAsUserIdpEnabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    assertThat(context).hasSingleBean(OAuth2AuthorizationServer.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                });
        }

        @Test
        @DisplayName("Should match when both User IDP roles are enabled")
        void shouldMatchWhenBothUserIdpRolesEnabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    assertThat(context).hasSingleBean(OAuth2AuthorizationServer.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                });
        }

        @Test
        @DisplayName("Should not match when no User IDP role is enabled")
        void shouldNotMatchWhenNoUserIdpRoleEnabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(IdTokenGenerator.class);
                    assertThat(context).doesNotHaveBean(TokenGenerator.class);
                    assertThat(context).doesNotHaveBean(OAuth2AuthorizationServer.class);
                    assertThat(context).doesNotHaveBean(OAuth2TokenServer.class);
                });
        }
    }

    @Nested
    @DisplayName("UserIdpOAuth2ServerConfiguration Tests")
    class UserIdpOAuth2ServerConfigurationTests {

        @Test
        @DisplayName("Should not create User IDP OAuth2 beans when only authorization-server role is enabled")
        void shouldNotCreateUserIdpOAuth2BeansWhenOnlyAuthorizationServerRoleEnabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    // Shared OAuth2 beans should still be created
                    assertThat(context).hasSingleBean(OAuth2AuthorizationCodeStorage.class);
                    assertThat(context).hasSingleBean(OAuth2ClientStore.class);
                    
                    // User IDP-specific OAuth2 beans should NOT be created
                    assertThat(context).doesNotHaveBean(IdTokenGenerator.class);
                    assertThat(context).doesNotHaveBean(TokenGenerator.class);
                    assertThat(context).doesNotHaveBean(OAuth2AuthorizationServer.class);
                    assertThat(context).doesNotHaveBean(OAuth2TokenServer.class);
                });
        }

        @Test
        @DisplayName("Should create User IDP OAuth2 beans when User IDP role is enabled")
        void shouldCreateUserIdpOAuth2BeansWhenUserIdpRoleEnabled() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    SharedCapabilityAutoConfiguration.class
                ))
                .withUserConfiguration(TestCoreConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.enabled=true",
                    "open-agent-auth.roles.agent-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.oauth2-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
                )
                .run(context -> {
                    // Shared OAuth2 beans should be created
                    assertThat(context).hasSingleBean(OAuth2AuthorizationCodeStorage.class);
                    assertThat(context).hasSingleBean(OAuth2ClientStore.class);
                    
                    // User IDP-specific OAuth2 beans should also be created
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    assertThat(context).hasSingleBean(OAuth2AuthorizationServer.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                    
                    // Verify bean types
                    assertThat(context.getBean(IdTokenGenerator.class)).isInstanceOf(DefaultIdTokenGenerator.class);
                    assertThat(context.getBean(OAuth2AuthorizationServer.class)).isInstanceOf(DefaultOAuth2AuthorizationServer.class);
                    assertThat(context.getBean(OAuth2TokenServer.class)).isInstanceOf(DefaultOAuth2TokenServer.class);
                });
        }
    }
}