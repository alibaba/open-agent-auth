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
import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.DefaultOAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.server.OAuth2AuthorizationServer;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.InMemoryOAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.authorization.storage.OAuth2AuthorizationCodeStorage;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.DefaultOAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.server.OAuth2DcrServer;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.InMemoryOAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.store.OAuth2DcrClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.DefaultOAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.server.OAuth2ParServer;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.InMemoryOAuth2ParRequestStore;
import com.alibaba.openagentauth.core.protocol.oauth2.par.store.OAuth2ParRequestStore;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.DefaultOAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.OAuth2TokenServer;
import com.alibaba.openagentauth.core.protocol.oauth2.token.server.TokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.AuthenticationProvider;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.framework.actor.UserIdentityProvider;
import com.alibaba.openagentauth.framework.orchestration.DefaultUserIdentityProvider;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.provider.DefaultConsentPageProvider;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
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
 * Unit tests for {@link AsUserIdpAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of AsUserIdpAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AsUserIdpAutoConfiguration Tests")
class AsUserIdpAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            TestCoreConfiguration.class,
            AsUserIdpAutoConfiguration.class
        ))
        .withPropertyValues(
            "open-agent-auth.infrastructures.key-management.keys.id-token-signing.key-id=id-token-signing-key",
            "open-agent-auth.infrastructures.key-management.keys.id-token-signing.algorithm=ES256"
        );

    @Configuration
    static class TestCoreConfiguration {
        @Bean
        public KeyManager keyManager() {
            return new DefaultKeyManager(
                new InMemoryKeyStore()
            );
        }

        @Bean
        public PromptDecryptionService promptDecryptionService(
            KeyManager keyManager) {
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
            return new TrustDomain("wimse://test.trust.domain");
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
        public IdTokenValidator idTokenValidator(ServiceProperties serviceProperties) {
            return new DefaultIdTokenValidator(serviceProperties);
        }

        @Bean
        public ServiceProperties serviceProperties() {
            return new ServiceProperties();
        }

        @Bean
        public ServiceEndpointResolver serviceEndpointResolver(
            ServiceProperties serviceProperties) {
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    IdTokenGenerator generator = context.getBean(IdTokenGenerator.class);
                    assertThat(generator).isInstanceOf(DefaultIdTokenGenerator.class);
                });
        }

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .getCause()
                        .getCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("AS User IDP issuer is not configured");
                });
        }

        @Test
        @DisplayName("Should depend on KeyManager bean")
        void shouldDependOnKeyManagerBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2AuthorizationCodeStorage.class);
                    OAuth2AuthorizationCodeStorage storage = context.getBean(OAuth2AuthorizationCodeStorage.class);
                    assertThat(storage).isInstanceOf(InMemoryOAuth2AuthorizationCodeStorage.class);
                });
        }

        @Test
        @DisplayName("Should depend on AsUserIdpProperties bean")
        void shouldDependOnAsUserIdpPropertiesBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2AuthorizationCodeStorage.class);
                });
        }
    }

    @Nested
    @DisplayName("AuthenticationProvider Bean Tests")
    class AuthenticationProviderBeanTests {

        @Test
        @DisplayName("Should create AuthenticationProvider bean when not defined")
        void shouldCreateAuthenticationProviderBeanWhenNotDefined() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthenticationProvider.class);
                    AuthenticationProvider provider = context.getBean(AuthenticationProvider.class);
                    assertThat(provider).isNotNull();
                });
        }

        @Test
        @DisplayName("Should depend on IdTokenGenerator bean")
        void shouldDependOnIdTokenGeneratorBean() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthenticationProvider.class);
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenGenerator.class);
                    TokenGenerator generator = context.getBean(TokenGenerator.class);
                    assertThat(generator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .getCause()
                        .getCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("AS User IDP issuer is not configured");
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                    OAuth2TokenServer server = context.getBean(OAuth2TokenServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2TokenServer.class);
                });
        }
    }

    @Nested
    @DisplayName("UserIdentityProvider Bean Tests")
    class UserIdentityProviderBeanTests {

        @Test
        @DisplayName("Should create UserIdentityProvider bean when not defined")
        void shouldCreateUserIdentityProviderBeanWhenNotDefined() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(UserIdentityProvider.class);
                    UserIdentityProvider provider = context.getBean(UserIdentityProvider.class);
                    assertThat(provider).isInstanceOf(DefaultUserIdentityProvider.class);
                });
        }

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .getCause()
                        .getCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("AS User IDP issuer is not configured");
                });
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
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
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
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ParServer.class);
                    OAuth2ParServer server = context.getBean(OAuth2ParServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2ParServer.class);
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2DcrClientStore.class);
                    OAuth2DcrClientStore store = context.getBean(OAuth2DcrClientStore.class);
                    assertThat(store).isInstanceOf(InMemoryOAuth2DcrClientStore.class);
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2DcrServer.class);
                    OAuth2DcrServer server = context.getBean(OAuth2DcrServer.class);
                    assertThat(server).isInstanceOf(DefaultOAuth2DcrServer.class);
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
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
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
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
        @DisplayName("Should load when role is as-user-idp")
        void shouldLoadWhenRoleIsAsUserIdp() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                    assertThat(context).hasSingleBean(OAuth2TokenServer.class);
                });
        }

        @Test
        @DisplayName("Should not load when role is not as-user-idp")
        void shouldNotLoadWhenRoleIsNotAsUserIdp() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(IdTokenGenerator.class);
                    assertThat(context).doesNotHaveBean(OAuth2TokenServer.class);
                });
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind AsUserIdpProperties correctly")
        void shouldBindAsUserIdpPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.as-user-idp.enabled=true",
                    "open-agent-auth.roles.as-user-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-server.token.id-token-expiry=3600",
                    "open-agent-auth.as-user-idp.refresh-token-expiration-seconds=86400"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenGenerator.class);
                });
        }
    }
}
