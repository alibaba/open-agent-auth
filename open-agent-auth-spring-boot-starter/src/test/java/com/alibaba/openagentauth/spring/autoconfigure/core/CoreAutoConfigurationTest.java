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
package com.alibaba.openagentauth.spring.autoconfigure.core;

import com.alibaba.openagentauth.core.crypto.key.DefaultKeyManager;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyManagementProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CoreAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of CoreAutoConfiguration,
 * including bean creation and conditional loading.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("CoreAutoConfiguration Tests")
class CoreAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(CoreAutoConfiguration.class))
        .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain");

    @Nested
    @DisplayName("KeyManager Bean Tests")
    class KeyManagerBeanTests {

        @Test
        @DisplayName("Should create KeyManager bean when not defined")
        void shouldCreateKeyManagerBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyManager.class);
                    KeyManager keyManager = context.getBean(KeyManager.class);
                    assertThat(keyManager).isInstanceOf(DefaultKeyManager.class);
                });
        }

        @Test
        @DisplayName("Should use custom KeyManager bean when defined")
        void shouldUseCustomKeyManagerBeanWhenDefined() {
            contextRunner
                .withUserConfiguration(CustomKeyManagerConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyManager.class);
                    KeyManager keyManager = context.getBean(KeyManager.class);
                    assertThat(keyManager).isInstanceOf(CustomKeyManager.class);
                });
        }
    }

    @Nested
    @DisplayName("TrustDomain Bean Tests")
    class TrustDomainBeanTests {

        @Test
        @DisplayName("Should create TrustDomain bean with configured trust domain")
        void shouldCreateTrustDomainBeanWithConfiguredTrustDomain() {
            contextRunner
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(TrustDomain.class);
                    TrustDomain trustDomain = context.getBean(TrustDomain.class);
                    assertThat(trustDomain.getDomainId()).isEqualTo("wimse://test.trust.domain");
                });
        }

        @Test
        @DisplayName("Should fail when trust domain is not configured")
        void shouldFailWhenTrustDomainIsNotConfigured() {
            contextRunner
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .getCause()
                        .getCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("Trust domain is not configured");
                });
        }

        @Test
        @DisplayName("Should use default trust domain when configured")
        void shouldUseDefaultTrustDomainWhenConfigured() {
            contextRunner
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://default.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(TrustDomain.class);
                    TrustDomain trustDomain = context.getBean(TrustDomain.class);
                    assertThat(trustDomain.getDomainId()).isEqualTo("wimse://default.trust.domain");
                });
        }

        @Test
        @DisplayName("Should use custom TrustDomain bean when defined")
        void shouldUseCustomTrustDomainBeanWhenDefined() {
            contextRunner
                .withUserConfiguration(CustomTrustDomainConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(TrustDomain.class);
                    TrustDomain trustDomain = context.getBean(TrustDomain.class);
                    assertThat(trustDomain.getDomainId()).isEqualTo("wimse://custom.trust.domain");
                });
        }
    }

    @Nested
    @DisplayName("TokenService Bean Tests")
    class TokenServiceBeanTests {

        @Test
        @DisplayName("Should create TokenService bean with default configuration")
        void shouldCreateTokenServiceBeanWithDefaultConfiguration() {
            contextRunner
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenService.class);
                    TokenService tokenService = context.getBean(TokenService.class);
                    assertThat(tokenService).isNotNull();
                });
        }

        @Test
        @DisplayName("Should use custom TokenService bean when defined")
        void shouldUseCustomTokenServiceBeanWhenDefined() {
            contextRunner
                .withUserConfiguration(CustomTokenServiceConfiguration.class)
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenService.class);
                    TokenService tokenService = context.getBean(TokenService.class);
                    assertThat(tokenService).isInstanceOf(CustomTokenService.class);
                });
        }

        @Test
        @DisplayName("Should depend on KeyManager and TrustDomain beans")
        void shouldDependOnKeyManagerAndTrustDomainBeans() {
            contextRunner
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenService.class);
                    assertThat(context).hasSingleBean(KeyManager.class);
                    assertThat(context).hasSingleBean(TrustDomain.class);
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when open-agent-auth.enabled is true")
        void shouldLoadWhenEnabledIsTrue() {
            contextRunner
                .withPropertyValues("open-agent-auth.enabled=true", "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyManager.class);
                    assertThat(context).hasSingleBean(TrustDomain.class);
                });
        }

        @Test
        @DisplayName("Should load when open-agent-auth.enabled is not specified (default)")
        void shouldLoadWhenEnabledIsNotSpecified() {
            contextRunner
                .withPropertyValues("open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain")
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyManager.class);
                    assertThat(context).hasSingleBean(TrustDomain.class);
                });
        }

        @Test
        @DisplayName("Should not load when open-agent-auth.enabled is false")
        void shouldNotLoadWhenEnabledIsFalse() {
            contextRunner
                .withPropertyValues("open-agent-auth.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(KeyManager.class);
                    assertThat(context).doesNotHaveBean(TrustDomain.class);
                });
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind OpenAgentAuthProperties correctly")
        void shouldBindOpenAgentAuthPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.isEnabled()).isTrue();
                    assertThat(properties.getRoles().get("agent") != null).isTrue();
                    assertThat(properties.getInfrastructures().getTrustDomain()).isEqualTo("wimse://test.trust.domain");
                });
        }

        @Test
        @DisplayName("Should bind JwksProperties correctly")
        void shouldBindJwksPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.jwks.provider.enabled=true",
                    "open-agent-auth.infrastructures.jwks.provider.path=/.well-known/jwks.json",
                    "open-agent-auth.infrastructures.jwks.provider.cache-duration-seconds=300"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.getInfrastructures().getJwks().getProvider().isEnabled()).isTrue();
                    assertThat(properties.getInfrastructures().getJwks().getProvider().getPath()).isEqualTo("/.well-known/jwks.json");
                    assertThat(properties.getInfrastructures().getJwks().getProvider().getCacheDurationSeconds()).isEqualTo(300);
                });
        }

        @Nested
        @DisplayName("New Properties Integration Tests")
        class NewPropertiesIntegrationTests {

            @Test
            @DisplayName("Should bind InfrastructureProperties correctly")
            void shouldBindInfrastructurePropertiesCorrectly() {
                contextRunner
                    .withPropertyValues(
                        "open-agent-auth.enabled=true",
                        "open-agent-auth.infrastructures.trust-domain=wimse://new.trust.domain",
                        "open-agent-auth.infrastructures.key-management.keys.wit-signing.key-id=wit-signing-key",
                        "open-agent-auth.infrastructures.key-management.keys.wit-signing.algorithm=ES256"
                    )
                    .run(context -> {
                        assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                        OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                        
                        InfrastructureProperties infra = properties.getInfrastructures();
                        assertThat(infra).isNotNull();
                        assertThat(infra.getTrustDomain()).isEqualTo("wimse://new.trust.domain");
                        
                        KeyManagementProperties keyManagement = infra.getKeyManagement();
                        assertThat(keyManagement).isNotNull();
                        assertThat(keyManagement.getKeys()).containsKey("wit-signing");
                    });
            }

            @Test
            @DisplayName("Should bind CapabilitiesProperties correctly")
            void shouldBindCapabilitiesPropertiesCorrectly() {
                contextRunner
                    .withPropertyValues(
                        "open-agent-auth.enabled=true",
                        "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                        "open-agent-auth.capabilities.oauth2-server.enabled=true",
                        "open-agent-auth.capabilities.oauth2-server.token.id-token-expiry=3600"
                    )
                    .run(context -> {
                        assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                        OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                        
                        CapabilitiesProperties capabilities = properties.getCapabilities();
                        assertThat(capabilities).isNotNull();
                        assertThat(capabilities.getOAuth2Server().isEnabled()).isTrue();
                        assertThat(capabilities.getOAuth2Server().getToken().getIdTokenExpiry()).isEqualTo(3600);
                    });
            }

            @Test
            @DisplayName("Should bind JwksInfrastructureProperties correctly")
            void shouldBindJwksInfrastructurePropertiesCorrectly() {
                contextRunner
                    .withPropertyValues(
                        "open-agent-auth.enabled=true",
                        "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                        "open-agent-auth.infrastructures.jwks.provider.enabled=true",
                        "open-agent-auth.infrastructures.jwks.provider.path=/.well-known/jwks.json"
                    )
                    .run(context -> {
                        assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                        OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                        
                        JwksInfrastructureProperties jwks = properties.getInfrastructures().getJwks();
                        assertThat(jwks).isNotNull();
                        assertThat(jwks.getProvider().isEnabled()).isTrue();
                        assertThat(jwks.getProvider().getPath()).isEqualTo("/.well-known/jwks.json");
                    });
            }

            @Test
            @DisplayName("Should bind ServiceDiscoveryProperties correctly")
            void shouldBindServiceDiscoveryPropertiesCorrectly() {
                contextRunner
                    .withPropertyValues(
                        "open-agent-auth.enabled=true",
                        "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                        "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://localhost:8082",
                        "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://localhost:8083"
                    )
                    .run(context -> {
                        assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                        OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                        
                        var services = properties.getInfrastructures().getServiceDiscovery().getServices();
                        assertThat(services).isNotNull();
                        assertThat(services).containsKey("agent-idp");
                        assertThat(services.get("agent-idp").getBaseUrl()).isEqualTo("http://localhost:8082");
                    });
            }
        }
    }

    // Test configurations for custom beans
    @Configuration
    static class CustomKeyManagerConfiguration {
        @Bean
        public KeyManager customKeyManager() {
            return new CustomKeyManager();
        }
    }

    @Configuration
    static class CustomTrustDomainConfiguration {
        @Bean
        public TrustDomain customTrustDomain() {
            return new TrustDomain("wimse://custom.trust.domain");
        }
    }

    @Configuration
    static class CustomTokenServiceConfiguration {
        @Bean
        public TokenService customTokenService() {
            return new CustomTokenService();
        }
    }

    // Custom implementations for testing
    static class CustomKeyManager extends DefaultKeyManager {
        public CustomKeyManager() {
            super(new InMemoryKeyStore());
        }
    }

    static class CustomTokenService extends TokenService {
        public CustomTokenService() {
            super(createTestSigningKey(), new TrustDomain("wimse://test.trust.domain"), JWSAlgorithm.RS256);
        }

        private static com.nimbusds.jose.jwk.RSAKey createTestSigningKey() {
            try {
                return new RSAKeyGenerator(2048).keyID("test-signing-key").generate();
            } catch (com.nimbusds.jose.JOSEException e) {
                throw new RuntimeException("Failed to create test signing key", e);
            }
        }
    }
}