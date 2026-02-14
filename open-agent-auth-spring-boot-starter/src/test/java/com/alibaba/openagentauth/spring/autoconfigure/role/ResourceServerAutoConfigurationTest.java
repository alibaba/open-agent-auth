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
import com.alibaba.openagentauth.core.crypto.key.model.KeyAlgorithm;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.trust.model.TrustAnchor;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.framework.orchestration.DefaultResourceServer;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDiscoveryProperties;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link ResourceServerAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of ResourceServerAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ResourceServerAutoConfiguration Tests")
class ResourceServerAutoConfigurationTest {

    // Base context runner with mock beans - for testing auto-configuration behavior
    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            ResourceServerAutoConfiguration.class
        ))
        .withPropertyValues(
            "spring.main.allow-bean-definition-overriding=true",
            "open-agent-auth.roles.resource-server.enabled=true",
            "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
            "open-agent-auth.roles.resource-server.issuer=http://localhost:8080"
        )
        .withUserConfiguration(TestMockValidatorsConfiguration.class);

    @Nested
    @DisplayName("ConfigurationPropertiesTests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind ResourceServerProperties correctly")
        void shouldBindResourceServerPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.resource-server.enabled=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("New Properties Integration Tests")
    class NewPropertiesIntegrationTests {

        @Test
        @DisplayName("Should bind JwksConsumerProperties correctly")
        void shouldBindJwksConsumerPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.jwks.consumers.agent-idp.jwks-endpoint=http://agent-idp:8080/.well-known/jwks.json",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-idp.issuer=http://agent-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.authorization-server.jwks-endpoint=http://authorization-server:8080/.well-known/jwks.json",
                    "open-agent-auth.infrastructures.jwks.consumers.authorization-server.issuer=http://authorization-server:8080",
                    "open-agent-auth.infrastructures.key-management.keys.wit-verification.key-id=wit-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.wit-verification.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.aoat-verification.key-id=aoat-signing-key",
                    "open-agent-auth.infrastructures.key-management.keys.aoat-verification.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    JwksConsumerProperties agentIdpConsumer = properties.getInfrastructures().getJwks().getConsumers().get("agent-idp");
                    assertThat(agentIdpConsumer).isNotNull();
                    assertThat(agentIdpConsumer.getJwksEndpoint()).isEqualTo("http://agent-idp:8080/.well-known/jwks.json");
                    
                    JwksConsumerProperties authServerConsumer = properties.getInfrastructures().getJwks().getConsumers().get("authorization-server");
                    assertThat(authServerConsumer).isNotNull();
                    assertThat(authServerConsumer.getJwksEndpoint()).isEqualTo("http://authorization-server:8080/.well-known/jwks.json");
                });
        }
    }

    @Nested
    @DisplayName("WptValidatorBeanTests")
    class WptValidatorBeanTests {

        @Test
        @DisplayName("Should create WptValidator bean when not defined")
        void shouldCreateWptValidatorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(WptValidator.class);
                    WptValidator validator = context.getBean(WptValidator.class);
                    assertThat(validator).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("PolicyRegistryBeanTests")
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
    @DisplayName("PolicyEvaluatorBeanTests")
    class PolicyEvaluatorBeanTests {

        @Test
        @DisplayName("Should create PolicyEvaluator bean when not defined")
        void shouldCreatePolicyEvaluatorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(PolicyEvaluator.class);
                    PolicyEvaluator evaluator = context.getBean(PolicyEvaluator.class);
                    assertThat(evaluator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should depend on PolicyRegistry bean")
        void shouldDependOnPolicyRegistryBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(PolicyEvaluator.class);
                    assertThat(context).hasSingleBean(PolicyRegistry.class);
                });
        }
    }



    @Nested
    @DisplayName("DefaultResourceServerBeanTests")
    class DefaultResourceServerBeanTests {

        @Test
        @DisplayName("Should create DefaultResourceServer bean when not defined")
        void shouldCreateDefaultResourceServerBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(DefaultResourceServer.class);
                    DefaultResourceServer resourceServer = context.getBean(DefaultResourceServer.class);
                    assertThat(resourceServer).isNotNull();
                });
        }

        @Test
        @DisplayName("Should depend on all validator beans")
        void shouldDependOnAllValidatorBeans() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(DefaultResourceServer.class);
                    assertThat(context).hasSingleBean(WitValidator.class);
                    assertThat(context).hasSingleBean(WptValidator.class);
                    assertThat(context).hasSingleBean(AoatValidator.class);
                    assertThat(context).hasSingleBean(PolicyEvaluator.class);
                });
        }
    }

    @Nested
    @DisplayName("ConditionalLoadingTests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when role is resource-server")
        void shouldLoadWhenRoleIsResourceServer() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(WptValidator.class);
                    assertThat(context).hasSingleBean(PolicyRegistry.class);
                });
        }

        @Test
        @DisplayName("Should not load when role is not resource-server")
        void shouldNotLoadWhenRoleIsNotResourceServer() {
            contextRunner
                .withPropertyValues("open-agent-auth.roles.resource-server.enabled=false")
                .run(context -> {
                    // ResourceServerAutoConfiguration should not load when resource-server role is disabled
                    // So WptValidator and PolicyRegistry beans should not be created
                    assertThat(context).doesNotHaveBean(WptValidator.class);
                    assertThat(context).doesNotHaveBean(PolicyRegistry.class);
                    assertThat(context).doesNotHaveBean(DefaultResourceServer.class);
                });
        }
    }



    @Nested
    @DisplayName("ServiceEndpointResolver Bean Tests")
    class ServiceEndpointResolverBeanTests {

        @Test
        @DisplayName("Should create ServiceEndpointResolver bean when not defined")
        void shouldCreateServiceEndpointResolverBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    ServiceEndpointResolver resolver = context.getBean(ServiceEndpointResolver.class);
                    assertThat(resolver).isNotNull();
                });
        }

        @Test
        @DisplayName("Should map service discovery to consumer services")
        void shouldMapServiceDiscoveryToConsumerServices() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://agent-idp:8080",
                    "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://auth-server:8080"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    ServiceDiscoveryProperties discovery = properties.getInfrastructures().getServiceDiscovery();
                    assertThat(discovery.getServices()).hasSize(2);
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

        @Test
        @DisplayName("Should depend on ServiceEndpointResolver bean")
        void shouldDependOnServiceEndpointResolverBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(BindingInstanceStore.class);
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                });
        }
    }

    @Nested
    @DisplayName("TrustDomain Configuration Tests")
    class TrustDomainConfigurationTests {

        @Test
        @DisplayName("Should use configured trust domain")
        void shouldUseConfiguredTrustDomain() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.trust-domain=wimse://custom.trust.domain"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WitValidator.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.getInfrastructures().getTrustDomain())
                        .isEqualTo("wimse://custom.trust.domain");
                });
        }
    }

    @Nested
    @DisplayName("Resource Server Issuer Tests")
    class ResourceServerIssuerTests {

        @Test
        @DisplayName("Should bind resource-server issuer correctly")
        void shouldBindResourceServerIssuerCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.resource-server.issuer=http://localhost:8081"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.getRoles().get("resource-server").getIssuer())
                        .isEqualTo("http://localhost:8081");
                });
        }
    }



    @Nested
    @DisplayName("AoatValidator Bean Tests")
    class AoatValidatorBeanTests {

        @Test
        @DisplayName("Should create AoatValidator bean when not defined")
        void shouldCreateAoatValidatorBeanWhenNotDefined() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AoatValidator.class);
                    AoatValidator validator = context.getBean(AoatValidator.class);
                    assertThat(validator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should depend on WitValidator bean")
        void shouldDependOnWitValidatorBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AoatValidator.class);
                    assertThat(context).hasSingleBean(WitValidator.class);
                });
        }

        @Test
        @DisplayName("Should use AoatValidator from mock configuration")
        void shouldUseAoatValidatorFromMockConfiguration() {
            contextRunner
                .run(context -> {
                    // AoatValidator bean is mocked in TestMockValidatorsConfiguration
                    assertThat(context).hasSingleBean(AoatValidator.class);
                    AoatValidator validator = context.getBean(AoatValidator.class);
                    assertThat(validator).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("ServiceEndpointResolver Advanced Tests")
    class ServiceEndpointResolverAdvancedTests {

        @Test
        @DisplayName("Should create ServiceEndpointResolver with empty service discovery")
        void shouldCreateServiceEndpointResolverWithEmptyServiceDiscovery() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    ServiceEndpointResolver resolver = context.getBean(ServiceEndpointResolver.class);
                    assertThat(resolver).isNotNull();
                });
        }

        @Test
        @DisplayName("Should map multiple services correctly")
        void shouldMapMultipleServicesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://agent-idp:8080",
                    "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://auth-server:8080",
                    "open-agent-auth.infrastructures.service-discovery.services.resource-server.base-url=http://resource-server:8080"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    ServiceDiscoveryProperties discovery = properties.getInfrastructures().getServiceDiscovery();
                    assertThat(discovery.getServices()).hasSize(3);
                    assertThat(discovery.getServices().get("agent-idp").getBaseUrl())
                        .isEqualTo("http://agent-idp:8080");
                    assertThat(discovery.getServices().get("authorization-server").getBaseUrl())
                        .isEqualTo("http://auth-server:8080");
                    assertThat(discovery.getServices().get("resource-server").getBaseUrl())
                        .isEqualTo("http://resource-server:8080");
                });
        }

        @Test
        @DisplayName("Should handle service discovery with custom endpoints")
        void shouldHandleServiceDiscoveryWithCustomEndpoints() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://agent-idp:8080",
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.endpoints.policy=http://agent-idp:8080/policy",
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.endpoints.binding=http://agent-idp:8080/binding"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    ServiceDiscoveryProperties discovery = properties.getInfrastructures().getServiceDiscovery();
                    assertThat(discovery.getServices().get("agent-idp").getEndpoints())
                        .isNotNull();
                    assertThat(discovery.getServices().get("agent-idp").getEndpoints().get("policy"))
                        .isEqualTo("http://agent-idp:8080/policy");
                });
        }
    }

    @Nested
    @DisplayName("Real Bean Coverage Tests")
    class RealBeanCoverageTests {

        private final WebApplicationContextRunner realContextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                CoreAutoConfiguration.class,
                ResourceServerAutoConfiguration.class
            ))
            .withPropertyValues(
                "spring.main.allow-bean-definition-overriding=true",
                "open-agent-auth.roles.resource-server.enabled=true",
                "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                "open-agent-auth.roles.resource-server.issuer=http://localhost:8080"
            )
            .withUserConfiguration(TestOnlyValidatorsConfiguration.class);

        @Test
        @DisplayName("Should execute serviceEndpointResolver method with service discovery")
        void shouldExecuteServiceEndpointResolverMethodWithServiceDiscovery() {
            realContextRunner
                .withPropertyValues(
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://agent-idp:8080",
                    "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://auth-server:8080"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    ServiceEndpointResolver resolver = context.getBean(ServiceEndpointResolver.class);
                    assertThat(resolver).isNotNull();
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.getInfrastructures().getServiceDiscovery().getServices()).hasSize(2);
                });
        }

        @Test
        @DisplayName("Should execute serviceEndpointResolver method with empty service discovery")
        void shouldExecuteServiceEndpointResolverMethodWithEmptyServiceDiscovery() {
            realContextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    ServiceEndpointResolver resolver = context.getBean(ServiceEndpointResolver.class);
                    assertThat(resolver).isNotNull();
                });
        }
    }

    @Configuration
    static class TestMockValidatorsConfiguration {

        @Bean
        public ServiceProperties serviceProperties() {
            ServiceProperties props = new ServiceProperties();
            props.postProcess();
            return props;
        }

        @Bean
        public ServiceEndpointResolver serviceEndpointResolver(ServiceProperties serviceProperties) {
            return new DefaultServiceEndpointResolver(serviceProperties);
        }

        @Bean
        public WitValidator witValidator() {
            return new WitValidator(createTestTrustAnchor());
        }

        @Bean
        public AoatValidator aoatValidator() {
            return new AoatValidator(
                createTestRsaKey(),
                "http://authorization-server:8080",
                "http://localhost:8080"
            );
        }

        private static TrustAnchor createTestTrustAnchor() {
            try {
                KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
                TrustDomain trustDomain = new TrustDomain("wimse://test.trust.domain");
                return new TrustAnchor(keyPair.getPublic(), "wit-signing-key", KeyAlgorithm.ES256, trustDomain);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to create test trust anchor", e);
            }
        }

        private static RSAKey createTestRsaKey() {
            try {
                return new RSAKeyGenerator(2048)
                    .keyID("aoat-signing-key")
                    .generate();
            } catch (Exception e) {
                throw new RuntimeException("Failed to create test RSA key", e);
            }
        }
    }

    @Configuration
    static class TestOnlyValidatorsConfiguration {

        @Bean
        public WitValidator witValidator() {
            return new WitValidator(createTestTrustAnchor());
        }

        @Bean
        public AoatValidator aoatValidator() {
            return new AoatValidator(
                createTestRsaKey(),
                "http://authorization-server:8080",
                "http://localhost:8080"
            );
        }

        private static TrustAnchor createTestTrustAnchor() {
            try {
                KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
                TrustDomain trustDomain = new TrustDomain("wimse://test.trust.domain");
                return new TrustAnchor(keyPair.getPublic(), "wit-signing-key", KeyAlgorithm.ES256, trustDomain);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to create test trust anchor", e);
            }
        }

        private static RSAKey createTestRsaKey() {
            try {
                return new RSAKeyGenerator(2048)
                    .keyID("aoat-signing-key")
                    .generate();
            } catch (Exception e) {
                throw new RuntimeException("Failed to create test RSA key", e);
            }
        }
    }
}