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

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.oidc.impl.DefaultIdTokenValidator;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.AgentRequestContext;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.InMemoryWorkloadRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.core.token.TokenService;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.orchestration.DefaultAgentIdentityProvider;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AgentIdpAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of AgentIdpAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AgentIdpAutoConfiguration Tests")
class AgentIdpAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            AgentIdpAutoConfiguration.class
        ))
        .withPropertyValues(
            "spring.main.allow-bean-definition-overriding=true",
            "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
        )
        .withUserConfiguration(TestConfiguration.class);

    @Nested
    @DisplayName("WorkloadRegistry Bean Tests")
    class WorkloadRegistryBeanTests {

        @Test
        @DisplayName("Should create WorkloadRegistry bean when not defined")
        void shouldCreateWorkloadRegistryBeanWhenNotDefined() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WorkloadRegistry.class);
                    WorkloadRegistry registry = context.getBean(WorkloadRegistry.class);
                    assertThat(registry).isInstanceOf(InMemoryWorkloadRegistry.class);
                });
        }

        @Test
        @DisplayName("Should use custom WorkloadRegistry bean when defined")
        void shouldUseCustomWorkloadRegistryBeanWhenDefined() {
            contextRunner
                .withUserConfiguration(CustomWorkloadRegistryConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WorkloadRegistry.class);
                    WorkloadRegistry registry = context.getBean(WorkloadRegistry.class);
                    assertThat(registry).isInstanceOf(CustomWorkloadRegistry.class);
                });
        }
    }

    @Nested
    @DisplayName("AgentIdentityProvider Bean Tests")
    class AgentIdentityProviderBeanTests {

        @Test
        @DisplayName("Should create AgentIdentityProvider bean with required configuration")
        void shouldCreateAgentIdentityProviderBeanWithRequiredConfiguration() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentIdentityProvider.class);
                    AgentIdentityProvider provider = context.getBean(AgentIdentityProvider.class);
                    assertThat(provider).isInstanceOf(DefaultAgentIdentityProvider.class);
                });
        }

        @Test
        @DisplayName("Should fail when issuer is not configured")
        void shouldFailWhenIssuerIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    // Context should fail because agentIdentityProvider bean creation
                    // throws IllegalStateException when issuer is not configured
                    assertThat(context).hasFailed();
                    Throwable failure = context.getStartupFailure();
                    assertThat(failure).isNotNull();
                    // Find the root cause which should be IllegalStateException
                    Throwable rootCause = failure;
                    while (rootCause.getCause() != null) {
                        rootCause = rootCause.getCause();
                    }
                    assertThat(rootCause).isInstanceOf(IllegalStateException.class);
                    assertThat(rootCause.getMessage()).contains("Agent IDP issuer is not configured");
                });
        }

        @Test
        @DisplayName("Should fail when agent user IDP JWKS endpoint is not configured")
        void shouldFailWhenAgentUserIdpJwksEndpointIsNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    // Context should fail because IdTokenValidator bean creation
                    // throws IllegalStateException when JWKS endpoint is not configured
                    assertThat(context).hasFailed();
                    Throwable failure = context.getStartupFailure();
                    assertThat(failure).isNotNull();
                    // Find the root cause which should be IllegalStateException
                    Throwable rootCause = failure;
                    while (rootCause.getCause() != null) {
                        rootCause = rootCause.getCause();
                    }
                    assertThat(rootCause).isInstanceOfAny(IllegalStateException.class, NullPointerException.class);
                    assertThat(rootCause.getMessage()).containsAnyOf(
                        "Agent User IDP JWKS endpoint is not configured",
                        "Agent User IDP issuer is not configured"
                    );
                });
        }

        @Test
        @DisplayName("Should depend on TokenService, IdTokenValidator, and WorkloadRegistry beans")
        void shouldDependOnRequiredBeans() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentIdentityProvider.class);
                    assertThat(context).hasSingleBean(TokenService.class);
                    assertThat(context).hasSingleBean(IdTokenValidator.class);
                    assertThat(context).hasSingleBean(WorkloadRegistry.class);
                });
        }

        @Test
        @DisplayName("Should use custom AgentIdentityProvider bean when defined")
        void shouldUseCustomAgentIdentityProviderBeanWhenDefined() {
            contextRunner
                .withUserConfiguration(CustomAgentIdentityProviderConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentIdentityProvider.class);
                    AgentIdentityProvider provider = context.getBean(AgentIdentityProvider.class);
                    assertThat(provider).isInstanceOf(CustomAgentIdentityProvider.class);
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when role is agent-idp")
        void shouldLoadWhenRoleIsAgentIdp() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WorkloadRegistry.class);
                    assertThat(context).hasSingleBean(AgentIdentityProvider.class);
                });
        }

        @Test
        @DisplayName("Should not load when role is not enabled")
        void shouldNotLoadWhenRoleIsNotEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=false",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(WorkloadRegistry.class);
                    assertThat(context).doesNotHaveBean(AgentIdentityProvider.class);
                });
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind AgentIdpProperties correctly")
        void shouldBindAgentIdpPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json",
                    "open-agent-auth.capabilities.workload-identity.enabled=true"
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
        @DisplayName("Should bind JwksConsumerProperties for agent-user-idp")
        void shouldBindJwksConsumerPropertiesForAgentUserIdp() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.roles.agent-idp.enabled=true",
                    "open-agent-auth.roles.agent-idp.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://agent-user-idp:8080/.well-known/jwks.json",
                    "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.issuer=http://agent-user-idp:8080"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    JwksInfrastructureProperties jwks = properties.getInfrastructures().getJwks();
                    assertThat(jwks.getConsumers()).containsKey("agent-user-idp");
                    
                    JwksConsumerProperties consumer = jwks.getConsumers().get("agent-user-idp");
                    assertThat(consumer.getJwksEndpoint()).isEqualTo("http://agent-user-idp:8080/.well-known/jwks.json");
                    assertThat(consumer.getIssuer()).isEqualTo("http://agent-user-idp:8080");
                });
        }
    }

    // Test configurations for custom beans
    @Configuration
    static class TestConfiguration {
        
        @Bean
        public IdTokenValidator idTokenValidator() throws Exception {
            RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("test-idp-key").generate();
            KeyManager mockKeyManager = Mockito.mock(KeyManager.class);
            Mockito.when(mockKeyManager.resolveVerificationKey(Mockito.anyString())).thenReturn(rsaKey.toPublicJWK());
            return new DefaultIdTokenValidator(mockKeyManager, "test-idp-key");
        }
    }

    @Configuration
    static class CustomWorkloadRegistryConfiguration {
        @Bean
        public WorkloadRegistry customWorkloadRegistry() {
            return new CustomWorkloadRegistry();
        }
    }

    @Configuration
    static class CustomAgentIdentityProviderConfiguration {
        @Bean
        public AgentIdentityProvider customAgentIdentityProvider() {
            return new CustomAgentIdentityProvider();
        }
    }

    // Custom implementations for testing
    static class CustomWorkloadRegistry extends InMemoryWorkloadRegistry {
        public CustomWorkloadRegistry() {
            super();
        }
    }

    static class CustomAgentIdentityProvider implements AgentIdentityProvider {
        @Override
        public WorkloadInfo createAgentWorkload(String idToken, AgentRequestContext context) throws WorkloadCreationException {
            return new WorkloadInfo(
                "test-workload-id",
                "test-user-id",
                "wimse://test.trust.domain",
                "http://localhost:8080",
                "test-public-key",
                java.time.Instant.now(),
                java.time.Instant.now().plusSeconds(3600),
                "active",
                null,
                null
            );
        }

        @Override
        public WorkloadIdentityToken issueWit(String agentWorkloadId)
                throws FrameworkTokenGenerationException, WorkloadNotFoundException {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("JWT")
                .algorithm("RS256")
                .build();
            
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("http://localhost:8080")
                .subject("test-workload-id")
                .expirationTime(new java.util.Date(java.time.Instant.now().plusSeconds(3600).toEpochMilli()))
                .jwtId("test-jti")
                .build();
            
            return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .build();
        }

        @Override
        public WorkloadIdentityToken issueWit(IssueWitRequest request)
                throws FrameworkTokenGenerationException, WorkloadCreationException {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("JWT")
                .algorithm("RS256")
                .build();
            
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("http://localhost:8080")
                .subject("test-workload-id")
                .expirationTime(new java.util.Date(java.time.Instant.now().plusSeconds(3600).toEpochMilli()))
                .jwtId("test-jti")
                .build();
            
            return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .build();
        }

        @Override
        public void revokeAgentWorkload(String agentWorkloadId) throws WorkloadNotFoundException {
            // No-op for testing
        }

        @Override
        public WorkloadInfo getAgentWorkload(String agentWorkloadId) throws WorkloadNotFoundException {
            return new WorkloadInfo(
                agentWorkloadId,
                "test-user-id",
                "wimse://test.trust.domain",
                "http://localhost:8080",
                "test-public-key",
                java.time.Instant.now(),
                java.time.Instant.now().plusSeconds(3600),
                "active",
                null,
                null
            );
        }
    }

}