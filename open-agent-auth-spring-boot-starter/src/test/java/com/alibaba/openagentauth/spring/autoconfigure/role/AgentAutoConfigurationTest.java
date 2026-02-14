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

import com.alibaba.openagentauth.core.crypto.jwe.JweEncoder;
import com.alibaba.openagentauth.core.crypto.jwe.NimbusJweEncoder;
import com.alibaba.openagentauth.core.protocol.oauth2.par.client.OAuth2ParClient;
import com.alibaba.openagentauth.core.protocol.oauth2.par.jwt.AapParJwtGenerator;
import com.alibaba.openagentauth.core.protocol.oidc.api.IdTokenValidator;
import com.alibaba.openagentauth.core.protocol.vc.VcSigner;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptEncryptionService;
import com.alibaba.openagentauth.core.protocol.vc.chain.PromptProtectionChain;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.resolver.ServiceEndpointResolver;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.framework.actor.Agent;
import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.executor.impl.DefaultAgentAapExecutor;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.executor.config.AgentAapExecutorConfig;
import com.alibaba.openagentauth.framework.web.interceptor.AgentAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.ServiceProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDiscoveryProperties;
import com.alibaba.openagentauth.spring.util.DefaultServiceEndpointResolver;
import com.alibaba.openagentauth.spring.web.controller.OAuth2CallbackController;
import com.alibaba.openagentauth.spring.web.interceptor.SpringAgentAuthenticationInterceptor;
import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AgentAutoConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of AgentAutoConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AgentAutoConfiguration Tests")
class AgentAutoConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            AgentAutoConfiguration.class
        ))
        .withConfiguration(AutoConfigurations.of())
        .withUserConfiguration(TestConfiguration.class)
        .withPropertyValues(
            "open-agent-auth.enabled=true",
            "open-agent-auth.roles.agent.enabled=true",
            "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
            "open-agent-auth.roles.agent.issuer=http://localhost:8080",
            "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://localhost:8082",
            "open-agent-auth.infrastructures.service-discovery.services.agent-idp.endpoints.oauth2-token=/oauth2/token",
            "open-agent-auth.infrastructures.service-discovery.services.agent-idp.endpoints.oauth2-par=/oauth2/par",
            "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://localhost:8083",
            "open-agent-auth.infrastructures.service-discovery.services.authorization-server.endpoints.oauth2-token=/oauth2/token",
            "open-agent-auth.infrastructures.service-discovery.services.authorization-server.endpoints.oauth2-par=/oauth2/par",
            "open-agent-auth.infrastructures.service-discovery.services.agent-user-idp.base-url=http://localhost:8083",
            "open-agent-auth.infrastructures.jwks.consumers.agent-user-idp.jwks-endpoint=http://localhost:8083/.well-known/jwks.json",
            "open-agent-auth.infrastructures.key-management.keys.wit-verification.key-id=wit-signing-key",
            "open-agent-auth.infrastructures.key-management.keys.wit-verification.algorithm=ES256",
            "open-agent-auth.infrastructures.key-management.keys.vc-signing.key-id=vc-signing-key",
            "open-agent-auth.infrastructures.key-management.keys.vc-signing.algorithm=ES256",
            "open-agent-auth.infrastructures.key-management.keys.par-jwt-signing.key-id=par-jwt-signing-key",
            "open-agent-auth.infrastructures.key-management.keys.par-jwt-signing.algorithm=RS256",
            "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
            "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256",
            "open-agent-auth.capabilities.oauth2-client.callback.client-id=test-client-id",
            "open-agent-auth.capabilities.oauth2-client.callback.client-secret=test-client-secret",
            "open-agent-auth.capabilities.oauth2-client.callback.callback-uri=http://localhost:8080/callback",
            "open-agent-auth.capabilities.operation-authorization.enabled=true",
            "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
            "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
            "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
            "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
            "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
            "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
            "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
            "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
            "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
            "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
            "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
            "open-agent-auth.infrastructures.crypto.key.algorithm=ES256"
        );

    @Nested
    @DisplayName("AgentAapExecutor Bean Tests")
    class AgentAapExecutorBeanTests {

        @Test
        @DisplayName("Should create AgentAapExecutor bean when not defined")
        void shouldCreateAgentAapExecutorBeanWhenNotDefined() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentAapExecutor.class);
                    AgentAapExecutor executor = context.getBean(AgentAapExecutor.class);
                    assertThat(executor).isInstanceOf(DefaultAgentAapExecutor.class);
                });
        }

        @Test
        @DisplayName("Should use custom AgentAapExecutor bean when defined")
        void shouldUseCustomAgentAapExecutorBeanWhenDefined() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class, CustomAgentAapExecutorConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentAapExecutor.class);
                    AgentAapExecutor executor = context.getBean(AgentAapExecutor.class);
                    assertThat(executor).isInstanceOf(CustomAgentAapExecutor.class);
                });
        }

        @Test
        @DisplayName("Should depend on required beans")
        void shouldDependOnRequiredBeans() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.roles.resource-server.enabled=false",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    AgentAapExecutor executor = context.getBean(AgentAapExecutor.class);
                    assertThat(executor).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("AgentAuthenticationInterceptor Bean Tests")
    class AgentAuthenticationInterceptorBeanTests {

        @Test
        @DisplayName("Should create AgentAuthenticationInterceptor bean when authentication is enabled")
        void shouldCreateAgentAuthenticationInterceptorBeanWhenAuthenticationEnabled() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentAuthenticationInterceptor.class);
                    assertThat(context).hasSingleBean(SpringAgentAuthenticationInterceptor.class);
                });
        }

        @Test
        @DisplayName("Should not create AgentAuthenticationInterceptor bean when authentication is disabled")
        void shouldNotCreateAgentAuthenticationInterceptorBeanWhenAuthenticationDisabled() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.capabilities.oauth2-client.authentication.enabled=false",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(AgentAuthenticationInterceptor.class);
                    assertThat(context).doesNotHaveBean(SpringAgentAuthenticationInterceptor.class);
                });
        }

        @Test
        @DisplayName("Should configure excluded paths from properties")
        void shouldConfigureExcludedPathsFromProperties() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.roles.resource-server.enabled=false",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    SpringAgentAuthenticationInterceptor interceptor = context.getBean(SpringAgentAuthenticationInterceptor.class);
                    assertThat(interceptor).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("OAuth2CallbackService Bean Tests")
    class OAuth2CallbackServiceBeanTests {

        @Test
        @DisplayName("Should create OAuth2CallbackService bean when not defined")
        void shouldCreateOAuth2CallbackServiceBeanWhenNotDefined() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2CallbackService.class);
                    OAuth2CallbackService service = context.getBean(OAuth2CallbackService.class);
                    assertThat(service).isNotNull();
                });
        }

        @Test
        @DisplayName("Should use custom callback endpoint from configuration")
        void shouldUseCustomCallbackEndpointFromConfiguration() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.capabilities.oauth2-client.callback.endpoint=/custom-callback"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2CallbackService.class);
                    OAuth2CallbackService service = context.getBean(OAuth2CallbackService.class);
                    assertThat(service).isNotNull();
                });
        }

        @Test
        @DisplayName("Should use default callback endpoint when not configured")
        void shouldUseDefaultCallbackEndpointWhenNotConfigured() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.capabilities.oauth2-client.callback.endpoint="
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2CallbackService.class);
                    OAuth2CallbackService service = context.getBean(OAuth2CallbackService.class);
                    assertThat(service).isNotNull();
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
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2CallbackController.class);
                    OAuth2CallbackController controller = context.getBean(OAuth2CallbackController.class);
                    assertThat(controller).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("IdTokenValidator Bean Tests")
    class IdTokenValidatorBeanTests {

        @Test
        @DisplayName("Should create IdTokenValidator bean when JWKS endpoint is configured")
        void shouldCreateIdTokenValidatorBeanWhenJwksEndpointIsConfigured() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(IdTokenValidator.class);
                    IdTokenValidator validator = context.getBean(IdTokenValidator.class);
                    assertThat(validator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should fail when JWKS endpoint is not configured")
        void shouldFailWhenJwksEndpointIsNotConfigured() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    AgentAutoConfiguration.class
                ))
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.service-discovery.services.agent-idp.base-url=http://localhost:8082",
                    "open-agent-auth.infrastructures.service-discovery.services.authorization-server.base-url=http://localhost:8083",
                    "open-agent-auth.infrastructures.service-discovery.services.agent-user-idp.base-url=http://localhost:8083",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.client.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.client.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.client.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.client.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable rootCause = context.getStartupFailure();
                    while (rootCause.getCause() != null) {
                        rootCause = rootCause.getCause();
                    }
                    assertThat(rootCause)
                        .isInstanceOf(NullPointerException.class);
                });
        }
    }

    @Nested
    @DisplayName("OAuth2ParClient Bean Tests")
    class OAuth2ParClientBeanTests {

        @Test
        @DisplayName("Should create OAuth2ParClient bean when not defined")
        void shouldCreateOAuth2ParClientBeanWhenNotDefined() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OAuth2ParClient.class);
                    OAuth2ParClient client = context.getBean(OAuth2ParClient.class);
                    assertThat(client).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("VcSigner Bean Tests")
    class VcSignerBeanTests {

        @Test
        @DisplayName("Should create VcSigner bean")
        void shouldCreateVcSignerBean() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(VcSigner.class);
                    VcSigner signer = context.getBean(VcSigner.class);
                    assertThat(signer).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("AapParJwtGenerator Bean Tests")
    class AapParJwtGeneratorBeanTests {

        @Test
        @DisplayName("Should create AapParJwtGenerator bean")
        void shouldCreateAapParJwtGeneratorBean() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AapParJwtGenerator.class);
                    AapParJwtGenerator generator = context.getBean(AapParJwtGenerator.class);
                    assertThat(generator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should create AapParJwtGenerator bean with null issuer")
        void shouldCreateAapParJwtGeneratorBeanWithNullIssuer() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AapParJwtGenerator.class);
                    AapParJwtGenerator generator = context.getBean(AapParJwtGenerator.class);
                    assertThat(generator).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("WitValidator Bean Tests")
    class WitValidatorBeanTests {

        @Test
        @DisplayName("Should create WitValidator bean with correct verification key")
        void shouldCreateWitValidatorBeanWithCorrectVerificationKey() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WitValidator.class);
                    WitValidator validator = context.getBean(WitValidator.class);
                    assertThat(validator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should create WitValidator bean with trust domain from properties")
        void shouldCreateWitValidatorBeanWithTrustDomain() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://custom.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WitValidator.class);
                    WitValidator validator = context.getBean(WitValidator.class);
                    assertThat(validator).isNotNull();
                });
        }

        @Test
        @DisplayName("Should create WitValidator bean with custom verification key ID")
        void shouldCreateWitValidatorBeanWithCustomKeyId() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(WitValidator.class);
                    WitValidator validator = context.getBean(WitValidator.class);
                    assertThat(validator).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("JweEncryptionKeyId Bean Tests")
    class JweEncryptionKeyIdBeanTests {

        @Test
        @DisplayName("Should create JweEncryptionKeyId bean")
        void shouldCreateJweEncryptionKeyIdBean() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasBean("jweEncryptionKeyId");
                    String keyId = context.getBean("jweEncryptionKeyId", String.class);
                    assertThat(keyId).isNotNull();
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
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(ServiceEndpointResolver.class);
                    ServiceEndpointResolver resolver = context.getBean(ServiceEndpointResolver.class);
                    assertThat(resolver).isInstanceOf(DefaultServiceEndpointResolver.class);
                });
        }
    }

    @Nested
    @DisplayName("Conditional Loading Tests")
    class ConditionalLoadingTests {

        @Test
        @DisplayName("Should load when role is agent")
        void shouldLoadWhenRoleIsAgent() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentAapExecutor.class);
                    assertThat(context).hasSingleBean(OAuth2CallbackService.class);
                    assertThat(context).hasSingleBean(OAuth2CallbackController.class);
                    assertThat(context).hasSingleBean(VcSigner.class);
                    assertThat(context).hasSingleBean(AapParJwtGenerator.class);
                });
        }

        @Test
        @DisplayName("Should not load when role is not agent")
        void shouldNotLoadWhenRoleIsNotAgent() {
            new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    CoreAutoConfiguration.class,
                    AgentAutoConfiguration.class
                ))
                .withUserConfiguration(TestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.roles.resource-server.enabled=true",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.roles.resource-server.issuer=http://localhost:8080"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(AgentAapExecutor.class);
                    assertThat(context).doesNotHaveBean(OAuth2CallbackService.class);
                    assertThat(context).doesNotHaveBean(OAuth2CallbackController.class);
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
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties).isNotNull();
                    assertThat(properties.getInfrastructures().getTrustDomain()).isEqualTo("wimse://test.trust.domain");
                });
        }
    }

    @Nested
    @DisplayName("New Properties Integration Tests")
    class NewPropertiesIntegrationTests {

        @Test
        @DisplayName("Should bind OperationAuthorizationProperties with new structure")
        void shouldBindOperationAuthorizationPropertiesWithNewStructure() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-key-id"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    OperationAuthorizationProperties opAuth = properties.getCapabilities().getOperationAuthorization();
                    assertThat(opAuth).isNotNull();
                    assertThat(opAuth.getOauth2Client().getClientId()).isEqualTo("test-client-id");
                    assertThat(opAuth.getPromptEncryption().isEnabled()).isTrue();
                });
        }

        @Test
        @DisplayName("Should bind ServiceDiscoveryProperties correctly")
        void shouldBindServiceDiscoveryPropertiesCorrectly() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    
                    ServiceDiscoveryProperties discovery = properties.getInfrastructures().getServiceDiscovery();
                    assertThat(discovery).isNotNull();
                    assertThat(discovery.getServices()).containsKey("agent-idp");
                    assertThat(discovery.getServices().get("agent-idp").getBaseUrl()).isEqualTo("http://localhost:8082");
                });
        }
    }

    @Nested
    @DisplayName("AgentWebMvcConfiguration Tests")
    class AgentWebMvcConfigurationTests {

        @Test
        @DisplayName("Should register authentication interceptor when role is agent")
        void shouldRegisterAuthenticationInterceptorWhenRoleIsAgent() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(SpringAgentAuthenticationInterceptor.class);
                });
        }

        @Test
        @DisplayName("Should not register authentication interceptor when authentication is disabled")
        void shouldNotRegisterAuthenticationInterceptorWhenAuthenticationDisabled() {
            contextRunner
                .withUserConfiguration(WitKeyTestConfiguration.class)
                .withPropertyValues(
                    "open-agent-auth.role=agent",
                    "open-agent-auth.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.operation-authorization.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-id=test-client-id",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.client-secret=test-client-secret",
                    "open-agent-auth.capabilities.operation-authorization.oauth2-client.oauth-callbacks-redirect-uri=http://localhost:8080/callback",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.channel=test-channel",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.language=en-US",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.platform=test-platform",
                    "open-agent-auth.capabilities.operation-authorization.agent-context.agent-client=test-agent-client",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.enabled=true",
                    "open-agent-auth.capabilities.operation-authorization.prompt-encryption.encryption-key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-id=test-server-client-id",
                    "open-agent-auth.capabilities.oauth2-client.server-callback.client-secret=test-server-client-secret",
                    "open-agent-auth.capabilities.oauth2-client.authentication.enabled=false",
                    "open-agent-auth.infrastructures.crypto.key.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.algorithm=RS256",
                    "open-agent-auth.infrastructures.key-management.keys.par-jwt.key-id=test-par-jwt-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.vc.algorithm=ES256",
                    "open-agent-auth.infrastructures.key-management.keys.vc.key-id=test-vc-signing-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.key-id=test-jwe-encryption-key-id",
                    "open-agent-auth.infrastructures.key-management.keys.jwe.algorithm=RS256"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(SpringAgentAuthenticationInterceptor.class);
                });
        }
    }

    // Test configurations for custom beans
    @Configuration
    static class TestConfiguration {
        @Bean
        public SessionMappingBizService sessionMappingBizService() {
            return new SessionMappingBizService(new InMemorySessionMappingStore());
        }
        
        @Bean
        public SessionManager sessionManager() {
            return new SessionManager();
        }
        
        @Bean
        public JweEncoder jweEncoder() throws JOSEException {
            RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("test-encryption-key")
                .generate();
            return new NimbusJweEncoder(rsaKey, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        }
        
        @Bean
        public PromptEncryptionService promptEncryptionService(JweEncoder jweEncoder) {
            return new PromptEncryptionService(jweEncoder, false);
        }
    }

    @Configuration
    static class WitKeyTestConfiguration {
        @Bean
        public ECKey witVerificationKey() throws Exception {
            return new ECKeyGenerator(Curve.P_256).keyID("wit-signing-key").generate();
        }
        
        @Bean
        @ConditionalOnMissingBean
        public WitValidator witValidator(ECKey witVerificationKey) {
            return new WitValidator(witVerificationKey, new TrustDomain("wimse://test.trust.domain"));
        }
        
        @Bean
        @ConditionalOnMissingBean
        public AoatValidator aoatValidator() throws Exception {
            RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("aoat-signing-key").generate();
            return new AoatValidator(rsaKey, "wimse://test.trust.domain", "test-issuer");
        }
        
        @Bean
        @ConditionalOnMissingBean
        public WptValidator wptValidator() {
            return new WptValidator();
        }

        @Bean
        @ConditionalOnMissingBean
        public ServiceProperties serviceProperties() {
            ServiceProperties props = new ServiceProperties();
            props.postProcess();
            return props;
        }

        @Bean
        @ConditionalOnMissingBean
        public ServiceEndpointResolver serviceEndpointResolver(ServiceProperties serviceProperties) {
            return new DefaultServiceEndpointResolver(serviceProperties);
        }
    }

    /**
     * Configuration for testing witVerificationKey bean loading from JWKS endpoint.
     * This configuration provides the necessary dependencies to test the JWKS loading logic.
     */
    @Configuration
    static class WitVerificationKeyTestConfiguration {
        @Bean
        @ConditionalOnMissingBean
        public SessionMappingBizService sessionMappingBizService() {
            return new SessionMappingBizService(new InMemorySessionMappingStore());
        }
        
        @Bean
        @ConditionalOnMissingBean
        public SessionManager sessionManager() {
            return new SessionManager();
        }
        
        @Bean
        @ConditionalOnMissingBean
        public JweEncoder jweEncoder() throws JOSEException {
            RSAKey rsaKey = new RSAKeyGenerator(2048)
                .keyID("test-encryption-key")
                .generate();
            return new NimbusJweEncoder(rsaKey, JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        }
        
        @Bean
        @ConditionalOnMissingBean
        public PromptEncryptionService promptEncryptionService(JweEncoder jweEncoder) {
            return new PromptEncryptionService(jweEncoder, false);
        }
    }

    @Configuration
    static class CustomAgentAapExecutorConfiguration {
        @Bean
        @Primary
        @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
        public AgentAapExecutor customAgentAapExecutor(
                @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") Agent agent,
                @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") VcSigner vcSigner,
                @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") PolicyBuilder policyBuilder,
                @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") PromptProtectionChain promptProtectionChain,
                @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") AgentAapExecutorConfig config) {
            return new CustomAgentAapExecutor(agent, vcSigner, policyBuilder, promptProtectionChain, config);
        }
    }

    // Custom implementations for testing
    static class CustomAgentAapExecutor extends DefaultAgentAapExecutor {
        public CustomAgentAapExecutor(
                Agent agent,
                VcSigner vcSigner,
                PolicyBuilder policyBuilder,
                PromptProtectionChain promptProtectionChain,
                AgentAapExecutorConfig config) {
            super(agent, vcSigner, policyBuilder, promptProtectionChain, config);
        }
    }
}
