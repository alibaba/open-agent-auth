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

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2TokenException;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.client.OAuth2DcrClient;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrRequest;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.framework.model.request.ExchangeCodeForTokenRequest;
import com.alibaba.openagentauth.framework.model.response.AuthenticationResponse;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.web.callback.OAuth2CallbackService;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.spring.autoconfigure.core.CoreAutoConfiguration;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AgentDcrAutoRegistrationConfiguration}.
 * <p>
 * This test class verifies the auto-configuration behavior of AgentDcrAutoRegistrationConfiguration,
 * including bean creation, conditional loading, and configuration validation.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("AgentDcrAutoRegistrationConfiguration Tests")
class AgentDcrAutoRegistrationConfigurationTest {

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            CoreAutoConfiguration.class,
            AgentDcrAutoRegistrationConfiguration.class
        ))
        .withUserConfiguration(TestConfiguration.class)
        .withPropertyValues("spring.main.allow-bean-definition-overriding=true");

    @Configuration
    static class TestConfiguration {
        
        @Bean
        public OAuth2DcrClient oAuth2DcrClient() {
            return new MockOAuth2DcrClient();
        }

        @Bean
        public FrameworkOAuth2TokenClient frameworkOAuth2TokenClient() {
            return new MockFrameworkOAuth2TokenClient();
        }

        @Bean
        public SessionMappingBizService sessionMappingBizService() {
            return new SessionMappingBizService(new InMemorySessionMappingStore());
        }

        @Bean
        public OAuth2CallbackService oauth2CallbackService(
                FrameworkOAuth2TokenClient oauth2TokenClient,
                SessionMappingBizService sessionMappingBizService) {
            return new OAuth2CallbackService(
                    oauth2TokenClient,
                    sessionMappingBizService,
                    "/callback"
            );
        }
    }

    @Nested
    @DisplayName("Configuration Loading Tests")
    class ConfigurationLoadingTests {

        @Test
        @DisplayName("Should load when agent role is enabled")
        void shouldLoadWhenAgentRoleIsEnabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-client.callback.enabled=true",
                    "open-agent-auth.capabilities.oauth2-client.callback.auto-register=true"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentDcrAutoRegistrationConfiguration.class);
                });
        }

        @Test
        @DisplayName("Should not load when agent role is disabled")
        void shouldNotLoadWhenAgentRoleIsDisabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.resource-server.enabled=true",
                    "open-agent-auth.roles.resource-server.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain"
                )
                .run(context -> {
                    assertThat(context).doesNotHaveBean(AgentDcrAutoRegistrationConfiguration.class);
                });
        }
    }

    @Nested
    @DisplayName("Auto Registration Behavior Tests")
    class AutoRegistrationBehaviorTests {

        @Test
        @DisplayName("Should not perform auto registration when disabled")
        void shouldNotPerformAutoRegistrationWhenDisabled() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-client.callback.enabled=false",
                    "open-agent-auth.capabilities.oauth2-client.callback.auto-register=false"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentDcrAutoRegistrationConfiguration.class);
                    assertThat(context).hasNotFailed();
                });
        }

        @Test
        @DisplayName("Should skip auto registration when auto-register is false")
        void shouldSkipAutoRegistrationWhenAutoRegisterIsFalse() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-client.callback.enabled=true",
                    "open-agent-auth.capabilities.oauth2-client.callback.auto-register=false"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentDcrAutoRegistrationConfiguration.class);
                    // Configuration should start successfully without performing auto registration
                    assertThat(context).hasNotFailed();
                });
        }
    }

    @Nested
    @DisplayName("Configuration Properties Tests")
    class ConfigurationPropertiesTests {

        @Test
        @DisplayName("Should bind OAuth2ClientProperties correctly")
        void shouldBindOAuth2ClientPropertiesCorrectly() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-client.callback.enabled=true",
                    "open-agent-auth.capabilities.oauth2-client.callback.auto-register=false",
                    "open-agent-auth.capabilities.oauth2-client.callback.endpoint=/callback"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    assertThat(context).hasSingleBean(AgentDcrAutoRegistrationConfiguration.class);
                    
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    assertThat(properties.getCapabilities().getOAuth2Client().getCallback().getEndpoint())
                        .isEqualTo("/callback");
                });
        }

        @Test
        @DisplayName("Should use default callback endpoint when not configured")
        void shouldUseDefaultCallbackEndpointWhenNotConfigured() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-client.callback.enabled=true",
                    "open-agent-auth.capabilities.oauth2-client.callback.auto-register=false"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    
                    OpenAgentAuthProperties properties = context.getBean(OpenAgentAuthProperties.class);
                    // Default endpoint should be set by the configuration
                    assertThat(properties.getCapabilities().getOAuth2Client().getCallback()).isNotNull();
                });
        }
    }

    @Nested
    @DisplayName("Dependency Injection Tests")
    class DependencyInjectionTests {

        @Test
        @DisplayName("Should inject OpenAgentAuthProperties and OAuth2DcrClient")
        void shouldInjectOpenAgentAuthPropertiesAndOAuth2DcrClient() {
            contextRunner
                .withPropertyValues(
                    "open-agent-auth.enabled=true",
                    "open-agent-auth.roles.agent.enabled=true",
                    "open-agent-auth.roles.agent.issuer=http://localhost:8080",
                    "open-agent-auth.infrastructures.trust-domain=wimse://test.trust.domain",
                    "open-agent-auth.capabilities.oauth2-client.callback.enabled=true",
                    "open-agent-auth.capabilities.oauth2-client.callback.auto-register=false"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AgentDcrAutoRegistrationConfiguration.class);
                    assertThat(context).hasSingleBean(OpenAgentAuthProperties.class);
                    assertThat(context).hasSingleBean(OAuth2DcrClient.class);
                });
        }
    }

    /**
     * Mock OAuth2DcrClient for testing purposes.
     */
    static class MockOAuth2DcrClient implements OAuth2DcrClient {
        @Override
        public DcrResponse registerClient(DcrRequest request) throws DcrException {
            return DcrResponse.builder()
                .clientId("mock-client-id")
                .clientSecret("mock-client-secret")
                .registrationAccessToken("mock-registration-token")
                .registrationClientUri("http://localhost:8080/registration/mock-client-id")
                .build();
        }

        @Override
        public DcrResponse readClient(String registrationClientUri, String registrationAccessToken) throws DcrException {
            return DcrResponse.builder()
                .clientId("mock-client-id")
                .clientSecret("mock-client-secret")
                .registrationAccessToken("mock-registration-token")
                .registrationClientUri(registrationClientUri)
                .build();
        }

        @Override
        public DcrResponse updateClient(String registrationClientUri, String registrationAccessToken, DcrRequest request) throws DcrException {
            return DcrResponse.builder()
                .clientId("mock-client-id")
                .clientSecret("mock-client-secret")
                .registrationAccessToken("mock-registration-token")
                .registrationClientUri(registrationClientUri)
                .build();
        }

        @Override
        public void deleteClient(String registrationClientUri, String registrationAccessToken) throws DcrException {
            // Mock delete operation - no-op
        }
    }

    /**
     * Mock FrameworkOAuth2TokenClient for testing purposes.
     */
    static class MockFrameworkOAuth2TokenClient implements FrameworkOAuth2TokenClient {
        @Override
        public AuthenticationResponse exchangeCodeForToken(ExchangeCodeForTokenRequest request) throws OAuth2TokenException {
            return AuthenticationResponse.builder()
                .success(true)
                .idToken("mock-id-token")
                .tokenType("Bearer")
                .expiresIn(3600)
                .build();
        }
    }
}
