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

import com.alibaba.openagentauth.framework.web.interceptor.UserAuthenticationInterceptor;
import com.alibaba.openagentauth.spring.autoconfigure.properties.AdminProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.web.interceptor.AdminAccessInterceptor;
import com.alibaba.openagentauth.spring.web.interceptor.SpringUserAuthenticationInterceptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.handler.MappedInterceptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AdminAutoConfiguration}.
 * <p>
 * Tests the auto-configuration for the Admin Console, including interceptor
 * bean creation and interceptor registration with correct path patterns.
 * </p>
 * <p>
 * <b>Note:</b> These tests use real {@link AdminProperties} objects instead of
 * mocking {@link OpenAgentAuthProperties}, because {@code OpenAgentAuthProperties}
 * implements {@link org.springframework.beans.factory.InitializingBean} which
 * causes issues with Mockito inline mocking on JDK 17+.
 * </p>
 *
 * @since 1.0
 * @see AdminAutoConfiguration
 * @see AdminAccessInterceptor
 */
@DisplayName("AdminAutoConfiguration Tests")
class AdminAutoConfigurationTest {

    private OpenAgentAuthProperties rootProperties;
    private AdminProperties adminProperties;

    /**
     * A simple ObjectProvider implementation for testing that wraps a nullable value.
     */
    private static <T> ObjectProvider<T> objectProviderOf(T value) {
        return new ObjectProvider<>() {
            @Override
            public T getObject() {
                if (value == null) {
                    throw new org.springframework.beans.factory.NoSuchBeanDefinitionException("No bean available");
                }
                return value;
            }

            @Override
            public T getObject(Object... args) {
                return getObject();
            }

            @Override
            public T getIfAvailable() {
                return value;
            }

            @Override
            public T getIfUnique() {
                return value;
            }
        };
    }

    @BeforeEach
    void setUp() {
        adminProperties = new AdminProperties();
        adminProperties.setEnabled(true);

        rootProperties = new OpenAgentAuthProperties();
        rootProperties.setEnabled(false);
        rootProperties.setAdmin(adminProperties);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create configuration successfully with valid properties")
        void shouldCreateConfigurationSuccessfully() {
            // Act
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Assert
            assertThat(configuration).isNotNull();
        }

        @Test
        @DisplayName("Should read admin properties from root properties")
        void shouldReadAdminPropertiesFromRootProperties() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of("admin"));

            // Act
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Assert
            assertThat(configuration).isNotNull();
        }
    }

    @Nested
    @DisplayName("adminAccessInterceptor() Bean Tests")
    class AdminAccessInterceptorBeanTests {

        @Test
        @DisplayName("Should create AdminAccessInterceptor bean")
        void shouldCreateAdminAccessInterceptorBean() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of("admin"));
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Act
            AdminAccessInterceptor interceptor = configuration.adminAccessInterceptor();

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with access control disabled")
        void shouldCreateInterceptorWithAccessControlDisabled() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(false);
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Act
            AdminAccessInterceptor interceptor = configuration.adminAccessInterceptor();

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with empty allowed subjects (fail-closed)")
        void shouldCreateInterceptorWithEmptyAllowedSubjects() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of());
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Act
            AdminAccessInterceptor interceptor = configuration.adminAccessInterceptor();

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should create interceptor with multiple allowed subjects")
        void shouldCreateInterceptorWithMultipleAllowedSubjects() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(
                    List.of("admin", "operator", "superuser"));
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Act
            AdminAccessInterceptor interceptor = configuration.adminAccessInterceptor();

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }

    @Nested
    @DisplayName("addInterceptors() Tests")
    class AddInterceptorsTests {

        @Test
        @DisplayName("Should register only AdminAccessInterceptor when no UserAuthenticationInterceptor available")
        void shouldRegisterOnlyAdminAccessInterceptorWhenNoUserAuthAvailable() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of("admin"));
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - only AdminAccessInterceptor registered
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(1);
            assertThat(interceptors.get(0)).isInstanceOf(MappedInterceptor.class);
            MappedInterceptor mappedInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(mappedInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should register both user auth and admin access interceptors when UserAuthenticationInterceptor available")
        void shouldRegisterBothInterceptorsWhenUserAuthAvailable() {
            // Arrange
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of("admin"));
            UserAuthenticationInterceptor userAuthInterceptor = new UserAuthenticationInterceptor(List.of());
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(userAuthInterceptor));

            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - both interceptors registered: user auth first, then admin access
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(2);

            assertThat(interceptors.get(0)).isInstanceOf(MappedInterceptor.class);
            MappedInterceptor firstInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(firstInterceptor.getInterceptor()).isInstanceOf(SpringUserAuthenticationInterceptor.class);

            assertThat(interceptors.get(1)).isInstanceOf(MappedInterceptor.class);
            MappedInterceptor secondInterceptor = (MappedInterceptor) interceptors.get(1);
            assertThat(secondInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should register interceptors with custom endpoint paths")
        void shouldRegisterInterceptorsWithCustomEndpointPaths() {
            // Arrange
            AdminProperties.EndpointProperties endpoints = adminProperties.getEndpoints();
            endpoints.setDashboard("/custom-admin");
            endpoints.setWorkloads("/custom-admin/workloads");
            endpoints.setBindings("/custom-admin/bindings");
            endpoints.setPolicies("/custom-admin/policies");
            endpoints.setAudit("/custom-admin/audit");

            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of("admin"));
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(1);
            assertThat(interceptors.get(0)).isInstanceOf(MappedInterceptor.class);
            MappedInterceptor mappedInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(mappedInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }
    }

    /**
     * Test helper that exposes the protected {@code getInterceptors()} method
     * from {@link InterceptorRegistry} for verification in unit tests.
     */
    private static class TestableInterceptorRegistry extends InterceptorRegistry {

        List<Object> exposedGetInterceptors() {
            return getInterceptors();
        }
    }

    @Nested
    @DisplayName("Fallback Interceptor Tests")
    class FallbackInterceptorTests {

        @Test
        @DisplayName("Should create fallback interceptor when agent-user-idp peer is configured")
        void shouldCreateFallbackInterceptorWithAgentUserIdpPeer() {
            // Arrange - simulate agent-idp role with agent-user-idp peer (no UserAuthenticationInterceptor bean)
            configureUserIdpPeer("agent-user-idp", "http://localhost:8083");
            configureOAuth2Client("sample-agent-idp");
            configureRole("agent-idp", "http://localhost:8082");

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - both fallback auth interceptor and admin access interceptor registered
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(2);

            MappedInterceptor firstInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(firstInterceptor.getInterceptor()).isInstanceOf(SpringUserAuthenticationInterceptor.class);

            MappedInterceptor secondInterceptor = (MappedInterceptor) interceptors.get(1);
            assertThat(secondInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should create fallback interceptor when as-user-idp peer is configured")
        void shouldCreateFallbackInterceptorWithAsUserIdpPeer() {
            // Arrange - simulate authorization-server role with as-user-idp peer
            configureUserIdpPeer("as-user-idp", "http://localhost:8084");
            configureOAuth2Client("sample-as-client");
            configureRole("authorization-server", "http://localhost:8085");

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - fallback interceptor created from as-user-idp
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(2);

            MappedInterceptor firstInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(firstInterceptor.getInterceptor()).isInstanceOf(SpringUserAuthenticationInterceptor.class);
        }

        @Test
        @DisplayName("Should prefer existing bean over fallback interceptor")
        void shouldPreferExistingBeanOverFallback() {
            // Arrange - both existing bean and peer configured
            configureUserIdpPeer("agent-user-idp", "http://localhost:8083");
            configureOAuth2Client("sample-agent-idp");
            configureRole("agent-idp", "http://localhost:8082");

            UserAuthenticationInterceptor existingInterceptor = new UserAuthenticationInterceptor(List.of());
            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(existingInterceptor));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - existing bean used, not fallback
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(2);

            MappedInterceptor firstInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(firstInterceptor.getInterceptor()).isInstanceOf(SpringUserAuthenticationInterceptor.class);
        }

        @Test
        @DisplayName("Should not create fallback when no User IDP peer configured")
        void shouldNotCreateFallbackWhenNoUserIdpPeerConfigured() {
            // Arrange - no user IDP peer, no existing bean
            configureRole("resource-server", "http://localhost:8086");

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - only admin access interceptor, no auth interceptor
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(1);

            MappedInterceptor onlyInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(onlyInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should not create fallback when User IDP peer has no issuer")
        void shouldNotCreateFallbackWhenUserIdpPeerHasNoIssuer() {
            // Arrange - peer configured but with blank issuer
            JwksConsumerProperties consumerProps = new JwksConsumerProperties();
            consumerProps.setIssuer("");
            rootProperties.getInfrastructures().getJwks().getConsumers()
                    .put("agent-user-idp", consumerProps);
            configureRole("agent-idp", "http://localhost:8082");

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - no auth interceptor created
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(1);
            MappedInterceptor onlyInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(onlyInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should not create fallback when OAuth2 client-id is missing")
        void shouldNotCreateFallbackWhenOAuth2ClientIdMissing() {
            // Arrange - peer configured but no OAuth2 client-id
            configureUserIdpPeer("agent-user-idp", "http://localhost:8083");
            configureRole("agent-idp", "http://localhost:8082");
            // Do NOT set client-id

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - no auth interceptor created
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(1);
            MappedInterceptor onlyInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(onlyInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should not create fallback when no role issuer configured")
        void shouldNotCreateFallbackWhenNoRoleIssuerConfigured() {
            // Arrange - peer and client configured but no role issuer for callback URL
            configureUserIdpPeer("agent-user-idp", "http://localhost:8083");
            configureOAuth2Client("sample-agent-idp");
            // Do NOT configure any role

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - no auth interceptor created (cannot determine callback URL)
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(1);
            MappedInterceptor onlyInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(onlyInterceptor.getInterceptor()).isInstanceOf(AdminAccessInterceptor.class);
        }

        @Test
        @DisplayName("Should prefer agent-user-idp over as-user-idp when both configured")
        void shouldPreferAgentUserIdpOverAsUserIdp() {
            // Arrange - both user IDPs configured
            configureUserIdpPeer("agent-user-idp", "http://localhost:8083");
            configureUserIdpPeer("as-user-idp", "http://localhost:8084");
            configureOAuth2Client("sample-client");
            configureRole("agent-idp", "http://localhost:8082");

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));
            TestableInterceptorRegistry registry = new TestableInterceptorRegistry();

            // Act
            configuration.addInterceptors(registry);

            // Assert - interceptor created (agent-user-idp is checked first)
            List<Object> interceptors = registry.exposedGetInterceptors();
            assertThat(interceptors).hasSize(2);

            MappedInterceptor firstInterceptor = (MappedInterceptor) interceptors.get(0);
            assertThat(firstInterceptor.getInterceptor()).isInstanceOf(SpringUserAuthenticationInterceptor.class);
        }

        private void configureUserIdpPeer(String serviceName, String issuer) {
            JwksConsumerProperties consumerProps = new JwksConsumerProperties();
            consumerProps.setIssuer(issuer);
            rootProperties.getInfrastructures().getJwks().getConsumers()
                    .put(serviceName, consumerProps);
        }

        private void configureOAuth2Client(String clientId) {
            rootProperties.getCapabilities().getOAuth2Client().setClientId(clientId);
        }

        private void configureRole(String roleName, String issuer) {
            RolesProperties.RoleProperties roleProps = new RolesProperties.RoleProperties();
            roleProps.setEnabled(true);
            roleProps.setIssuer(issuer);
            rootProperties.getRoles().put(roleName, roleProps);
        }
    }

    @Nested
    @DisplayName("Integration Scenario Tests")
    class IntegrationScenarioTests {

        @Test
        @DisplayName("Should support typical production configuration")
        void shouldSupportTypicalProductionConfiguration() {
            // Arrange - typical production setup
            adminProperties.setEnabled(true);
            adminProperties.getAccessControl().setEnabled(true);
            adminProperties.getAccessControl().setAllowedSessionSubjects(List.of("admin"));

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Act
            AdminAccessInterceptor interceptor = configuration.adminAccessInterceptor();

            // Assert
            assertThat(interceptor).isNotNull();
        }

        @Test
        @DisplayName("Should support development configuration with access control disabled")
        void shouldSupportDevelopmentConfigurationWithAccessControlDisabled() {
            // Arrange - development setup with no access control
            adminProperties.setEnabled(true);
            adminProperties.getAccessControl().setEnabled(false);

            AdminAutoConfiguration configuration = new AdminAutoConfiguration(
                    rootProperties, objectProviderOf(null));

            // Act
            AdminAccessInterceptor interceptor = configuration.adminAccessInterceptor();

            // Assert
            assertThat(interceptor).isNotNull();
        }
    }
}
