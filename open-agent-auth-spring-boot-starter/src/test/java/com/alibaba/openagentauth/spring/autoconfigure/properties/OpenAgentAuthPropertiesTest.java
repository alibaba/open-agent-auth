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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.UserAuthenticationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.WorkloadIdentityProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDefinitionProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OpenAgentAuthProperties}.
 * <p>
 * This test class verifies the configuration properties for the Open Agent Auth framework,
 * including default values, getter/setter methods, and nested properties.
 * </p>
 *
 * @since 1.0
 */
@DisplayName("OpenAgentAuthProperties Tests")
class OpenAgentAuthPropertiesTest {

    private OpenAgentAuthProperties properties;

    @BeforeEach
    void setUp() {
        properties = new OpenAgentAuthProperties();
    }

    @Nested
    @DisplayName("Default Values Tests")
    class DefaultValuesTests {

        @Test
        @DisplayName("Should have default enabled value as true")
        void shouldHaveDefaultEnabledAsTrue() {
            assertTrue(properties.isEnabled());
        }

        @Test
        @DisplayName("Should initialize all nested properties")
        void shouldInitializeAllNestedProperties() {
            assertNotNull(properties.getInfrastructures());
            assertNotNull(properties.getCapabilities());
            assertNotNull(properties.getRoles());
            assertNotNull(properties.getSecurity());
            assertNotNull(properties.getMonitoring());
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterAndSetterTests {

        @Test
        @DisplayName("Should set and get enabled property")
        void shouldSetAndGetEnabled() {
            properties.setEnabled(false);
            assertFalse(properties.isEnabled());
            
            properties.setEnabled(true);
            assertTrue(properties.isEnabled());
        }

        @Test
        @DisplayName("Should set and get infrastructure properties")
        void shouldSetAndGetInfrastructureProperties() {
            InfrastructureProperties infrastructure = new InfrastructureProperties();
            properties.setInfrastructures(infrastructure);
            assertSame(infrastructure, properties.getInfrastructures());
        }

        @Test
        @DisplayName("Should set and get capabilities properties")
        void shouldSetAndGetCapabilitiesProperties() {
            CapabilitiesProperties capabilities = new CapabilitiesProperties();
            properties.setCapabilities(capabilities);
            assertSame(capabilities, properties.getCapabilities());
        }

        @Test
        @DisplayName("Should set and get roles properties")
        void shouldSetAndGetRolesProperties() {
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            properties.setRoles(roles);
            assertEquals(roles, properties.getRoles());
        }

        @Test
        @DisplayName("Should set and get security properties")
        void shouldSetAndGetSecurityProperties() {
            SecurityProperties security = new SecurityProperties();
            properties.setSecurity(security);
            assertSame(security, properties.getSecurity());
        }

        @Test
        @DisplayName("Should set and get monitoring properties")
        void shouldSetAndGetMonitoringProperties() {
            MonitoringProperties monitoring = new MonitoringProperties();
            properties.setMonitoring(monitoring);
            assertSame(monitoring, properties.getMonitoring());
        }
    }

    @Nested
    @DisplayName("Infrastructure Properties Tests")
    class InfrastructurePropertiesTests {

        private InfrastructureProperties infrastructureProperties;

        @BeforeEach
        void setUp() {
            infrastructureProperties = new InfrastructureProperties();
        }

        @Test
        @DisplayName("Should initialize trust domain")
        void shouldInitializeTrustDomain() {
            assertNotNull(infrastructureProperties.getTrustDomain());
        }

        @Test
        @DisplayName("Should set and get trust domain")
        void shouldSetAndGetTrustDomain() {
            infrastructureProperties.setTrustDomain("wimse://custom.domain");
            assertEquals("wimse://custom.domain", infrastructureProperties.getTrustDomain());
        }
    }

    @Nested
    @DisplayName("CapabilitiesProperties Tests")
    class CapabilitiesPropertiesTests {

        private CapabilitiesProperties capabilitiesProperties;

        @BeforeEach
        void setUp() {
            capabilitiesProperties = new CapabilitiesProperties();
        }

        @Test
        @DisplayName("Should initialize oauth2 server properties")
        void shouldInitializeOAuth2ServerProperties() {
            assertNotNull(capabilitiesProperties.getOAuth2Server());
        }

        @Test
        @DisplayName("Should initialize oauth2 client properties")
        void shouldInitializeOAuth2ClientProperties() {
            assertNotNull(capabilitiesProperties.getOAuth2Client());
        }

        @Test
        @DisplayName("Should initialize workload identity properties")
        void shouldInitializeWorkloadIdentityProperties() {
            assertNotNull(capabilitiesProperties.getWorkloadIdentity());
        }

        @Test
        @DisplayName("Should initialize operation authorization properties")
        void shouldInitializeOperationAuthorizationProperties() {
            assertNotNull(capabilitiesProperties.getOperationAuthorization());
        }

        @Test
        @DisplayName("Should initialize user authentication properties")
        void shouldInitializeUserAuthenticationProperties() {
            assertNotNull(capabilitiesProperties.getUserAuthentication());
        }

        @Test
        @DisplayName("Should set and get oauth2 server properties")
        void shouldSetAndGetOAuth2ServerProperties() {
            OAuth2ServerProperties oauth2Server = new OAuth2ServerProperties();
            capabilitiesProperties.setOAuth2Server(oauth2Server);
            assertSame(oauth2Server, capabilitiesProperties.getOAuth2Server());
        }

        @Test
        @DisplayName("Should set and get oauth2 client properties")
        void shouldSetAndGetOAuth2ClientProperties() {
            OAuth2ClientProperties oauth2Client = new OAuth2ClientProperties();
            capabilitiesProperties.setOAuth2Client(oauth2Client);
            assertSame(oauth2Client, capabilitiesProperties.getOAuth2Client());
        }

        @Test
        @DisplayName("Should set and get workload identity properties")
        void shouldSetAndGetWorkloadIdentityProperties() {
            WorkloadIdentityProperties workloadIdentity = new WorkloadIdentityProperties();
            capabilitiesProperties.setWorkloadIdentity(workloadIdentity);
            assertSame(workloadIdentity, capabilitiesProperties.getWorkloadIdentity());
        }

        @Test
        @DisplayName("Should set and get operation authorization properties")
        void shouldSetAndGetOperationAuthorizationProperties() {
            OperationAuthorizationProperties operationAuthorization = new OperationAuthorizationProperties();
            capabilitiesProperties.setOperationAuthorization(operationAuthorization);
            assertSame(operationAuthorization, capabilitiesProperties.getOperationAuthorization());
        }

        @Test
        @DisplayName("Should set and get user authentication properties")
        void shouldSetAndGetUserAuthenticationProperties() {
            UserAuthenticationProperties userAuthentication = new UserAuthenticationProperties();
            capabilitiesProperties.setUserAuthentication(userAuthentication);
            assertSame(userAuthentication, capabilitiesProperties.getUserAuthentication());
        }

    }

    @Nested
    @DisplayName("RolesProperties Tests")
    class RolesPropertiesTests {

        private RolesProperties rolesProperties;

        @BeforeEach
        void setUp() {
            rolesProperties = new RolesProperties();
        }

        @Test
        @DisplayName("Should initialize roles as empty map")
        void shouldInitializeRolesAsEmptyMap() {
            assertNotNull(rolesProperties.getRoles());
            assertTrue(rolesProperties.getRoles().isEmpty());
        }

        @Test
        @DisplayName("Should set and get roles map")
        void shouldSetAndGetRolesMap() {
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            rolesProperties.setRoles(roles);
            assertEquals(roles, rolesProperties.getRoles());
        }

        @Test
        @DisplayName("Should create and configure role properties")
        void shouldCreateAndConfigureRoleProperties() {
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setEnabled(true);
            role.setIssuer("https://example.com/issuer");

            assertTrue(role.isEnabled());
            assertEquals("https://example.com/issuer", role.getIssuer());
        }

        @Test
        @DisplayName("Should handle null issuer")
        void shouldHandleNullIssuer() {
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setIssuer(null);
            assertNull(role.getIssuer());
        }

    }

    @Nested
    @DisplayName("Boundary Conditions and Null Handling Tests")
    class BoundaryConditionsAndNullHandlingTests {

        @Test
        @DisplayName("Should handle null for all nested properties")
        void shouldHandleNullForAllNestedProperties() {
            properties.setInfrastructures(null);
            properties.setCapabilities(null);
            properties.setRoles(null);
            properties.setSecurity(null);
            properties.setMonitoring(null);

            assertNull(properties.getInfrastructures());
            assertNull(properties.getCapabilities());
            // Note: roles field is initialized to empty HashMap and setRoles() clears it when null is passed
            // So getRoles() returns empty map, not null
            assertNotNull(properties.getRoles());
            assertTrue(properties.getRoles().isEmpty());
            assertNull(properties.getSecurity());
            assertNull(properties.getMonitoring());
        }

        @Test
        @DisplayName("Should create independent instances")
        void shouldCreateIndependentInstances() {
            OpenAgentAuthProperties properties1 = new OpenAgentAuthProperties();
            OpenAgentAuthProperties properties2 = new OpenAgentAuthProperties();

            properties1.setEnabled(false);

            assertTrue(properties2.isEnabled());
        }
    }

    @Nested
    @DisplayName("InitializingBean and Role-Aware Inference Tests")
    class InitializingBeanAndRoleAwareInferenceTests {

        @Test
        @DisplayName("afterPropertiesSet when enabled should trigger inference")
        void afterPropertiesSet_whenEnabled_shouldTriggerInference() {
            properties.setEnabled(true);
            properties.setInfrastructures(new InfrastructureProperties());
            
            // Add an enabled role
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setEnabled(true);
            role.setIssuer("http://localhost:8080");
            roles.put("agent-idp", role);
            properties.setRoles(roles);
            
            // Call afterPropertiesSet
            properties.afterPropertiesSet();
            
            // Verify that inference has occurred - JWKS provider should be enabled for agent-idp role
            assertThat(properties.getInfrastructures().getJwks().getProvider().isEnabled()).isTrue();
        }

        @Test
        @DisplayName("afterPropertiesSet when disabled should not trigger inference")
        void afterPropertiesSet_whenDisabled_shouldNotTriggerInference() {
            properties.setEnabled(false);
            properties.setInfrastructures(new InfrastructureProperties());
            
            // Add an enabled role that would normally trigger key inference
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setEnabled(true);
            role.setIssuer("http://localhost:8080");
            roles.put("agent-idp", role);
            properties.setRoles(roles);
            
            // Call afterPropertiesSet
            properties.afterPropertiesSet();
            
            // Verify that inference has NOT occurred - no keys should be inferred
            assertThat(properties.getInfrastructures().getKeyManagement().getKeys()).isEmpty();
        }

        @Test
        @DisplayName("afterPropertiesSet should infer keys from roles")
        void afterPropertiesSet_shouldInferKeysFromRoles() {
            properties.setEnabled(true);
            properties.setInfrastructures(new InfrastructureProperties());
            
            // Add an enabled role that requires keys
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setEnabled(true);
            role.setIssuer("http://localhost:8080");
            roles.put("agent-idp", role);
            properties.setRoles(roles);
            
            // Call afterPropertiesSet
            properties.afterPropertiesSet();
            
            // Verify that keys have been inferred
            Map<String, KeyDefinitionProperties> keys = properties.getInfrastructures().getKeyManagement().getKeys();
            assertThat(keys).isNotEmpty();
            
            // Verify that a local provider was added
            assertThat(properties.getInfrastructures().getKeyManagement().getProviders()).containsKey("local");
        }

        @Test
        @DisplayName("afterPropertiesSet should expand peers to JWKS consumers")
        void afterPropertiesSet_shouldExpandPeersToJwksConsumers() {
            properties.setEnabled(true);
            properties.setInfrastructures(new InfrastructureProperties());
            
            // Must have at least one enabled role for processConfiguration to run
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setEnabled(true);
            role.setIssuer("http://localhost:8080");
            roles.put("agent-idp", role);
            properties.setRoles(roles);
            
            // Add a peer configuration
            Map<String, PeerProperties> peers = new HashMap<>();
            PeerProperties peer = new PeerProperties();
            peer.setEnabled(true);
            peer.setIssuer("http://localhost:8082");
            peers.put("authorization-server", peer);
            properties.setPeers(peers);
            
            // Call afterPropertiesSet
            properties.afterPropertiesSet();
            
            // Verify that peer was expanded to JWKS consumer
            Map<String, JwksConsumerProperties> consumers = properties.getInfrastructures().getJwks().getConsumers();
            assertThat(consumers).containsKey("authorization-server");
            assertThat(consumers.get("authorization-server").getIssuer()).isEqualTo("http://localhost:8082");
            
            // Verify that peer was expanded to service-discovery entry
            Map<String, ServiceDefinitionProperties> services = properties.getInfrastructures().getServiceDiscovery().getServices();
            assertThat(services).containsKey("authorization-server");
            assertThat(services.get("authorization-server").getBaseUrl()).isEqualTo("http://localhost:8082");
        }

        @Test
        @DisplayName("afterPropertiesSet should not override explicit config")
        void afterPropertiesSet_shouldNotOverrideExplicitConfig() {
            properties.setEnabled(true);
            properties.setInfrastructures(new InfrastructureProperties());
            
            // Must have at least one enabled role for processConfiguration to run
            Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
            RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
            role.setEnabled(true);
            role.setIssuer("http://localhost:8080");
            roles.put("agent-idp", role);
            properties.setRoles(roles);
            
            // Add explicit JWKS consumer configuration
            JwksConsumerProperties explicitConsumer = new JwksConsumerProperties();
            explicitConsumer.setEnabled(true);
            explicitConsumer.setIssuer("http://explicit-config.example.com");
            properties.getInfrastructures().getJwks().getConsumers().put("authorization-server", explicitConsumer);
            
            // Add explicit service-discovery configuration
            ServiceDefinitionProperties explicitService = new ServiceDefinitionProperties();
            explicitService.setBaseUrl("http://explicit-service.example.com");
            properties.getInfrastructures().getServiceDiscovery().getServices().put("authorization-server", explicitService);
            
            // Add a peer with different issuer
            Map<String, PeerProperties> peers = new HashMap<>();
            PeerProperties peer = new PeerProperties();
            peer.setEnabled(true);
            peer.setIssuer("http://localhost:8082");
            peers.put("authorization-server", peer);
            properties.setPeers(peers);
            
            // Call afterPropertiesSet
            properties.afterPropertiesSet();
            
            // Verify that explicit JWKS consumer was NOT overridden
            Map<String, JwksConsumerProperties> consumers = properties.getInfrastructures().getJwks().getConsumers();
            assertThat(consumers.get("authorization-server").getIssuer()).isEqualTo("http://explicit-config.example.com");
            
            // Verify that explicit service-discovery was NOT overridden
            Map<String, ServiceDefinitionProperties> services = properties.getInfrastructures().getServiceDiscovery().getServices();
            assertThat(services.get("authorization-server").getBaseUrl()).isEqualTo("http://explicit-service.example.com");
        }
    }
}