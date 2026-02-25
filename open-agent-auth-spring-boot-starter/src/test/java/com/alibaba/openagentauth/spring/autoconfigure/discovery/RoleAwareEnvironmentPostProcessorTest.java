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
package com.alibaba.openagentauth.spring.autoconfigure.discovery;

import com.alibaba.openagentauth.spring.autoconfigure.properties.InfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.PeerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyProviderProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDefinitionProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link RoleAwareEnvironmentPostProcessor}.
 *
 * @since 2.1
 */
class RoleAwareEnvironmentPostProcessorTest {

    private OpenAgentAuthProperties properties;

    @BeforeEach
    void setUp() {
        properties = new OpenAgentAuthProperties();
    }

    @Test
    void noRolesConfigured_shouldNotInferAnything() {
        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        assertEquals(0, properties.getInfrastructures().getKeyManagement().getKeys().size());
        assertEquals(0, properties.getInfrastructures().getJwks().getConsumers().size());
        assertEquals(0, properties.getInfrastructures().getServiceDiscovery().getServices().size());
    }

    @Test
    void noRolesEnabled_shouldNotInferAnything() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(false);
        roles.put("agent", role);
        properties.setRoles(roles);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        assertEquals(0, properties.getInfrastructures().getKeyManagement().getKeys().size());
    }

    @Test
    void agentUserIdpRole_shouldInferIdTokenSigningKey() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8083");
        roles.put("agent-user-idp", role);
        properties.setRoles(roles);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        Map<String, KeyDefinitionProperties> keys = properties.getInfrastructures().getKeyManagement().getKeys();
        assertEquals(1, keys.size());

        KeyDefinitionProperties key = keys.get("id-token-signing");
        assertNotNull(key);
        assertEquals("id-token-signing-key", key.getKeyId());
        assertEquals("ES256", key.getAlgorithm());
        assertEquals("local", key.getProvider());
    }

    @Test
    void agentIdpRoleWithPeer_shouldExpandPeers() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8082");
        roles.put("agent-idp", role);
        properties.setRoles(roles);

        Map<String, PeerProperties> peers = new HashMap<>();
        PeerProperties peer = new PeerProperties();
        peer.setEnabled(true);
        peer.setIssuer("http://localhost:8083");
        peers.put("agent-user-idp", peer);
        properties.setPeers(peers);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        Map<String, JwksConsumerProperties> consumers = properties.getInfrastructures().getJwks().getConsumers();
        assertEquals(1, consumers.size());

        JwksConsumerProperties consumer = consumers.get("agent-user-idp");
        assertNotNull(consumer);
        assertTrue(consumer.isEnabled());
        assertEquals("http://localhost:8083", consumer.getIssuer());

        Map<String, ServiceDefinitionProperties> services = properties.getInfrastructures().getServiceDiscovery().getServices();
        assertEquals(1, services.size());

        ServiceDefinitionProperties service = services.get("agent-user-idp");
        assertNotNull(service);
        assertEquals("http://localhost:8083", service.getBaseUrl());
    }

    @Test
    void resourceServerRole_shouldInferVerificationKeys() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8086");
        roles.put("resource-server", role);
        properties.setRoles(roles);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        Map<String, KeyDefinitionProperties> keys = properties.getInfrastructures().getKeyManagement().getKeys();
        assertEquals(2, keys.size());

        KeyDefinitionProperties witKey = keys.get("wit-verification");
        assertNotNull(witKey);
        assertEquals("wit-signing-key", witKey.getKeyId());
        assertEquals("ES256", witKey.getAlgorithm());
        assertEquals("agent-idp", witKey.getJwksConsumer());

        KeyDefinitionProperties aoatKey = keys.get("aoat-verification");
        assertNotNull(aoatKey);
        assertEquals("aoat-signing-key", aoatKey.getKeyId());
        assertEquals("RS256", aoatKey.getAlgorithm());
        assertEquals("authorization-server", aoatKey.getJwksConsumer());
    }

    @Test
    void explicitConfig_shouldNotBeOverridden() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8082");
        roles.put("agent-idp", role);
        properties.setRoles(roles);

        Map<String, PeerProperties> peers = new HashMap<>();
        PeerProperties peer = new PeerProperties();
        peer.setEnabled(true);
        peer.setIssuer("http://localhost:8083");
        peers.put("agent-user-idp", peer);
        properties.setPeers(peers);

        InfrastructureProperties infra = properties.getInfrastructures();

        JwksConsumerProperties existingConsumer = new JwksConsumerProperties();
        existingConsumer.setEnabled(false);
        existingConsumer.setIssuer("http://custom.issuer.com");
        infra.getJwks().getConsumers().put("agent-user-idp", existingConsumer);

        ServiceDefinitionProperties existingService = new ServiceDefinitionProperties();
        existingService.setBaseUrl("http://custom.baseurl.com");
        infra.getServiceDiscovery().getServices().put("agent-user-idp", existingService);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        JwksConsumerProperties consumer = infra.getJwks().getConsumers().get("agent-user-idp");
        assertNotNull(consumer);
        assertEquals("http://custom.issuer.com", consumer.getIssuer());

        ServiceDefinitionProperties service = infra.getServiceDiscovery().getServices().get("agent-user-idp");
        assertNotNull(service);
        assertEquals("http://custom.baseurl.com", service.getBaseUrl());
    }

    @Test
    void defaultKeyProvider_shouldBeCreated() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8082");
        roles.put("agent-idp", role);
        properties.setRoles(roles);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        Map<String, KeyProviderProperties> providers = properties.getInfrastructures().getKeyManagement().getProviders();
        assertEquals(1, providers.size());

        KeyProviderProperties provider = providers.get("local");
        assertNotNull(provider);
        assertEquals("in-memory", provider.getType());
    }

    @Test
    void jwksProvider_shouldBeAutoEnabled() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8082");
        roles.put("agent-idp", role);
        properties.setRoles(roles);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        assertTrue(properties.getInfrastructures().getJwks().getProvider().isEnabled());
    }

    @Test
    void disabledPeer_shouldNotBeExpanded() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8082");
        roles.put("agent-idp", role);
        properties.setRoles(roles);

        Map<String, PeerProperties> peers = new HashMap<>();
        PeerProperties peer = new PeerProperties();
        peer.setEnabled(false);
        peer.setIssuer("http://localhost:8083");
        peers.put("agent-user-idp", peer);
        properties.setPeers(peers);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        assertEquals(0, properties.getInfrastructures().getJwks().getConsumers().size());
        assertEquals(0, properties.getInfrastructures().getServiceDiscovery().getServices().size());
    }

    @Test
    void peerWithNullIssuer_shouldNotBeExpanded() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8082");
        roles.put("agent-idp", role);
        properties.setRoles(roles);

        Map<String, PeerProperties> peers = new HashMap<>();
        PeerProperties peer = new PeerProperties();
        peer.setEnabled(true);
        peer.setIssuer(null);
        peers.put("agent-user-idp", peer);
        properties.setPeers(peers);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        assertEquals(0, properties.getInfrastructures().getJwks().getConsumers().size());
        assertEquals(0, properties.getInfrastructures().getServiceDiscovery().getServices().size());
    }

    @Test
    void agentRole_shouldInferMultipleKeys() {
        Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8081");
        roles.put("agent", role);
        properties.setRoles(roles);

        RoleAwareEnvironmentPostProcessor processor = new RoleAwareEnvironmentPostProcessor(properties);
        processor.processConfiguration();

        Map<String, KeyDefinitionProperties> keys = properties.getInfrastructures().getKeyManagement().getKeys();
        assertEquals(5, keys.size());

        assertNotNull(keys.get("par-jwt-signing"));
        assertNotNull(keys.get("vc-signing"));
        assertNotNull(keys.get("wit-verification"));
        assertNotNull(keys.get("id-token-verification"));
        assertNotNull(keys.get("jwe-encryption"));
    }
}
