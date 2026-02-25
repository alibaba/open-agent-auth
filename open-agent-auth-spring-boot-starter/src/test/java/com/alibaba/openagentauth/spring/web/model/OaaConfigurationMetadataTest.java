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
package com.alibaba.openagentauth.spring.web.model;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit tests for {@link OaaConfigurationMetadata}.
 *
 * @since 2.1
 */
class OaaConfigurationMetadataTest {

    @Test
    void testCurrentProtocolVersion() {
        assertEquals("1.0", OaaConfigurationMetadata.CURRENT_PROTOCOL_VERSION);
    }

    @Test
    void testDefaultValues() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        assertNull(metadata.getIssuer());
        assertNull(metadata.getRoles());
        assertNull(metadata.getTrustDomain());
        assertEquals("1.0", metadata.getProtocolVersion());
        assertNull(metadata.getJwksUri());
        assertNull(metadata.getSigningAlgorithmsSupported());
        assertNull(metadata.getCapabilities());
        assertNull(metadata.getEndpoints());
        assertNull(metadata.getPeersRequired());
    }

    @Test
    void testIssuerGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        metadata.setIssuer("http://localhost:8080");
        assertEquals("http://localhost:8080", metadata.getIssuer());
    }

    @Test
    void testRolesGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        List<String> roles = List.of("agent", "agent-idp");
        metadata.setRoles(roles);
        assertEquals(roles, metadata.getRoles());
    }

    @Test
    void testTrustDomainGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        metadata.setTrustDomain("wimse://default.trust.domain");
        assertEquals("wimse://default.trust.domain", metadata.getTrustDomain());
    }

    @Test
    void testProtocolVersionGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        metadata.setProtocolVersion("2.0");
        assertEquals("2.0", metadata.getProtocolVersion());
    }

    @Test
    void testJwksUriGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        metadata.setJwksUri("http://localhost:8080/.well-known/jwks.json");
        assertEquals("http://localhost:8080/.well-known/jwks.json", metadata.getJwksUri());
    }

    @Test
    void testSigningAlgorithmsSupportedGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        List<String> algorithms = List.of("RS256", "ES256");
        metadata.setSigningAlgorithmsSupported(algorithms);
        assertEquals(algorithms, metadata.getSigningAlgorithmsSupported());
    }

    @Test
    void testCapabilitiesGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("oauth2", true);
        capabilities.put("workload-identity", true);
        metadata.setCapabilities(capabilities);
        assertEquals(capabilities, metadata.getCapabilities());
    }

    @Test
    void testEndpointsGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("oauth2.authorize", "http://localhost:8080/oauth2/authorize");
        endpoints.put("oauth2.token", "http://localhost:8080/oauth2/token");
        metadata.setEndpoints(endpoints);
        assertEquals(endpoints, metadata.getEndpoints());
    }

    @Test
    void testPeersRequiredGetterSetter() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        List<String> peers = List.of("agent-idp", "authorization-server");
        metadata.setPeersRequired(peers);
        assertEquals(peers, metadata.getPeersRequired());
    }

    @Test
    void testAllFieldsPopulated() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        metadata.setIssuer("http://localhost:8080");
        metadata.setRoles(List.of("agent", "agent-idp"));
        metadata.setTrustDomain("wimse://default.trust.domain");
        metadata.setProtocolVersion("1.0");
        metadata.setJwksUri("http://localhost:8080/.well-known/jwks.json");
        metadata.setSigningAlgorithmsSupported(List.of("RS256", "ES256"));
        
        Map<String, Object> capabilities = new HashMap<>();
        capabilities.put("oauth2", true);
        metadata.setCapabilities(capabilities);
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("oauth2.authorize", "http://localhost:8080/oauth2/authorize");
        metadata.setEndpoints(endpoints);
        
        metadata.setPeersRequired(List.of("agent-idp"));
        
        assertNotNull(metadata.getIssuer());
        assertNotNull(metadata.getRoles());
        assertNotNull(metadata.getTrustDomain());
        assertNotNull(metadata.getProtocolVersion());
        assertNotNull(metadata.getJwksUri());
        assertNotNull(metadata.getSigningAlgorithmsSupported());
        assertNotNull(metadata.getCapabilities());
        assertNotNull(metadata.getEndpoints());
        assertNotNull(metadata.getPeersRequired());
    }

    @Test
    void testProtocolVersionDefault() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        assertEquals("1.0", metadata.getProtocolVersion());
    }

    @Test
    void testEmptyCollections() {
        OaaConfigurationMetadata metadata = new OaaConfigurationMetadata();
        
        metadata.setRoles(List.of());
        assertNotNull(metadata.getRoles());
        assertEquals(0, metadata.getRoles().size());
        
        metadata.setSigningAlgorithmsSupported(List.of());
        assertNotNull(metadata.getSigningAlgorithmsSupported());
        assertEquals(0, metadata.getSigningAlgorithmsSupported().size());
        
        metadata.setCapabilities(new HashMap<>());
        assertNotNull(metadata.getCapabilities());
        assertEquals(0, metadata.getCapabilities().size());
        
        metadata.setEndpoints(new HashMap<>());
        assertNotNull(metadata.getEndpoints());
        assertEquals(0, metadata.getEndpoints().size());
        
        metadata.setPeersRequired(List.of());
        assertNotNull(metadata.getPeersRequired());
        assertEquals(0, metadata.getPeersRequired().size());
    }
}
