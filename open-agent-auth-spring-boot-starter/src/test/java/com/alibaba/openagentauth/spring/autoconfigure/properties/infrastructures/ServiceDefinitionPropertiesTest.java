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
package com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ServiceDefinitionProperties}.
 *
 * @since 2.0
 */
class ServiceDefinitionPropertiesTest {

    @Test
    void testDefaultValues() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        assertNull(properties.getBaseUrl());
        assertNotNull(properties.getEndpoints());
        // getEndpoints() returns merged defaults, so it should not be empty
        assertFalse(properties.getEndpoints().isEmpty());
        // Verify it contains the default endpoints count (17 total: 3 workload + 6 oauth2 + 3 policy + 3 binding + 2 audit)
        assertEquals(17, properties.getEndpoints().size());
    }

    @Test
    void testGetterSetter() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        String baseUrl = "http://localhost:8080";
        properties.setBaseUrl(baseUrl);
        assertEquals(baseUrl, properties.getBaseUrl());
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("authorize", "/oauth2/authorize");
        endpoints.put("token", "/oauth2/token");
        properties.setEndpoints(endpoints);
        
        // getEndpoints() returns user endpoints merged with defaults
        Map<String, String> result = properties.getEndpoints();
        assertTrue(result.size() >= 2);
        assertEquals("/oauth2/authorize", result.get("authorize"));
        assertEquals("/oauth2/token", result.get("token"));
        // Verify defaults are also present
        assertNotNull(result.get("oauth2.authorize"));
        assertNotNull(result.get("workload.issue"));
    }

    @Test
    void testBoundaryValues() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        properties.setBaseUrl("");
        assertEquals("", properties.getBaseUrl());
        
        properties.setBaseUrl(null);
        assertNull(properties.getBaseUrl());
        
        // Setting empty map means getEndpoints() returns all defaults
        properties.setEndpoints(new HashMap<>());
        assertFalse(properties.getEndpoints().isEmpty());
        assertEquals(17, properties.getEndpoints().size());
        
        // Setting null means getEndpoints() returns all defaults
        properties.setEndpoints(null);
        assertNotNull(properties.getEndpoints());
        assertFalse(properties.getEndpoints().isEmpty());
        assertEquals(17, properties.getEndpoints().size());
    }

    @Test
    void testBaseUrlFormats() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        String httpUrl = "http://localhost:8080";
        properties.setBaseUrl(httpUrl);
        assertEquals(httpUrl, properties.getBaseUrl());
        
        String httpsUrl = "https://example.com";
        properties.setBaseUrl(httpsUrl);
        assertEquals(httpsUrl, properties.getBaseUrl());
        
        String urlWithPort = "http://localhost:8080";
        properties.setBaseUrl(urlWithPort);
        assertEquals(urlWithPort, properties.getBaseUrl());
        
        String urlWithPath = "https://example.com/api";
        properties.setBaseUrl(urlWithPath);
        assertEquals(urlWithPath, properties.getBaseUrl());
    }

    @Test
    void testEndpointPaths() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("authorize", "/oauth2/authorize");
        endpoints.put("token", "/oauth2/token");
        endpoints.put("jwks", "/.well-known/jwks.json");
        endpoints.put("userinfo", "/oauth2/userinfo");
        endpoints.put("logout", "/oauth2/logout");
        properties.setEndpoints(endpoints);
        
        // getEndpoints() returns merged map, so it contains both user endpoints and defaults
        Map<String, String> result = properties.getEndpoints();
        assertTrue(result.size() >= 5);
        assertTrue(result.get("authorize").startsWith("/"));
        assertTrue(result.get("token").startsWith("/"));
        assertTrue(result.get("jwks").startsWith("/"));
        assertTrue(result.get("userinfo").startsWith("/"));
        assertTrue(result.get("logout").startsWith("/"));
    }

    @Test
    void testEndpointPathVariables() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("binding-by-id", "/api/v1/bindings/{bindingInstanceId}");
        endpoints.put("binding-by-user", "/api/v1/bindings/user/{userIdentity}");
        endpoints.put("binding-by-workload", "/api/v1/bindings/workload/{workloadIdentity}");
        properties.setEndpoints(endpoints);
        
        Map<String, String> result = properties.getEndpoints();
        assertTrue(result.get("binding-by-id").contains("{bindingInstanceId}"));
        assertTrue(result.get("binding-by-user").contains("{userIdentity}"));
        assertTrue(result.get("binding-by-workload").contains("{workloadIdentity}"));
    }

    @Test
    void testPropertyIndependence() {
        ServiceDefinitionProperties properties1 = new ServiceDefinitionProperties();
        ServiceDefinitionProperties properties2 = new ServiceDefinitionProperties();
        
        properties1.setBaseUrl("http://localhost:8081");
        assertNull(properties2.getBaseUrl());
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("test", "/test");
        properties1.setEndpoints(endpoints);
        
        // properties2 should still have all default endpoints
        assertFalse(properties2.getEndpoints().isEmpty());
        assertEquals(17, properties2.getEndpoints().size());
    }

    @Test
    void testSetEndpointsWithNull() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("test", "/test");
        properties.setEndpoints(endpoints);
        
        // getEndpoints() returns merged map with defaults
        assertTrue(properties.getEndpoints().size() >= 1);
        
        properties.setEndpoints(null);
        
        // When null, getEndpoints() returns all defaults
        assertNotNull(properties.getEndpoints());
        assertEquals(17, properties.getEndpoints().size());
    }

    @Test
    void testMultipleEndpoints() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("authorize", "/oauth2/authorize");
        endpoints.put("token", "/oauth2/token");
        endpoints.put("userinfo", "/oauth2/userinfo");
        endpoints.put("jwks", "/.well-known/jwks.json");
        endpoints.put("revoke", "/oauth2/revoke");
        endpoints.put("introspect", "/oauth2/introspect");
        properties.setEndpoints(endpoints);
        
        // getEndpoints() returns merged map with defaults
        Map<String, String> result = properties.getEndpoints();
        assertTrue(result.size() >= 6);
        // Verify user-provided endpoints are present
        assertEquals("/oauth2/authorize", result.get("authorize"));
        assertEquals("/oauth2/token", result.get("token"));
        assertEquals("/oauth2/userinfo", result.get("userinfo"));
        assertEquals("/.well-known/jwks.json", result.get("jwks"));
        assertEquals("/oauth2/revoke", result.get("revoke"));
        assertEquals("/oauth2/introspect", result.get("introspect"));
    }

    @Test
    void testNotNullConstraints() {
        ServiceDefinitionProperties properties = new ServiceDefinitionProperties();
        
        // baseUrl can be null by default
        // Test that we can set it to a non-null value
        properties.setBaseUrl("http://localhost:8080");
        assertNotNull(properties.getBaseUrl());
        // getEndpoints() always returns a non-null map with defaults
        assertNotNull(properties.getEndpoints());
        assertFalse(properties.getEndpoints().isEmpty());
    }
}