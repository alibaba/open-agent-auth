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
 * Unit tests for {@link ServiceDiscoveryProperties}.
 *
 * @since 2.0
 */
class ServiceDiscoveryPropertiesTest {

    @Test
    void testDefaultValues() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        assertTrue(properties.isEnabled());
        assertEquals("static", properties.getType());
        assertNotNull(properties.getServices());
        assertTrue(properties.getServices().isEmpty());
    }

    @Test
    void testGetterSetter() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.setType("consul");
        assertEquals("consul", properties.getType());
        
        properties.setType("eureka");
        assertEquals("eureka", properties.getType());
        
        Map<String, ServiceDefinitionProperties> services = new HashMap<>();
        ServiceDefinitionProperties service = new ServiceDefinitionProperties();
        service.setBaseUrl("http://localhost:8080");
        services.put("authorization-server", service);
        properties.setServices(services);
        
        assertEquals(1, properties.getServices().size());
        assertEquals("http://localhost:8080", properties.getServices().get("authorization-server").getBaseUrl());
    }

    @Test
    void testNestedProperties() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        assertNotNull(properties.getServices());
    }

    @Test
    void testMultipleServices() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        Map<String, ServiceDefinitionProperties> services = new HashMap<>();
        
        ServiceDefinitionProperties service1 = new ServiceDefinitionProperties();
        service1.setBaseUrl("http://localhost:8085");
        Map<String, String> endpoints1 = new HashMap<>();
        endpoints1.put("authorize", "/oauth2/authorize");
        endpoints1.put("token", "/oauth2/token");
        service1.setEndpoints(endpoints1);
        services.put("authorization-server", service1);
        
        ServiceDefinitionProperties service2 = new ServiceDefinitionProperties();
        service2.setBaseUrl("http://localhost:8081");
        Map<String, String> endpoints2 = new HashMap<>();
        endpoints2.put("policies", "/api/v1/policies");
        endpoints2.put("bindings", "/api/v1/bindings");
        service2.setEndpoints(endpoints2);
        services.put("policy-server", service2);
        
        properties.setServices(services);
        
        assertEquals(2, properties.getServices().size());
        assertEquals("http://localhost:8085", properties.getServices().get("authorization-server").getBaseUrl());
        assertEquals("http://localhost:8081", properties.getServices().get("policy-server").getBaseUrl());
    }

    @Test
    void testBoundaryValues() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.setType("");
        assertEquals("", properties.getType());
        
        properties.setType(null);
        assertNull(properties.getType());
        
        properties.setServices(new HashMap<>());
        assertTrue(properties.getServices().isEmpty());
        
        properties.setServices(null);
        assertNull(properties.getServices());
    }

    @Test
    void testDiscoveryTypes() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        properties.setType("static");
        assertEquals("static", properties.getType());
        
        properties.setType("consul");
        assertEquals("consul", properties.getType());
        
        properties.setType("eureka");
        assertEquals("eureka", properties.getType());
    }

    @Test
    void testPropertyIndependence() {
        ServiceDiscoveryProperties properties1 = new ServiceDiscoveryProperties();
        ServiceDiscoveryProperties properties2 = new ServiceDiscoveryProperties();
        
        properties1.setEnabled(false);
        assertTrue(properties2.isEnabled());
        
        properties1.setType("consul");
        assertEquals("static", properties2.getType());
        
        Map<String, ServiceDefinitionProperties> services = new HashMap<>();
        services.put("test", new ServiceDefinitionProperties());
        properties1.setServices(services);
        
        assertTrue(properties2.getServices().isEmpty());
    }

    @Test
    void testSetServicesWithNull() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        Map<String, ServiceDefinitionProperties> services = new HashMap<>();
        services.put("test", new ServiceDefinitionProperties());
        properties.setServices(services);
        
        assertEquals(1, properties.getServices().size());
        
        properties.setServices(null);
        
        assertNull(properties.getServices());
    }

    @Test
    void testNotNullConstraints() {
        ServiceDiscoveryProperties properties = new ServiceDiscoveryProperties();
        
        assertNotNull(properties.isEnabled());
        assertNotNull(properties.getType());
        assertNotNull(properties.getServices());
    }
}
