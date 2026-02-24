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
package com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities;

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link AuditProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(OpenAgentAuthProperties.class)
class AuditPropertiesTest {

    @Autowired
    private OpenAgentAuthProperties openAgentAuthProperties;

    @Test
    void testDefaultValues() {
        AuditProperties properties = new AuditProperties();
        
        assertFalse(properties.isEnabled());
        assertEquals("logging", properties.getProvider());
        assertNotNull(properties.getEndpoints());
        
        assertEquals("/api/v1/audit/events/{eventId}", properties.getEndpoints().getEvent().getGet());
        assertEquals("/api/v1/audit/events", properties.getEndpoints().getEvent().getList());
    }

    @Test
    void testGetterSetter() {
        AuditProperties properties = openAgentAuthProperties.getCapabilities().getAudit();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        properties.setProvider("database");
        assertEquals("database", properties.getProvider());
        
        AuditProperties.AuditEndpointsProperties endpoints = new AuditProperties.AuditEndpointsProperties();
        endpoints.setEvent(new AuditProperties.AuditEndpointsProperties.EventEndpointPaths());
        endpoints.getEvent().setGet("/custom/events/{id}");
        properties.setEndpoints(endpoints);
        assertEquals("/custom/events/{id}", properties.getEndpoints().getEvent().getGet());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = AuditProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNull(annotation, "AuditProperties should not have @ConfigurationProperties annotation as it is nested within parent properties");
    }

    @Test
    void testEndpointsProperties() {
        AuditProperties.AuditEndpointsProperties endpoints = new AuditProperties.AuditEndpointsProperties();
        AuditProperties.AuditEndpointsProperties.EventEndpointPaths event = endpoints.getEvent();
        
        event.setGet("/custom/events/{eventId}");
        assertEquals("/custom/events/{eventId}", event.getGet());
        
        event.setList("/custom/events");
        assertEquals("/custom/events", event.getList());
    }

    @Test
    void testBoundaryValues() {
        AuditProperties properties = openAgentAuthProperties.getCapabilities().getAudit();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.setProvider("");
        assertEquals("", properties.getProvider());
        
        properties.setProvider("elk");
        assertEquals("elk", properties.getProvider());
        
        properties.getEndpoints().getEvent().setGet("");
        assertEquals("", properties.getEndpoints().getEvent().getGet());
        
        properties.getEndpoints().getEvent().setList("/api/v1/custom/events");
        assertEquals("/api/v1/custom/events", properties.getEndpoints().getEvent().getList());
    }

    @Test
    void testPropertyIndependence() {
        AuditProperties properties1 = openAgentAuthProperties.getCapabilities().getAudit();
        AuditProperties properties2 = new AuditProperties();
        
        properties1.setEnabled(true);
        assertFalse(properties2.isEnabled());
        
        properties1.setProvider("database");
        assertEquals("logging", properties2.getProvider());
        
        properties1.getEndpoints().getEvent().setGet("/custom");
        assertEquals("/api/v1/audit/events/{eventId}", properties2.getEndpoints().getEvent().getGet());
    }

    @Test
    void testEndpointPaths() {
        AuditProperties.AuditEndpointsProperties endpoints = new AuditProperties.AuditEndpointsProperties();
        AuditProperties.AuditEndpointsProperties.EventEndpointPaths event = endpoints.getEvent();
        
        event.setGet("/api/v1/audit/events/{eventId}");
        assertTrue(event.getGet().startsWith("/"));
        
        event.setList("/api/v1/audit/events");
        assertTrue(event.getList().startsWith("/"));
    }

    @Test
    void testProviderValues() {
        AuditProperties properties = openAgentAuthProperties.getCapabilities().getAudit();
        
        properties.setProvider("logging");
        assertEquals("logging", properties.getProvider());
        
        properties.setProvider("database");
        assertEquals("database", properties.getProvider());
        
        properties.setProvider("elk");
        assertEquals("elk", properties.getProvider());
    }
}
