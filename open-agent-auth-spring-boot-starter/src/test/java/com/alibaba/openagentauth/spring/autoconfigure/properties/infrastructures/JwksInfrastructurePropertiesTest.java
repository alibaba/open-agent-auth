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
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JwksInfrastructureProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(JwksInfrastructureProperties.class)
class JwksInfrastructurePropertiesTest {

    @Test
    void testDefaultValues() {
        JwksInfrastructureProperties properties = new JwksInfrastructureProperties();
        
        assertNotNull(properties.getProvider());
        assertNotNull(properties.getConsumers());
        assertTrue(properties.getConsumers().isEmpty());
        
        assertTrue(properties.getProvider().isEnabled());
        assertEquals("/.well-known/jwks.json", properties.getProvider().getPath());
        assertEquals(300, properties.getProvider().getCacheDurationSeconds());
        assertTrue(properties.getProvider().isCacheHeadersEnabled());
    }

    @Test
    void testGetterSetter() {
        JwksInfrastructureProperties properties = new JwksInfrastructureProperties();
        
        JwksProviderProperties provider = new JwksProviderProperties();
        provider.setEnabled(false);
        properties.setProvider(provider);
        assertFalse(properties.getProvider().isEnabled());
        
        Map<String, JwksConsumerProperties> consumers = new HashMap<>();
        JwksConsumerProperties consumer = new JwksConsumerProperties();
        consumer.setJwksEndpoint("https://example.com/jwks.json");
        consumer.setIssuer("https://example.com");
        consumers.put("external-idp", consumer);
        properties.setConsumers(consumers);
        
        assertEquals(1, properties.getConsumers().size());
        assertEquals("https://example.com/jwks.json", properties.getConsumers().get("external-idp").getJwksEndpoint());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = JwksInfrastructureProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.infrastructures.jwks", annotation.prefix());
    }

    @Test
    void testNestedProperties() {
        JwksInfrastructureProperties properties = new JwksInfrastructureProperties();
        
        assertNotNull(properties.getProvider());
        assertNotNull(properties.getConsumers());
    }

    @Test
    void testMultipleConsumers() {
        JwksInfrastructureProperties properties = new JwksInfrastructureProperties();
        
        Map<String, JwksConsumerProperties> consumers = new HashMap<>();
        
        JwksConsumerProperties consumer1 = new JwksConsumerProperties();
        consumer1.setJwksEndpoint("https://idp1.com/jwks.json");
        consumer1.setIssuer("https://idp1.com");
        consumers.put("idp1", consumer1);
        
        JwksConsumerProperties consumer2 = new JwksConsumerProperties();
        consumer2.setJwksEndpoint("https://idp2.com/jwks.json");
        consumer2.setIssuer("https://idp2.com");
        consumers.put("idp2", consumer2);
        
        properties.setConsumers(consumers);
        
        assertEquals(2, properties.getConsumers().size());
        assertEquals("https://idp1.com/jwks.json", properties.getConsumers().get("idp1").getJwksEndpoint());
        assertEquals("https://idp2.com/jwks.json", properties.getConsumers().get("idp2").getJwksEndpoint());
    }

    @Test
    void testBoundaryValues() {
        JwksInfrastructureProperties properties = new JwksInfrastructureProperties();
        
        properties.getProvider().setEnabled(true);
        assertTrue(properties.getProvider().isEnabled());
        properties.getProvider().setEnabled(false);
        assertFalse(properties.getProvider().isEnabled());
        
        properties.getProvider().setCacheDurationSeconds(0);
        assertEquals(0, properties.getProvider().getCacheDurationSeconds());
        
        properties.getProvider().setCacheDurationSeconds(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, properties.getProvider().getCacheDurationSeconds());
    }

    @Test
    void testPropertyIndependence() {
        JwksInfrastructureProperties properties1 = new JwksInfrastructureProperties();
        JwksInfrastructureProperties properties2 = new JwksInfrastructureProperties();
        
        properties1.getProvider().setEnabled(false);
        assertTrue(properties2.getProvider().isEnabled());
        
        Map<String, JwksConsumerProperties> consumers = new HashMap<>();
        consumers.put("test", new JwksConsumerProperties());
        properties1.setConsumers(consumers);
        
        assertTrue(properties2.getConsumers().isEmpty());
    }

    @Test
    void testSetConsumersWithNull() {
        JwksInfrastructureProperties properties = new JwksInfrastructureProperties();
        
        Map<String, JwksConsumerProperties> consumers = new HashMap<>();
        consumers.put("test", new JwksConsumerProperties());
        properties.setConsumers(consumers);
        
        assertEquals(1, properties.getConsumers().size());
        
        properties.setConsumers(null);
        
        assertNull(properties.getConsumers());
    }
}
