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

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link KeyManagementProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(OpenAgentAuthProperties.class)
class KeyManagementPropertiesTest {

    @Autowired
    private OpenAgentAuthProperties openAgentAuthProperties;

    @Test
    void testDefaultValues() {
        KeyManagementProperties properties = new KeyManagementProperties();
        
        assertNotNull(properties.getProviders());
        assertNotNull(properties.getKeys());
        assertTrue(properties.getProviders().isEmpty());
        assertTrue(properties.getKeys().isEmpty());
    }

    @Test
    void testGetterSetter() {
        KeyManagementProperties properties = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        
        Map<String, KeyProviderProperties> providers = new HashMap<>();
        KeyProviderProperties provider = new KeyProviderProperties();
        provider.setType("in-memory");
        providers.put("local", provider);
        properties.setProviders(providers);
        
        assertEquals(1, properties.getProviders().size());
        assertEquals("in-memory", properties.getProviders().get("local").getType());
        
        Map<String, KeyDefinitionProperties> keys = new HashMap<>();
        KeyDefinitionProperties key = new KeyDefinitionProperties();
        key.setKeyId("signing-key-001");
        key.setAlgorithm("RS256");
        keys.put("signing-key", key);
        properties.setKeys(keys);
        
        assertEquals(1, properties.getKeys().size());
        assertEquals("signing-key-001", properties.getKeys().get("signing-key").getKeyId());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = KeyManagementProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNull(annotation, "KeyManagementProperties should not have @ConfigurationProperties annotation as it is nested within OpenAgentAuthProperties");
    }

    @Test
    void testNestedProperties() {
        KeyManagementProperties properties = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        
        assertNotNull(properties.getProviders());
        assertNotNull(properties.getKeys());
    }

    @Test
    void testMultipleProviders() {
        KeyManagementProperties properties = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        
        Map<String, KeyProviderProperties> providers = new HashMap<>();
        
        KeyProviderProperties provider1 = new KeyProviderProperties();
        provider1.setType("in-memory");
        providers.put("local", provider1);
        
        KeyProviderProperties provider2 = new KeyProviderProperties();
        provider2.setType("in-memory");
        providers.put("backup", provider2);
        
        properties.setProviders(providers);
        
        assertEquals(2, properties.getProviders().size());
        assertEquals("in-memory", properties.getProviders().get("local").getType());
        assertEquals("in-memory", properties.getProviders().get("backup").getType());
    }

    @Test
    void testMultipleKeys() {
        KeyManagementProperties properties = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        
        Map<String, KeyDefinitionProperties> keys = new HashMap<>();
        
        KeyDefinitionProperties key1 = new KeyDefinitionProperties();
        key1.setKeyId("signing-key-001");
        key1.setAlgorithm("RS256");
        key1.setProvider("local");
        keys.put("signing-key", key1);
        
        KeyDefinitionProperties key2 = new KeyDefinitionProperties();
        key2.setKeyId("encryption-key-001");
        key2.setAlgorithm("RSA-OAEP-256");
        key2.setProvider("local");
        keys.put("encryption-key", key2);
        
        properties.setKeys(keys);
        
        assertEquals(2, properties.getKeys().size());
        assertEquals("signing-key-001", properties.getKeys().get("signing-key").getKeyId());
        assertEquals("encryption-key-001", properties.getKeys().get("encryption-key").getKeyId());
    }

    @Test
    void testBoundaryValues() {
        KeyManagementProperties properties = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        
        properties.setProviders(new HashMap<>());
        assertTrue(properties.getProviders().isEmpty());
        
        properties.setKeys(new HashMap<>());
        assertTrue(properties.getKeys().isEmpty());
        
        properties.setProviders(null);
        assertNull(properties.getProviders());
        
        properties.setKeys(null);
        assertNull(properties.getKeys());
    }

    @Test
    void testPropertyIndependence() {
        KeyManagementProperties properties1 = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        KeyManagementProperties properties2 = new KeyManagementProperties();
        
        Map<String, KeyProviderProperties> providers = new HashMap<>();
        providers.put("test", new KeyProviderProperties());
        properties1.setProviders(providers);
        
        assertTrue(properties2.getProviders().isEmpty());
        
        Map<String, KeyDefinitionProperties> keys = new HashMap<>();
        keys.put("test", new KeyDefinitionProperties());
        properties1.setKeys(keys);
        
        assertTrue(properties2.getKeys().isEmpty());
    }

    @Test
    void testKeyProviderRelationship() {
        KeyManagementProperties properties = openAgentAuthProperties.getInfrastructures().getKeyManagement();
        
        Map<String, KeyProviderProperties> providers = new HashMap<>();
        KeyProviderProperties provider = new KeyProviderProperties();
        provider.setType("in-memory");
        providers.put("local", provider);
        properties.setProviders(providers);
        
        Map<String, KeyDefinitionProperties> keys = new HashMap<>();
        KeyDefinitionProperties key = new KeyDefinitionProperties();
        key.setKeyId("signing-key-001");
        key.setAlgorithm("RS256");
        key.setProvider("local");
        keys.put("signing-key", key);
        properties.setKeys(keys);
        
        assertEquals("local", properties.getKeys().get("signing-key").getProvider());
        assertNotNull(properties.getProviders().get("local"));
    }
}
