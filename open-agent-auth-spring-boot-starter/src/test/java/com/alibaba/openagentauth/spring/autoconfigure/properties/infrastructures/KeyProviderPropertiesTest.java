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
 * Unit tests for {@link KeyProviderProperties}.
 *
 * @since 2.0
 */
class KeyProviderPropertiesTest {

    @Test
    void testDefaultValues() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        assertNull(properties.getType());
        assertNotNull(properties.getConfig());
        assertTrue(properties.getConfig().isEmpty());
    }

    @Test
    void testGetterSetter() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        String type = "in-memory";
        properties.setType(type);
        assertEquals(type, properties.getType());
        
        Map<String, String> config = new HashMap<>();
         config.put("custom-key", "custom-value");
        properties.setConfig(config);
        
        assertEquals(1, properties.getConfig().size());
        assertEquals("custom-value", properties.getConfig().get("custom-key"));
    }

    @Test
    void testBoundaryValues() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        properties.setType("");
        assertEquals("", properties.getType());
        
        properties.setType(null);
        assertNull(properties.getType());
        
        properties.setConfig(new HashMap<>());
        assertTrue(properties.getConfig().isEmpty());
        
        properties.setConfig(null);
        assertNull(properties.getConfig());
    }

    @Test
    void testTypeValues() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        properties.setType("in-memory");
        assertEquals("in-memory", properties.getType());
    }

    @Test
    void testConfigForInMemoryProvider() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        properties.setType("in-memory");
        Map<String, String> config = new HashMap<>();
        properties.setConfig(config);
        
        assertTrue(properties.getConfig().isEmpty());
    }

    @Test
    void testPropertyIndependence() {
        KeyProviderProperties properties1 = new KeyProviderProperties();
        KeyProviderProperties properties2 = new KeyProviderProperties();
        
        properties1.setType("in-memory");
        assertNull(properties2.getType());
        
        Map<String, String> config = new HashMap<>();
        config.put("key", "value");
        properties1.setConfig(config);
        
        assertTrue(properties2.getConfig().isEmpty());
    }

    @Test
    void testConfigModifications() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        Map<String, String> config = new HashMap<>();
        properties.setConfig(config);
        
        properties.getConfig().put("key1", "value1");
        assertEquals(1, properties.getConfig().size());
        
        properties.getConfig().put("key2", "value2");
        assertEquals(2, properties.getConfig().size());
        
        properties.getConfig().remove("key1");
        assertEquals(1, properties.getConfig().size());
    }

    @Test
    void testNotNullConstraints() {
        KeyProviderProperties properties = new KeyProviderProperties();
        
        assertNotNull(properties.getConfig());
    }
}
