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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link KeyDefinitionProperties}.
 *
 * @since 2.0
 */
class KeyDefinitionPropertiesTest {

    @Test
    void testDefaultValues() {
        KeyDefinitionProperties properties = new KeyDefinitionProperties();
        
        assertNull(properties.getKeyId());
        assertNull(properties.getAlgorithm());
        assertEquals("local", properties.getProvider());
        assertNull(properties.getJwksConsumer());
    }

    @Test
    void testGetterSetter() {
        KeyDefinitionProperties properties = new KeyDefinitionProperties();
        
        String keyId = "signing-key-001";
        properties.setKeyId(keyId);
        assertEquals(keyId, properties.getKeyId());
        
        String algorithm = "RS256";
        properties.setAlgorithm(algorithm);
        assertEquals(algorithm, properties.getAlgorithm());
        
        String provider = "local";
        properties.setProvider(provider);
        assertEquals(provider, properties.getProvider());
        
        String jwksConsumer = "external-idp";
        properties.setJwksConsumer(jwksConsumer);
        assertEquals(jwksConsumer, properties.getJwksConsumer());
    }

    @Test
    void testBoundaryValues() {
        KeyDefinitionProperties properties = new KeyDefinitionProperties();
        
        properties.setKeyId("");
        assertEquals("", properties.getKeyId());
        
        properties.setAlgorithm("");
        assertEquals("", properties.getAlgorithm());
        
        properties.setProvider("");
        assertEquals("", properties.getProvider());
        
        properties.setJwksConsumer("");
        assertEquals("", properties.getJwksConsumer());
        
        properties.setKeyId(null);
        assertNull(properties.getKeyId());
        
        properties.setAlgorithm(null);
        assertNull(properties.getAlgorithm());
        
        properties.setProvider(null);
        assertNull(properties.getProvider());
        
        properties.setJwksConsumer(null);
        assertNull(properties.getJwksConsumer());
    }

    @Test
    void testAlgorithmValues() {
        KeyDefinitionProperties properties = new KeyDefinitionProperties();
        
        properties.setAlgorithm("RS256");
        assertEquals("RS256", properties.getAlgorithm());
        
        properties.setAlgorithm("RS384");
        assertEquals("RS384", properties.getAlgorithm());
        
        properties.setAlgorithm("RS512");
        assertEquals("RS512", properties.getAlgorithm());
        
        properties.setAlgorithm("ES256");
        assertEquals("ES256", properties.getAlgorithm());
        
        properties.setAlgorithm("ES384");
        assertEquals("ES384", properties.getAlgorithm());
        
        properties.setAlgorithm("ES512");
        assertEquals("ES512", properties.getAlgorithm());
        
        properties.setAlgorithm("PS256");
        assertEquals("PS256", properties.getAlgorithm());
        
        properties.setAlgorithm("PS384");
        assertEquals("PS384", properties.getAlgorithm());
        
        properties.setAlgorithm("PS512");
        assertEquals("PS512", properties.getAlgorithm());
    }

    @Test
    void testProviderValues() {
        KeyDefinitionProperties properties = new KeyDefinitionProperties();
        
        properties.setProvider("local");
        assertEquals("local", properties.getProvider());
    }

    @Test
    void testPropertyIndependence() {
        KeyDefinitionProperties properties1 = new KeyDefinitionProperties();
        KeyDefinitionProperties properties2 = new KeyDefinitionProperties();
        
        properties1.setKeyId("key-1");
        assertNull(properties2.getKeyId());
        
        properties1.setAlgorithm("RS256");
        assertNull(properties2.getAlgorithm());
        
        properties1.setProvider("local");
        assertEquals("local", properties2.getProvider());
        
        properties1.setJwksConsumer("external");
        assertNull(properties2.getJwksConsumer());
    }

    @Test
    void testKeyIdFormat() {
        KeyDefinitionProperties properties = new KeyDefinitionProperties();
        
        String simpleKeyId = "signing-key";
        properties.setKeyId(simpleKeyId);
        assertEquals(simpleKeyId, properties.getKeyId());
        
        String complexKeyId = "wit-signing-key-001";
        properties.setKeyId(complexKeyId);
        assertEquals(complexKeyId, properties.getKeyId());
        
        String uuidKeyId = "550e8400-e29b-41d4-a716-446655440000";
        properties.setKeyId(uuidKeyId);
        assertEquals(uuidKeyId, properties.getKeyId());
    }
}
