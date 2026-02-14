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
 * Unit tests for {@link JwksProviderProperties}.
 *
 * @since 2.0
 */
class JwksProviderPropertiesTest {

    @Test
    void testDefaultValues() {
        JwksProviderProperties properties = new JwksProviderProperties();
        
        assertTrue(properties.isEnabled());
        assertEquals("/.well-known/jwks.json", properties.getPath());
        assertEquals(300, properties.getCacheDurationSeconds());
        assertTrue(properties.isCacheHeadersEnabled());
    }

    @Test
    void testGetterSetter() {
        JwksProviderProperties properties = new JwksProviderProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.setPath("/custom/jwks.json");
        assertEquals("/custom/jwks.json", properties.getPath());
        
        properties.setCacheDurationSeconds(600);
        assertEquals(600, properties.getCacheDurationSeconds());
        
        properties.setCacheHeadersEnabled(false);
        assertFalse(properties.isCacheHeadersEnabled());
        
        properties.setCacheHeadersEnabled(true);
        assertTrue(properties.isCacheHeadersEnabled());
    }

    @Test
    void testBoundaryValues() {
        JwksProviderProperties properties = new JwksProviderProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.setPath("");
        assertEquals("", properties.getPath());
        
        properties.setCacheDurationSeconds(0);
        assertEquals(0, properties.getCacheDurationSeconds());
        
        properties.setCacheDurationSeconds(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, properties.getCacheDurationSeconds());
    }

    @Test
    void testPathFormat() {
        JwksProviderProperties properties = new JwksProviderProperties();
        
        String standardPath = "/.well-known/jwks.json";
        properties.setPath(standardPath);
        assertEquals(standardPath, properties.getPath());
        
        String customPath = "/custom/jwks";
        properties.setPath(customPath);
        assertEquals(customPath, properties.getPath());
        
        String rootPath = "/jwks.json";
        properties.setPath(rootPath);
        assertEquals(rootPath, properties.getPath());
    }

    @Test
    void testCacheDurationValues() {
        JwksProviderProperties properties = new JwksProviderProperties();
        
        properties.setCacheDurationSeconds(60);
        assertEquals(60, properties.getCacheDurationSeconds());
        
        properties.setCacheDurationSeconds(300);
        assertEquals(300, properties.getCacheDurationSeconds());
        
        properties.setCacheDurationSeconds(600);
        assertEquals(600, properties.getCacheDurationSeconds());
        
        properties.setCacheDurationSeconds(3600);
        assertEquals(3600, properties.getCacheDurationSeconds());
    }

    @Test
    void testPropertyIndependence() {
        JwksProviderProperties properties1 = new JwksProviderProperties();
        JwksProviderProperties properties2 = new JwksProviderProperties();
        
        properties1.setEnabled(false);
        assertTrue(properties2.isEnabled());
        
        properties1.setPath("/custom");
        assertEquals("/.well-known/jwks.json", properties2.getPath());
        
        properties1.setCacheDurationSeconds(600);
        assertEquals(300, properties2.getCacheDurationSeconds());
        
        properties1.setCacheHeadersEnabled(false);
        assertTrue(properties2.isCacheHeadersEnabled());
    }

    @Test
    void testNotNullConstraints() {
        JwksProviderProperties properties = new JwksProviderProperties();
        
        assertNotNull(properties.isEnabled());
        assertNotNull(properties.getPath());
        assertNotNull(properties.getCacheDurationSeconds());
        assertNotNull(properties.isCacheHeadersEnabled());
    }
}
