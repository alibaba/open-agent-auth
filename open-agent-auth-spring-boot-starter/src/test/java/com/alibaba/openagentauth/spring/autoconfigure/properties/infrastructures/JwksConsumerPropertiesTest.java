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
 * Unit tests for {@link JwksConsumerProperties}.
 *
 * @since 2.0
 */
class JwksConsumerPropertiesTest {

    @Test
    void testDefaultValues() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        assertTrue(properties.isEnabled());
        assertNull(properties.getJwksEndpoint());
        assertNull(properties.getIssuer());
    }

    @Test
    void testGetterSetter() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        String jwksEndpoint = "https://example.com/.well-known/jwks.json";
        properties.setJwksEndpoint(jwksEndpoint);
        assertEquals(jwksEndpoint, properties.getJwksEndpoint());
        
        String issuer = "https://example.com";
        properties.setIssuer(issuer);
        assertEquals(issuer, properties.getIssuer());
    }

    @Test
    void testBoundaryValues() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.setJwksEndpoint("");
        assertEquals("", properties.getJwksEndpoint());
        
        properties.setIssuer("");
        assertEquals("", properties.getIssuer());
        
        properties.setJwksEndpoint(null);
        assertNull(properties.getJwksEndpoint());
        
        properties.setIssuer(null);
        assertNull(properties.getIssuer());
    }

    @Test
    void testJwksEndpointFormat() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        String validEndpoint = "https://example.com/.well-known/jwks.json";
        properties.setJwksEndpoint(validEndpoint);
        assertEquals(validEndpoint, properties.getJwksEndpoint());
        
        String customEndpoint = "https://custom-idp.com/jwks";
        properties.setJwksEndpoint(customEndpoint);
        assertEquals(customEndpoint, properties.getJwksEndpoint());
    }

    @Test
    void testIssuerFormat() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        String validIssuer = "https://example.com";
        properties.setIssuer(validIssuer);
        assertEquals(validIssuer, properties.getIssuer());
        
        String customIssuer = "https://custom-idp.example.com";
        properties.setIssuer(customIssuer);
        assertEquals(customIssuer, properties.getIssuer());
    }

    @Test
    void testPropertyIndependence() {
        JwksConsumerProperties properties1 = new JwksConsumerProperties();
        JwksConsumerProperties properties2 = new JwksConsumerProperties();
        
        properties1.setEnabled(false);
        assertTrue(properties2.isEnabled());
        
        properties1.setJwksEndpoint("https://example1.com/jwks.json");
        assertNull(properties2.getJwksEndpoint());
        
        properties1.setIssuer("https://example1.com");
        assertNull(properties2.getIssuer());
    }

    @Test
    void testNotNullConstraints() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // isEnabled() returns a primitive boolean, not null
        assertTrue(properties.isEnabled());
        // jwksEndpoint and issuer can be null by default
        // Test that we can set them to non-null values
        properties.setJwksEndpoint("https://example.com/.well-known/jwks.json");
        assertNotNull(properties.getJwksEndpoint());
        properties.setIssuer("https://example.com");
        assertNotNull(properties.getIssuer());
    }

    // ========== Automatic Derivation Tests ==========

    @Test
    void testDeriveJwksEndpointFromIssuer() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Set only issuer, jwks-endpoint should be derived
        properties.setIssuer("https://example.com");
        assertEquals("https://example.com", properties.getIssuer());
        assertEquals("https://example.com/.well-known/jwks.json", properties.getJwksEndpoint());
    }

    @Test
    void testDeriveIssuerFromJwksEndpoint() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Set only jwks-endpoint, issuer should be derived
        properties.setJwksEndpoint("https://agent-idp.example.com/.well-known/jwks.json");
        assertEquals("https://agent-idp.example.com/.well-known/jwks.json", properties.getJwksEndpoint());
        assertEquals("https://agent-idp.example.com", properties.getIssuer());
    }

    @Test
    void testBothConfiguredNoDerivation() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Set both, no derivation should happen
        properties.setIssuer("https://custom-issuer.com");
        properties.setJwksEndpoint("https://custom-endpoint.com/custom/jwks.json");
        assertEquals("https://custom-issuer.com", properties.getIssuer());
        assertEquals("https://custom-endpoint.com/custom/jwks.json", properties.getJwksEndpoint());
    }

    @Test
    void testDeriveIssuerFromNonStandardJwksEndpoint() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Set jwks-endpoint without standard path, issuer should be the endpoint itself
        properties.setJwksEndpoint("https://custom-idp.com/jwks");
        assertEquals("https://custom-idp.com/jwks", properties.getJwksEndpoint());
        assertEquals("https://custom-idp.com/jwks", properties.getIssuer());
    }

    @Test
    void testDeriveWithLocalhost() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Test with localhost
        properties.setIssuer("http://localhost:8080");
        assertEquals("http://localhost:8080", properties.getIssuer());
        assertEquals("http://localhost:8080/.well-known/jwks.json", properties.getJwksEndpoint());
    }

    @Test
    void testDeriveWithPort() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Test with port
        properties.setIssuer("https://example.com:8443");
        assertEquals("https://example.com:8443", properties.getIssuer());
        assertEquals("https://example.com:8443/.well-known/jwks.json", properties.getJwksEndpoint());
    }

    @Test
    void testDeriveWithTrailingSlash() {
        JwksConsumerProperties properties = new JwksConsumerProperties();
        
        // Test issuer with trailing slash
        properties.setIssuer("https://example.com/");
        assertEquals("https://example.com/", properties.getIssuer());
        assertEquals("https://example.com//.well-known/jwks.json", properties.getJwksEndpoint());
    }

    @Test
    void testDerivedValuesAreIndependent() {
        JwksConsumerProperties properties1 = new JwksConsumerProperties();
        JwksConsumerProperties properties2 = new JwksConsumerProperties();
        
        properties1.setIssuer("https://example1.com");
        properties2.setIssuer("https://example2.com");
        
        assertEquals("https://example1.com/.well-known/jwks.json", properties1.getJwksEndpoint());
        assertEquals("https://example2.com/.well-known/jwks.json", properties2.getJwksEndpoint());
    }
}