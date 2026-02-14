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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksInfrastructureProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyManagementProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDiscoveryProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link InfrastructureProperties}.
 *
 * @since 2.0
 */
@SpringBootTest(classes = TestConfiguration.class)
@EnableConfigurationProperties(InfrastructureProperties.class)
class InfrastructurePropertiesTest {

    @Test
    void testDefaultValues() {
        InfrastructureProperties properties = new InfrastructureProperties();
        
        assertEquals("wimse://default.trust.domain", properties.getTrustDomain());
        assertNotNull(properties.getKeyManagement());
        assertNotNull(properties.getJwks());
        assertNotNull(properties.getServiceDiscovery());
    }

    @Test
    void testGetterSetter() {
        InfrastructureProperties properties = new InfrastructureProperties();
        
        String trustDomain = "wimse://custom.trust.domain";
        properties.setTrustDomain(trustDomain);
        assertEquals(trustDomain, properties.getTrustDomain());
        
        KeyManagementProperties keyManagement = new KeyManagementProperties();
        properties.setKeyManagement(keyManagement);
        assertEquals(keyManagement, properties.getKeyManagement());
        
        JwksInfrastructureProperties jwks = new JwksInfrastructureProperties();
        properties.setJwks(jwks);
        assertEquals(jwks, properties.getJwks());
        
        ServiceDiscoveryProperties serviceDiscovery = new ServiceDiscoveryProperties();
        properties.setServiceDiscovery(serviceDiscovery);
        assertEquals(serviceDiscovery, properties.getServiceDiscovery());
    }

    @Test
    void testNestedProperties() {
        InfrastructureProperties properties = new InfrastructureProperties();
        
        assertNotNull(properties.getKeyManagement().getProviders());
        assertNotNull(properties.getKeyManagement().getKeys());
        
        assertNotNull(properties.getJwks().getProvider());
        assertNotNull(properties.getJwks().getConsumers());
        
        assertNotNull(properties.getServiceDiscovery().getServices());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = InfrastructureProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.infrastructures", annotation.prefix());
    }

    @Test
    void testBoundaryValues() {
        InfrastructureProperties properties = new InfrastructureProperties();
        
        properties.setTrustDomain("");
        assertEquals("", properties.getTrustDomain());
        
        properties.setTrustDomain("wimse://test.domain");
        assertEquals("wimse://test.domain", properties.getTrustDomain());
        
        properties.setTrustDomain(null);
        assertNull(properties.getTrustDomain());
    }

    @Test
    void testNotNullConstraints() {
        InfrastructureProperties properties = new InfrastructureProperties();
        
        assertNotNull(properties.getTrustDomain());
        assertNotNull(properties.getKeyManagement());
        assertNotNull(properties.getJwks());
        assertNotNull(properties.getServiceDiscovery());
    }

    @Test
    void testPropertyIndependence() {
        InfrastructureProperties properties1 = new InfrastructureProperties();
        InfrastructureProperties properties2 = new InfrastructureProperties();
        
        properties1.setTrustDomain("wimse://domain1");
        assertEquals("wimse://default.trust.domain", properties2.getTrustDomain());
        
        properties1.getKeyManagement().getProviders().put("test", null);
        assertTrue(properties2.getKeyManagement().getProviders().isEmpty());
    }

    @Test
    void testTrustDomainFormat() {
        InfrastructureProperties properties = new InfrastructureProperties();
        
        String validDomain = "wimse://example.trust.domain";
        properties.setTrustDomain(validDomain);
        assertEquals(validDomain, properties.getTrustDomain());
        
        String customDomain = "wimse://custom.domain.name";
        properties.setTrustDomain(customDomain);
        assertEquals(customDomain, properties.getTrustDomain());
    }
}
