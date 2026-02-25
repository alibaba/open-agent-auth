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

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link PeerProperties}.
 *
 * @since 2.1
 */
@SpringBootTest(classes = TestConfiguration.class)
class PeerPropertiesTest {

    @Test
    void testDefaultValues() {
        PeerProperties properties = new PeerProperties();
        
        assertTrue(properties.isEnabled());
    }

    @Test
    void testGetterSetter() {
        PeerProperties properties = new PeerProperties();
        
        properties.setIssuer("http://localhost:8082");
        assertEquals("http://localhost:8082", properties.getIssuer());
        
        properties.setEnabled(false);
        assertEquals(false, properties.isEnabled());
        
        properties.setEnabled(true);
        assertEquals(true, properties.isEnabled());
    }

    @Test
    void testEnabledDefaultValueIsTrue() {
        PeerProperties properties = new PeerProperties();
        
        assertTrue(properties.isEnabled());
    }

    @Test
    void testIssuerSetting() {
        PeerProperties properties = new PeerProperties();
        
        String issuer1 = "http://localhost:8082";
        properties.setIssuer(issuer1);
        assertEquals(issuer1, properties.getIssuer());
        
        String issuer2 = "https://agent-idp.example.com";
        properties.setIssuer(issuer2);
        assertEquals(issuer2, properties.getIssuer());
        
        String issuer3 = "http://192.168.1.100:8080";
        properties.setIssuer(issuer3);
        assertEquals(issuer3, properties.getIssuer());
    }
}
