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

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OAuth2ClientProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(OpenAgentAuthProperties.class)
class OAuth2ClientPropertiesTest {

    @Autowired
    private OpenAgentAuthProperties openAgentAuthProperties;

    @Test
    void testDefaultValues() {
        OAuth2ClientProperties properties = new OAuth2ClientProperties();
        
        assertFalse(properties.isEnabled());
        assertNotNull(properties.getAuthentication());
        assertNotNull(properties.getCallback());
        
        assertTrue(properties.getAuthentication().isEnabled());
        // includePaths default value: List.of("/**")
        assertFalse(properties.getAuthentication().getIncludePaths().isEmpty());
        assertEquals(1, properties.getAuthentication().getIncludePaths().size());
        assertEquals("/**", properties.getAuthentication().getIncludePaths().get(0));
        
        // excludePaths default value: List.of("/login", "/callback", "/public/**", "/oauth2/consent", "/oauth2/authorize", "/.well-known/**")
        assertFalse(properties.getAuthentication().getExcludePaths().isEmpty());
        assertEquals(6, properties.getAuthentication().getExcludePaths().size());
        
        assertFalse(properties.getCallback().isEnabled());
        assertEquals("/callback", properties.getCallback().getEndpoint());
        assertFalse(properties.getCallback().isAutoRegister());
    }

    @Test
    void testGetterSetter() {
        OAuth2ClientProperties properties = openAgentAuthProperties.getCapabilities().getOAuth2Client();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        OAuth2ClientProperties.OAuth2ClientAuthenticationProperties auth = new OAuth2ClientProperties.OAuth2ClientAuthenticationProperties();
        auth.setEnabled(false);
        properties.setAuthentication(auth);
        assertFalse(properties.getAuthentication().isEnabled());
        
        OAuth2ClientProperties.OAuth2ClientCallbackProperties callback = new OAuth2ClientProperties.OAuth2ClientCallbackProperties();
        callback.setEnabled(true);
        properties.setCallback(callback);
        assertTrue(properties.getCallback().isEnabled());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = OAuth2ClientProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNull(annotation, "OAuth2ClientProperties should not have @ConfigurationProperties annotation as it is nested within parent properties");
    }

    @Test
    void testAuthenticationProperties() {
        OAuth2ClientProperties.OAuth2ClientAuthenticationProperties auth = new OAuth2ClientProperties.OAuth2ClientAuthenticationProperties();
        
        auth.setEnabled(true);
        assertTrue(auth.isEnabled());
        
        List<String> includePaths = new ArrayList<>();
        includePaths.add("/api/v1/**");
        includePaths.add("/api/v2/**");
        auth.setIncludePaths(includePaths);
        assertEquals(includePaths, auth.getIncludePaths());
        
        List<String> excludePaths = new ArrayList<>();
        excludePaths.add("/health");
        excludePaths.add("/metrics");
        auth.setExcludePaths(excludePaths);
        assertEquals(excludePaths, auth.getExcludePaths());
    }

    @Test
    void testCallbackProperties() {
        OAuth2ClientProperties.OAuth2ClientCallbackProperties callback = new OAuth2ClientProperties.OAuth2ClientCallbackProperties();
        
        callback.setEnabled(true);
        assertTrue(callback.isEnabled());
        
        callback.setEndpoint("/oauth2/callback");
        assertEquals("/oauth2/callback", callback.getEndpoint());
        
        callback.setAutoRegister(false);
        assertFalse(callback.isAutoRegister());
    }

    @Test
    void testTopLevelCredentials() {
        OAuth2ClientProperties properties = new OAuth2ClientProperties();

        properties.setClientId("test-client");
        assertEquals("test-client", properties.getClientId());

        properties.setClientSecret("test-secret");
        assertEquals("test-secret", properties.getClientSecret());
    }

    @Test
    void testBoundaryValues() {
        OAuth2ClientProperties properties = openAgentAuthProperties.getCapabilities().getOAuth2Client();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.getAuthentication().setEnabled(true);
        assertTrue(properties.getAuthentication().isEnabled());
        properties.getAuthentication().setEnabled(false);
        assertFalse(properties.getAuthentication().isEnabled());
        
        properties.getCallback().setEnabled(true);
        assertTrue(properties.getCallback().isEnabled());
        properties.getCallback().setEnabled(false);
        assertFalse(properties.getCallback().isEnabled());
    }

    @Test
    void testPathPatterns() {
        OAuth2ClientProperties properties = openAgentAuthProperties.getCapabilities().getOAuth2Client();
        
        List<String> includePaths = new ArrayList<>();
        includePaths.add("/api/**");
        includePaths.add("/admin/**");
        properties.getAuthentication().setIncludePaths(includePaths);
        
        assertEquals(2, properties.getAuthentication().getIncludePaths().size());
        assertTrue(properties.getAuthentication().getIncludePaths().contains("/api/**"));
        
        List<String> excludePaths = new ArrayList<>();
        excludePaths.add("/api/public/**");
        excludePaths.add("/health");
        properties.getAuthentication().setExcludePaths(excludePaths);
        
        assertEquals(2, properties.getAuthentication().getExcludePaths().size());
        assertTrue(properties.getAuthentication().getExcludePaths().contains("/api/public/**"));
    }

    @Test
    void testPropertyIndependence() {
        OAuth2ClientProperties properties1 = openAgentAuthProperties.getCapabilities().getOAuth2Client();
        OAuth2ClientProperties properties2 = new OAuth2ClientProperties();
        
        properties1.setEnabled(true);
        assertFalse(properties2.isEnabled());
        
        properties1.getAuthentication().setEnabled(false);
        assertTrue(properties2.getAuthentication().isEnabled());
        
        properties1.getCallback().setEnabled(true);
        assertFalse(properties2.getCallback().isEnabled());
    }
}