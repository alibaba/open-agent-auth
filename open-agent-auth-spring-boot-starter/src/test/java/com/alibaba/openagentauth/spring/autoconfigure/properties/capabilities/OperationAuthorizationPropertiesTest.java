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

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link OperationAuthorizationProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(OperationAuthorizationProperties.class)
class OperationAuthorizationPropertiesTest {

    @Test
    void testDefaultValues() {
        OperationAuthorizationProperties properties = new OperationAuthorizationProperties();
        
        assertFalse(properties.isEnabled());
        assertNotNull(properties.getEndpoints());
        assertNotNull(properties.getPromptEncryption());
        assertNotNull(properties.getPromptProtection());
        assertNotNull(properties.getAgentContext());
        assertNotNull(properties.getOauth2Client());
        assertNotNull(properties.getAuthorization());
        
        assertEquals("/api/v1/policies", properties.getEndpoints().getPolicy().getRegistry());
        assertEquals("/api/v1/policies/{policyId}", properties.getEndpoints().getPolicy().getDelete());
        assertEquals("/api/v1/policies/{policyId}", properties.getEndpoints().getPolicy().getGet());
        assertEquals("/api/v1/bindings", properties.getEndpoints().getBinding().getRegistry());
        assertEquals("/api/v1/bindings/{bindingInstanceId}", properties.getEndpoints().getBinding().getGet());
        assertEquals("/api/v1/bindings/{bindingInstanceId}", properties.getEndpoints().getBinding().getDelete());
        
        assertFalse(properties.getPromptEncryption().isEnabled());
        assertEquals("jwe-encryption-key-001", properties.getPromptEncryption().getEncryptionKeyId());
        assertEquals("RSA-OAEP-256", properties.getPromptEncryption().getEncryptionAlgorithm());
        assertEquals("A256GCM", properties.getPromptEncryption().getContentEncryptionAlgorithm());
        
        assertTrue(properties.getPromptProtection().isEnabled());
        assertTrue(properties.getPromptProtection().isEncryptionEnabled());
        assertEquals("MEDIUM", properties.getPromptProtection().getSanitizationLevel());
        assertEquals(3600, properties.getAuthorization().getExpirationSeconds());
    }

    @Test
    void testGetterSetter() {
        OperationAuthorizationProperties properties = new OperationAuthorizationProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties endpoints = new OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties();
        endpoints.setPolicy(new OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties.PolicyEndpointPaths());
        endpoints.getPolicy().setRegistry("/custom/policies");
        properties.setEndpoints(endpoints);
        assertEquals("/custom/policies", properties.getEndpoints().getPolicy().getRegistry());
        
        OperationAuthorizationProperties.PromptEncryptionProperties encryption = new OperationAuthorizationProperties.PromptEncryptionProperties();
        encryption.setEnabled(true);
        properties.setPromptEncryption(encryption);
        assertTrue(properties.getPromptEncryption().isEnabled());
        
        OperationAuthorizationProperties.OAuth2ClientProperties oauth2Client = new OperationAuthorizationProperties.OAuth2ClientProperties();
        oauth2Client.setClientId("test-client");
        properties.setOauth2Client(oauth2Client);
        assertEquals("test-client", properties.getOauth2Client().getClientId());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = OperationAuthorizationProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.capabilities.operation-authorization", annotation.prefix());
    }

    @Test
    void testEndpointsProperties() {
        OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties endpoints = new OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties();
        
        OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties.PolicyEndpointPaths policy = endpoints.getPolicy();
        policy.setRegistry("/custom/policies");
        assertEquals("/custom/policies", policy.getRegistry());
        
        policy.setDelete("/custom/policies/{id}");
        assertEquals("/custom/policies/{id}", policy.getDelete());
        
        policy.setGet("/custom/policies/{id}");
        assertEquals("/custom/policies/{id}", policy.getGet());
        
        OperationAuthorizationProperties.OperationAuthorizationEndpointsProperties.BindingEndpointPaths binding = endpoints.getBinding();
        binding.setRegistry("/custom/bindings");
        assertEquals("/custom/bindings", binding.getRegistry());
        
        binding.setGet("/custom/bindings/{id}");
        assertEquals("/custom/bindings/{id}", binding.getGet());
        
        binding.setDelete("/custom/bindings/{id}");
        assertEquals("/custom/bindings/{id}", binding.getDelete());
    }

    @Test
    void testPromptEncryptionProperties() {
        OperationAuthorizationProperties.PromptEncryptionProperties encryption = new OperationAuthorizationProperties.PromptEncryptionProperties();
        
        encryption.setEnabled(true);
        assertTrue(encryption.isEnabled());
        
        encryption.setEncryptionKeyId("custom-key-id");
        assertEquals("custom-key-id", encryption.getEncryptionKeyId());
        
        encryption.setEncryptionAlgorithm("RSA-OAEP");
        assertEquals("RSA-OAEP", encryption.getEncryptionAlgorithm());
        
        encryption.setContentEncryptionAlgorithm("A128GCM");
        assertEquals("A128GCM", encryption.getContentEncryptionAlgorithm());
        
        encryption.setJwksConsumer("authorization-server");
        assertEquals("authorization-server", encryption.getJwksConsumer());
    }

    @Test
    void testOAuth2ClientProperties() {
        
        
        OperationAuthorizationProperties.OAuth2ClientProperties oauth2Client = new OperationAuthorizationProperties.OAuth2ClientProperties();
        
        // Test credentials
        oauth2Client.setClientId("test-client");
        assertEquals("test-client", oauth2Client.getClientId());
        
        oauth2Client.setClientSecret("test-secret");
        assertEquals("test-secret", oauth2Client.getClientSecret());
        
        oauth2Client.setOauthCallbacksRedirectUri("http://localhost:8080/callback");
        assertEquals("http://localhost:8080/callback", oauth2Client.getOauthCallbacksRedirectUri());
    }

    @Test
    void testAgentContextProperties() {
        OperationAuthorizationProperties.AgentContextProperties agentContext = new OperationAuthorizationProperties.AgentContextProperties();
        
        agentContext.setDefaultClient("test-agent");
        assertEquals("test-agent", agentContext.getDefaultClient());
        
        agentContext.setDefaultChannel("web");
        assertEquals("web", agentContext.getDefaultChannel());
        
        agentContext.setDefaultLanguage("zh-CN");
        assertEquals("zh-CN", agentContext.getDefaultLanguage());
        
        agentContext.setDefaultPlatform("macOS");
        assertEquals("macOS", agentContext.getDefaultPlatform());
        
        agentContext.setDefaultDeviceFingerprint("device-123");
        assertEquals("device-123", agentContext.getDefaultDeviceFingerprint());
    }

    @Test
    void testPromptProtectionProperties() {
        OperationAuthorizationProperties.PromptProtectionProperties protection = new OperationAuthorizationProperties.PromptProtectionProperties();
        
        protection.setEnabled(false);
        assertFalse(protection.isEnabled());
        
        protection.setEncryptionEnabled(false);
        assertFalse(protection.isEncryptionEnabled());
        
        protection.setSanitizationLevel("HIGH");
        assertEquals("HIGH", protection.getSanitizationLevel());
    }

    @Test
    void testAuthorizationBehaviorProperties() {
        OperationAuthorizationProperties.AuthorizationBehaviorProperties authorization = new OperationAuthorizationProperties.AuthorizationBehaviorProperties();
        
        authorization.setRequireUserInteraction(true);
        assertTrue(authorization.isRequireUserInteraction());
        
        authorization.setExpirationSeconds(7200);
        assertEquals(7200, authorization.getExpirationSeconds());
    }

    @Test
    void testBoundaryValues() {
        OperationAuthorizationProperties properties = new OperationAuthorizationProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.getPromptEncryption().setEnabled(true);
        assertTrue(properties.getPromptEncryption().isEnabled());
        
        properties.getAuthorization().setExpirationSeconds(0);
        assertEquals(0, properties.getAuthorization().getExpirationSeconds());
        
        properties.getAuthorization().setExpirationSeconds(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, properties.getAuthorization().getExpirationSeconds());
    }

    @Test
    void testSanitizationLevelValues() {
        OperationAuthorizationProperties.PromptProtectionProperties protection = new OperationAuthorizationProperties.PromptProtectionProperties();
        
        protection.setSanitizationLevel("LOW");
        assertEquals("LOW", protection.getSanitizationLevel());
        
        protection.setSanitizationLevel("MEDIUM");
        assertEquals("MEDIUM", protection.getSanitizationLevel());
        
        protection.setSanitizationLevel("HIGH");
        assertEquals("HIGH", protection.getSanitizationLevel());
    }

    @Test
    void testPropertyIndependence() {
        OperationAuthorizationProperties properties1 = new OperationAuthorizationProperties();
        OperationAuthorizationProperties properties2 = new OperationAuthorizationProperties();
        
        properties1.setEnabled(true);
        assertFalse(properties2.isEnabled());
        
        properties1.getOauth2Client().setClientId("client-1");
        assertNull(properties2.getOauth2Client().getClientId());
    }
}
