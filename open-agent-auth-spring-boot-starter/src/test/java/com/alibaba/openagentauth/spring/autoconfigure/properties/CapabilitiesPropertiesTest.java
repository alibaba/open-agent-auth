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

import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.AuditProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.UserAuthenticationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.WorkloadIdentityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link CapabilitiesProperties}.
 *
 * @since 2.0
 */
@SpringBootTest(classes = TestConfiguration.class)
@EnableConfigurationProperties(CapabilitiesProperties.class)
class CapabilitiesPropertiesTest {

    @Test
    void testDefaultValues() {
        CapabilitiesProperties properties = new CapabilitiesProperties();
        
        assertNotNull(properties.getOAuth2Server());
        assertNotNull(properties.getOAuth2Client());
        assertNotNull(properties.getWorkloadIdentity());
        assertNotNull(properties.getOperationAuthorization());
        assertNotNull(properties.getUserAuthentication());
        assertNotNull(properties.getAudit());
        
        assertFalse(properties.getOAuth2Server().isEnabled());
        assertFalse(properties.getOAuth2Client().isEnabled());
        assertFalse(properties.getWorkloadIdentity().isEnabled());
        assertFalse(properties.getOperationAuthorization().isEnabled());
        assertFalse(properties.getUserAuthentication().isEnabled());
        assertFalse(properties.getAudit().isEnabled());
    }

    @Test
    void testGetterSetter() {
        CapabilitiesProperties properties = new CapabilitiesProperties();
        
        OAuth2ServerProperties oauth2Server = new OAuth2ServerProperties();
        oauth2Server.setEnabled(true);
        properties.setOAuth2Server(oauth2Server);
        assertTrue(properties.getOAuth2Server().isEnabled());
        
        OAuth2ClientProperties oauth2Client = new OAuth2ClientProperties();
        oauth2Client.setEnabled(true);
        properties.setOAuth2Client(oauth2Client);
        assertTrue(properties.getOAuth2Client().isEnabled());
        
        WorkloadIdentityProperties workloadIdentity = new WorkloadIdentityProperties();
        workloadIdentity.setEnabled(true);
        properties.setWorkloadIdentity(workloadIdentity);
        assertTrue(properties.getWorkloadIdentity().isEnabled());
        
        OperationAuthorizationProperties operationAuthorization = new OperationAuthorizationProperties();
        operationAuthorization.setEnabled(true);
        properties.setOperationAuthorization(operationAuthorization);
        assertTrue(properties.getOperationAuthorization().isEnabled());
        
        UserAuthenticationProperties userAuthentication = new UserAuthenticationProperties();
        userAuthentication.setEnabled(true);
        properties.setUserAuthentication(userAuthentication);
        assertTrue(properties.getUserAuthentication().isEnabled());
        
        AuditProperties audit = new AuditProperties();
        audit.setEnabled(true);
        properties.setAudit(audit);
        assertTrue(properties.getAudit().isEnabled());
    }

    @Test
    void testNestedProperties() {
        CapabilitiesProperties properties = new CapabilitiesProperties();
        
        assertNotNull(properties.getOAuth2Server().getEndpoints());
        assertNotNull(properties.getOAuth2Server().getToken());
        assertNotNull(properties.getOAuth2Server().getAutoRegisterClients());
        
        assertNotNull(properties.getOAuth2Client().getAuthentication());
        assertNotNull(properties.getOAuth2Client().getCallback());
        
        assertNotNull(properties.getWorkloadIdentity().getEndpoints());
        
        assertNotNull(properties.getOperationAuthorization().getEndpoints());
        assertNotNull(properties.getOperationAuthorization().getPromptEncryption());
        assertNotNull(properties.getOperationAuthorization().getOauth2Client());
        
        assertNotNull(properties.getUserAuthentication().getLoginPage());
        assertNotNull(properties.getUserAuthentication().getUserRegistry());
        
        assertNotNull(properties.getAudit().getEndpoints());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = CapabilitiesProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.capabilities", annotation.prefix());
    }

    @Test
    void testBoundaryValues() {
        CapabilitiesProperties properties = new CapabilitiesProperties();
        
        properties.getOAuth2Server().setEnabled(true);
        assertTrue(properties.getOAuth2Server().isEnabled());
        properties.getOAuth2Server().setEnabled(false);
        assertFalse(properties.getOAuth2Server().isEnabled());
        
        properties.getOAuth2Client().setEnabled(true);
        assertTrue(properties.getOAuth2Client().isEnabled());
        properties.getOAuth2Client().setEnabled(false);
        assertFalse(properties.getOAuth2Client().isEnabled());
    }

    @Test
    void testNotNullConstraints() {
        CapabilitiesProperties properties = new CapabilitiesProperties();
        
        assertNotNull(properties.getOAuth2Server());
        assertNotNull(properties.getOAuth2Client());
        assertNotNull(properties.getWorkloadIdentity());
        assertNotNull(properties.getOperationAuthorization());
        assertNotNull(properties.getUserAuthentication());
        assertNotNull(properties.getAudit());
    }

    @Test
    void testPropertyIndependence() {
        CapabilitiesProperties properties1 = new CapabilitiesProperties();
        CapabilitiesProperties properties2 = new CapabilitiesProperties();
        
        properties1.getOAuth2Server().setEnabled(true);
        assertFalse(properties2.getOAuth2Server().isEnabled());
        
        properties1.getOAuth2Client().setEnabled(true);
        assertFalse(properties2.getOAuth2Client().isEnabled());
        
        properties1.getAudit().setEnabled(true);
        assertFalse(properties2.getAudit().isEnabled());
    }
}
