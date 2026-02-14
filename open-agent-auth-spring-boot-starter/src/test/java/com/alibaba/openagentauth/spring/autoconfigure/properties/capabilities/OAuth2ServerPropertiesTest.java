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

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OAuth2ServerProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(OAuth2ServerProperties.class)
class OAuth2ServerPropertiesTest {

    @Test
    void testDefaultValues() {
        OAuth2ServerProperties properties = new OAuth2ServerProperties();
        
        assertFalse(properties.isEnabled());
        assertNotNull(properties.getEndpoints());
        assertNotNull(properties.getToken());
        assertNotNull(properties.getAutoRegisterClients());
        
        assertEquals("/oauth2/authorize", properties.getEndpoints().getOauth2().getAuthorize());
        assertEquals("/oauth2/token", properties.getEndpoints().getOauth2().getToken());
        assertEquals("/par", properties.getEndpoints().getOauth2().getPar());
        assertEquals("/oauth2/userinfo", properties.getEndpoints().getOauth2().getUserinfo());
        assertEquals("/oauth2/register", properties.getEndpoints().getOauth2().getDcr());
        assertEquals("/oauth2/logout", properties.getEndpoints().getOauth2().getLogout());
        
        assertEquals(3600, properties.getToken().getAccessTokenExpiry());
        assertEquals(2592000, properties.getToken().getRefreshTokenExpiry());
        assertEquals(3600, properties.getToken().getIdTokenExpiry());
        assertEquals(600, properties.getToken().getAuthorizationCodeExpiry());
        
        assertFalse(properties.getAutoRegisterClients().isEnabled());
        assertTrue(properties.getAutoRegisterClients().getClients().isEmpty());
    }

    @Test
    void testGetterSetter() {
        OAuth2ServerProperties properties = new OAuth2ServerProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        OAuth2ServerProperties.OAuth2EndpointsProperties endpoints = new OAuth2ServerProperties.OAuth2EndpointsProperties();
        endpoints.setOauth2(new OAuth2ServerProperties.OAuth2EndpointsProperties.OAuth2EndpointPaths());
        endpoints.getOauth2().setAuthorize("/custom/authorize");
        properties.setEndpoints(endpoints);
        assertEquals("/custom/authorize", properties.getEndpoints().getOauth2().getAuthorize());
        
        OAuth2ServerProperties.OAuth2TokenProperties token = new OAuth2ServerProperties.OAuth2TokenProperties();
        token.setAccessTokenExpiry(7200);
        properties.setToken(token);
        assertEquals(7200, properties.getToken().getAccessTokenExpiry());
        
        OAuth2ServerProperties.AutoRegisterClientsProperties autoRegister = new OAuth2ServerProperties.AutoRegisterClientsProperties();
        autoRegister.setEnabled(true);
        properties.setAutoRegisterClients(autoRegister);
        assertTrue(properties.getAutoRegisterClients().isEnabled());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = OAuth2ServerProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.capabilities.oauth2-server", annotation.prefix());
    }

    @Test
    void testEndpointsProperties() {
        OAuth2ServerProperties.OAuth2EndpointsProperties endpoints = new OAuth2ServerProperties.OAuth2EndpointsProperties();
        OAuth2ServerProperties.OAuth2EndpointsProperties.OAuth2EndpointPaths oauth2 = endpoints.getOauth2();
        
        oauth2.setAuthorize("/custom/authorize");
        assertEquals("/custom/authorize", oauth2.getAuthorize());
        
        oauth2.setToken("/custom/token");
        assertEquals("/custom/token", oauth2.getToken());
        
        oauth2.setPar("/custom/par");
        assertEquals("/custom/par", oauth2.getPar());
        
        oauth2.setUserinfo("/custom/userinfo");
        assertEquals("/custom/userinfo", oauth2.getUserinfo());
        
        oauth2.setDcr("/custom/register");
        assertEquals("/custom/register", oauth2.getDcr());
        
        oauth2.setLogout("/custom/logout");
        assertEquals("/custom/logout", oauth2.getLogout());
    }

    @Test
    void testTokenProperties() {
        OAuth2ServerProperties.OAuth2TokenProperties token = new OAuth2ServerProperties.OAuth2TokenProperties();
        
        token.setAccessTokenExpiry(7200);
        assertEquals(7200, token.getAccessTokenExpiry());
        
        token.setRefreshTokenExpiry(5184000);
        assertEquals(5184000, token.getRefreshTokenExpiry());
        
        token.setIdTokenExpiry(7200);
        assertEquals(7200, token.getIdTokenExpiry());
        
        token.setAuthorizationCodeExpiry(300);
        assertEquals(300, token.getAuthorizationCodeExpiry());
    }

    @Test
    void testAutoRegisterClientsProperties() {
        OAuth2ServerProperties.AutoRegisterClientsProperties autoRegister = new OAuth2ServerProperties.AutoRegisterClientsProperties();
        
        autoRegister.setEnabled(true);
        assertTrue(autoRegister.isEnabled());
        
        List<OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties> clients = new ArrayList<>();
        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties client = new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        client.setClientId("test-client");
        client.setClientSecret("test-secret");
        client.setClientName("Test Client");
        clients.add(client);
        
        autoRegister.setClients(clients);
        assertEquals(1, autoRegister.getClients().size());
        assertEquals("test-client", autoRegister.getClients().get(0).getClientId());
    }

    @Test
    void testAutoRegisterClientItemProperties() {
        OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties client = new OAuth2ServerProperties.AutoRegisterClientsProperties.AutoRegisterClientItemProperties();
        
        client.setClientName("Test Client");
        assertEquals("Test Client", client.getClientName());
        
        client.setClientId("test-client");
        assertEquals("test-client", client.getClientId());
        
        client.setClientSecret("test-secret");
        assertEquals("test-secret", client.getClientSecret());
        
        List<String> redirectUris = new ArrayList<>();
        redirectUris.add("http://localhost:8080/callback");
        client.setRedirectUris(redirectUris);
        assertEquals(redirectUris, client.getRedirectUris());
        
        List<String> grantTypes = new ArrayList<>();
        grantTypes.add("authorization_code");
        grantTypes.add("refresh_token");
        client.setGrantTypes(grantTypes);
        assertEquals(grantTypes, client.getGrantTypes());
        
        List<String> responseTypes = new ArrayList<>();
        responseTypes.add("code");
        client.setResponseTypes(responseTypes);
        assertEquals(responseTypes, client.getResponseTypes());
        
        client.setTokenEndpointAuthMethod("client_secret_post");
        assertEquals("client_secret_post", client.getTokenEndpointAuthMethod());
        
        List<String> scopes = new ArrayList<>();
        scopes.add("openid");
        scopes.add("profile");
        client.setScopes(scopes);
        assertEquals(scopes, client.getScopes());
    }

    @Test
    void testBoundaryValues() {
        OAuth2ServerProperties properties = new OAuth2ServerProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.getToken().setAccessTokenExpiry(0);
        assertEquals(0, properties.getToken().getAccessTokenExpiry());
        
        properties.getToken().setAccessTokenExpiry(Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, properties.getToken().getAccessTokenExpiry());
    }

    @Test
    void testPropertyIndependence() {
        OAuth2ServerProperties properties1 = new OAuth2ServerProperties();
        OAuth2ServerProperties properties2 = new OAuth2ServerProperties();
        
        properties1.setEnabled(true);
        assertFalse(properties2.isEnabled());
        
        properties1.getEndpoints().getOauth2().setAuthorize("/custom");
        assertEquals("/oauth2/authorize", properties2.getEndpoints().getOauth2().getAuthorize());
    }
}
