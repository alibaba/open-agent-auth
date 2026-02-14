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
 * Unit tests for {@link UserAuthenticationProperties}.
 *
 * @since 2.0
 */
@SpringBootTest
@ContextConfiguration
@EnableConfigurationProperties(UserAuthenticationProperties.class)
class UserAuthenticationPropertiesTest {

    @Test
    void testDefaultValues() {
        UserAuthenticationProperties properties = new UserAuthenticationProperties();
        
        assertFalse(properties.isEnabled());
        assertNotNull(properties.getLoginPage());
        assertNotNull(properties.getUserRegistry());
        
        assertTrue(properties.getLoginPage().isEnabled());
        assertEquals("Identity Provider - Login", properties.getLoginPage().getPageTitle());
        assertEquals("Identity Provider", properties.getLoginPage().getTitle());
        assertEquals("Please sign in to continue", properties.getLoginPage().getSubtitle());
        assertEquals("Username", properties.getLoginPage().getUsernameLabel());
        assertEquals("Password", properties.getLoginPage().getPasswordLabel());
        assertEquals("Sign In", properties.getLoginPage().getButtonText());
        assertFalse(properties.getLoginPage().isShowDemoUsers());
        assertEquals("", properties.getLoginPage().getDemoUsers());
        assertEquals("", properties.getLoginPage().getFooterText());
        assertEquals("classpath:/templates/login.html", properties.getLoginPage().getTemplate());
        
        assertTrue(properties.getUserRegistry().isEnabled());
        assertEquals("in-memory", properties.getUserRegistry().getType());
        assertTrue(properties.getUserRegistry().getPresetUsers().isEmpty());
    }

    @Test
    void testGetterSetter() {
        UserAuthenticationProperties properties = new UserAuthenticationProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        
        UserAuthenticationProperties.LoginPageProperties loginPage = new UserAuthenticationProperties.LoginPageProperties();
        loginPage.setEnabled(false);
        properties.setLoginPage(loginPage);
        assertFalse(properties.getLoginPage().isEnabled());
        
        UserAuthenticationProperties.UserRegistryProperties userRegistry = new UserAuthenticationProperties.UserRegistryProperties();
        userRegistry.setType("jdbc");
        properties.setUserRegistry(userRegistry);
        assertEquals("jdbc", properties.getUserRegistry().getType());
    }

    @Test
    void testConfigurationPropertiesAnnotation() {
        ConfigurationProperties annotation = UserAuthenticationProperties.class.getAnnotation(ConfigurationProperties.class);
        assertNotNull(annotation);
        assertEquals("open-agent-auth.capabilities.user-authentication", annotation.prefix());
    }

    @Test
    void testLoginPageProperties() {
        UserAuthenticationProperties.LoginPageProperties loginPage = new UserAuthenticationProperties.LoginPageProperties();
        
        loginPage.setEnabled(true);
        assertTrue(loginPage.isEnabled());
        
        loginPage.setPageTitle("Custom Title");
        assertEquals("Custom Title", loginPage.getPageTitle());
        
        loginPage.setTitle("Custom Identity Provider");
        assertEquals("Custom Identity Provider", loginPage.getTitle());
        
        loginPage.setSubtitle("Custom subtitle");
        assertEquals("Custom subtitle", loginPage.getSubtitle());
        
        loginPage.setUsernameLabel("User ID");
        assertEquals("User ID", loginPage.getUsernameLabel());
        
        loginPage.setPasswordLabel("Passcode");
        assertEquals("Passcode", loginPage.getPasswordLabel());
        
        loginPage.setButtonText("Login");
        assertEquals("Login", loginPage.getButtonText());
        
        loginPage.setShowDemoUsers(true);
        assertTrue(loginPage.isShowDemoUsers());
        
        loginPage.setDemoUsers("admin:admin123;user:user123");
        assertEquals("admin:admin123;user:user123", loginPage.getDemoUsers());
        
        loginPage.setFooterText("© 2024 My Company");
        assertEquals("© 2024 My Company", loginPage.getFooterText());
        
        loginPage.setTemplate("classpath:/templates/custom-login.html");
        assertEquals("classpath:/templates/custom-login.html", loginPage.getTemplate());
    }

    @Test
    void testUserRegistryProperties() {
        UserAuthenticationProperties.UserRegistryProperties userRegistry = new UserAuthenticationProperties.UserRegistryProperties();
        
        userRegistry.setEnabled(true);
        assertTrue(userRegistry.isEnabled());
        
        userRegistry.setType("jdbc");
        assertEquals("jdbc", userRegistry.getType());
        
        userRegistry.setType("ldap");
        assertEquals("ldap", userRegistry.getType());
        
        List<UserAuthenticationProperties.UserRegistryProperties.PresetUserProperties> presetUsers = new ArrayList<>();
        UserAuthenticationProperties.UserRegistryProperties.PresetUserProperties user = new UserAuthenticationProperties.UserRegistryProperties.PresetUserProperties();
        user.setUsername("admin");
        user.setPassword("admin123");
        presetUsers.add(user);
        
        userRegistry.setPresetUsers(presetUsers);
        assertEquals(1, userRegistry.getPresetUsers().size());
        assertEquals("admin", userRegistry.getPresetUsers().get(0).getUsername());
    }

    @Test
    void testPresetUserProperties() {
        UserAuthenticationProperties.UserRegistryProperties.PresetUserProperties user = new UserAuthenticationProperties.UserRegistryProperties.PresetUserProperties();
        
        user.setUsername("testuser");
        assertEquals("testuser", user.getUsername());
        
        user.setPassword("testpass");
        assertEquals("testpass", user.getPassword());
        
        user.setSubject("sub-123");
        assertEquals("sub-123", user.getSubject());
        
        user.setEmail("test@example.com");
        assertEquals("test@example.com", user.getEmail());
        
        user.setName("Test User");
        assertEquals("Test User", user.getName());
    }

    @Test
    void testBoundaryValues() {
        UserAuthenticationProperties properties = new UserAuthenticationProperties();
        
        properties.setEnabled(true);
        assertTrue(properties.isEnabled());
        properties.setEnabled(false);
        assertFalse(properties.isEnabled());
        
        properties.getLoginPage().setEnabled(true);
        assertTrue(properties.getLoginPage().isEnabled());
        properties.getLoginPage().setEnabled(false);
        assertFalse(properties.getLoginPage().isEnabled());
        
        properties.getUserRegistry().setEnabled(true);
        assertTrue(properties.getUserRegistry().isEnabled());
        properties.getUserRegistry().setEnabled(false);
        assertFalse(properties.getUserRegistry().isEnabled());
    }

    @Test
    void testDemoUsersFormat() {
        UserAuthenticationProperties.LoginPageProperties loginPage = new UserAuthenticationProperties.LoginPageProperties();
        
        loginPage.setShowDemoUsers(true);
        loginPage.setDemoUsers("admin:admin123");
        assertEquals("admin:admin123", loginPage.getDemoUsers());
        
        loginPage.setDemoUsers("admin:admin123;user:user123;guest:guest123");
        assertEquals("admin:admin123;user:user123;guest:guest123", loginPage.getDemoUsers());
        
        loginPage.setDemoUsers("");
        assertEquals("", loginPage.getDemoUsers());
    }

    @Test
    void testPropertyIndependence() {
        UserAuthenticationProperties properties1 = new UserAuthenticationProperties();
        UserAuthenticationProperties properties2 = new UserAuthenticationProperties();
        
        properties1.setEnabled(true);
        assertFalse(properties2.isEnabled());
        
        properties1.getLoginPage().setTitle("Title 1");
        assertEquals("Identity Provider", properties2.getLoginPage().getTitle());
        
        properties1.getUserRegistry().setType("jdbc");
        assertEquals("in-memory", properties2.getUserRegistry().getType());
    }
}
