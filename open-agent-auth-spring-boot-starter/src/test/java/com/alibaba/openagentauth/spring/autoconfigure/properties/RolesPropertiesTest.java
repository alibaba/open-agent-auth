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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link RolesProperties}.
 *
 * @since 2.0
 */
@SpringBootTest(classes = TestConfiguration.class)
class RolesPropertiesTest {

    @Test
    void testDefaultValues() {
        RolesProperties properties = new RolesProperties();
        
        assertNotNull(properties.getRoles());
        assertTrue(properties.getRoles().isEmpty());
    }

    @Test
    void testGetRole() {
        RolesProperties properties = new RolesProperties();
        
        assertNull(properties.getRole("non-existent"));
        
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8080");
        properties.putRole("test-role", role);
        
        assertEquals(role, properties.getRole("test-role"));
    }

    @Test
    void testPutRole() {
        RolesProperties properties = new RolesProperties();
        
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setIssuer("http://localhost:8080");
        
        properties.putRole("agent", role);
        
        assertEquals(1, properties.getRoles().size());
        assertEquals(role, properties.getRoles().get("agent"));
    }

    @Test
    void testSetRoles() {
        RolesProperties properties = new RolesProperties();
        
        Map<String, RolesProperties.RoleProperties> rolesMap = new HashMap<>();
        
        RolesProperties.RoleProperties role1 = new RolesProperties.RoleProperties();
        role1.setEnabled(true);
        role1.setIssuer("http://localhost:8081");
        rolesMap.put("agent", role1);
        
        RolesProperties.RoleProperties role2 = new RolesProperties.RoleProperties();
        role2.setEnabled(true);
        role2.setIssuer("http://localhost:8082");
        rolesMap.put("agent-idp", role2);
        
        properties.setRoles(rolesMap);
        
        assertEquals(2, properties.getRoles().size());
        assertEquals(role1, properties.getRoles().get("agent"));
        assertEquals(role2, properties.getRoles().get("agent-idp"));
    }

    @Test
    void testSetRolesWithNull() {
        RolesProperties properties = new RolesProperties();
        
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        properties.putRole("test", role);
        
        assertEquals(1, properties.getRoles().size());
        
        properties.setRoles(null);
        
        assertTrue(properties.getRoles().isEmpty());
    }

    @Test
    void testRolePropertiesDefaultValues() {
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        
        assertFalse(role.isEnabled());
        assertNull(role.getInstanceId());
        assertNull(role.getIssuer());
        assertNotNull(role.getCapabilities());
        assertTrue(role.getCapabilities().isEmpty());
        assertNotNull(role.getConfig());
        assertTrue(role.getConfig().isEmpty());
    }

    @Test
    void testRolePropertiesGetterSetter() {
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        
        role.setEnabled(true);
        assertTrue(role.isEnabled());
        
        role.setInstanceId("instance-001");
        assertEquals("instance-001", role.getInstanceId());
        
        role.setIssuer("http://localhost:8080");
        assertEquals("http://localhost:8080", role.getIssuer());
        
        List<String> capabilities = new ArrayList<>();
        capabilities.add("oauth2-client");
        capabilities.add("operation-authorization");
        role.setCapabilities(capabilities);
        assertEquals(capabilities, role.getCapabilities());
        
        Map<String, Object> config = new HashMap<>();
        config.put("custom-key", "custom-value");
        role.setConfig(config);
        assertEquals(config, role.getConfig());
    }

    @Test
    void testBoundaryValues() {
        RolesProperties properties = new RolesProperties();
        
        properties.putRole("", new RolesProperties.RoleProperties());
        assertEquals(1, properties.getRoles().size());
        
        properties.putRole("very-long-role-name-with-many-characters", new RolesProperties.RoleProperties());
        assertEquals(2, properties.getRoles().size());
        
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        role.setInstanceId("");
        role.setIssuer("");
        role.setCapabilities(new ArrayList<>());
        role.setConfig(new HashMap<>());
        
        properties.putRole("test", role);
        assertEquals("", properties.getRole("test").getInstanceId());
        assertEquals("", properties.getRole("test").getIssuer());
    }

    @Test
    void testPropertyIndependence() {
        RolesProperties properties1 = new RolesProperties();
        RolesProperties properties2 = new RolesProperties();
        
        RolesProperties.RoleProperties role = new RolesProperties.RoleProperties();
        role.setEnabled(true);
        properties1.putRole("agent", role);
        
        assertEquals(0, properties2.getRoles().size());
        assertNull(properties2.getRole("agent"));
    }

    @Test
    void testMultipleRoles() {
        RolesProperties properties = new RolesProperties();
        
        RolesProperties.RoleProperties agentRole = new RolesProperties.RoleProperties();
        agentRole.setEnabled(true);
        agentRole.setIssuer("http://localhost:8081");
        agentRole.setCapabilities(List.of("oauth2-client", "operation-authorization"));
        
        RolesProperties.RoleProperties idpRole = new RolesProperties.RoleProperties();
        idpRole.setEnabled(true);
        idpRole.setIssuer("http://localhost:8082");
        idpRole.setCapabilities(List.of("workload-identity"));
        
        RolesProperties.RoleProperties asRole = new RolesProperties.RoleProperties();
        asRole.setEnabled(true);
        asRole.setIssuer("http://localhost:8085");
        asRole.setCapabilities(List.of("oauth2-server", "operation-authorization"));
        
        properties.putRole("agent", agentRole);
        properties.putRole("agent-idp", idpRole);
        properties.putRole("authorization-server", asRole);
        
        assertEquals(3, properties.getRoles().size());
        assertEquals(agentRole, properties.getRole("agent"));
        assertEquals(idpRole, properties.getRole("agent-idp"));
        assertEquals(asRole, properties.getRole("authorization-server"));
    }

    @Test
    void testRoleOverride() {
        RolesProperties properties = new RolesProperties();
        
        RolesProperties.RoleProperties role1 = new RolesProperties.RoleProperties();
        role1.setEnabled(false);
        role1.setIssuer("http://localhost:8081");
        properties.putRole("agent", role1);
        
        RolesProperties.RoleProperties role2 = new RolesProperties.RoleProperties();
        role2.setEnabled(true);
        role2.setIssuer("http://localhost:8082");
        properties.putRole("agent", role2);
        
        assertEquals(1, properties.getRoles().size());
        assertTrue(properties.getRole("agent").isEnabled());
        assertEquals("http://localhost:8082", properties.getRole("agent").getIssuer());
    }
}
