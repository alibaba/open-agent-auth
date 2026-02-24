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

import java.util.HashMap;
import java.util.Map;

/**
 * Roles configuration properties for the Open Agent Auth framework.
 * <p>
 * This class defines role-level configurations that compose capabilities
 * to create specific functional roles (e.g., authorization-server, agent, idp).
 * </p>
 * <p>
 * This class uses composition instead of inheritance, allowing configuration like:
 * <pre>
 * open-agent-auth:
 *   roles:
 *     agent-idp:
 *       enabled: true
 *       instance-id: agent-idp-1
 *       issuer: http://localhost:8082
 *     agent:
 *       enabled: true
 *       instance-id: agent-1
 *       issuer: http://localhost:8081
 * </pre>
 * <p>
 * <b>Note:</b> The capabilities that each role requires are determined by the
 * {@code open-agent-auth.capabilities.xxx.enabled} properties, not by a list
 * on the role itself. The framework's {@code ConfigurationValidator} uses a
 * built-in mapping to verify that each enabled role has its required capabilities
 * also enabled. This design follows the DRY principle — capabilities are configured
 * once at the capability level and validated automatically.
 * </p>
  *
 * @since 2.0
 */
public class RolesProperties {

    /**
     * Map of role configurations keyed by role name.
     * <p>
     * The role name serves as the key in the configuration hierarchy.
     * For example, configuration under {@code open-agent-auth.roles.agent-user-idp}
     * will be bound to a RoleProperties instance stored under the key "agent-user-idp".
     * </p>
     */
    private final Map<String, RoleProperties> roles = new HashMap<>();

    /**
     * Get a role configuration by name.
     *
     * @param roleName the role name (e.g., "agent-idp", "agent", "authorization-server")
     * @return the role properties, or null if not found
     */
    public RoleProperties getRole(String roleName) {
        return roles.get(roleName);
    }

    /**
     * Add or update a role configuration.
     *
     * @param roleName the role name
     * @param roleProperties the role properties
     */
    public void putRole(String roleName, RoleProperties roleProperties) {
        roles.put(roleName, roleProperties);
    }

    /**
     * Get all roles as a map.
     *
     * @return the map of role name to role properties
     */
    public Map<String, RoleProperties> getRoles() {
        return roles;
    }

    /**
     * Set all roles.
     * <p>
     * This method is called by Spring Boot during configuration binding when
     * binding to the {@code roles} field of {@code OpenAgentAuthProperties}.
     * The configuration under {@code open-agent-auth.roles.*} will be bound to this map.
     * </p>
     *
     * @param roles the map of role name to role properties
     */
    public void setRoles(Map<String, RoleProperties> roles) {
        this.roles.clear();
        if (roles != null) {
            this.roles.putAll(roles);
        }
    }

    /**
     * Role configuration properties.
     */
    public static class RoleProperties {

        /**
         * Whether this role is enabled.
         */
        private boolean enabled = false;

        /**
         * Instance identifier for this role (supports multiple instances).
         */
        private String instanceId;

        /**
         * Issuer URL for this role instance.
         */
        private String issuer;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getInstanceId() {
            return instanceId;
        }

        public void setInstanceId(String instanceId) {
            this.instanceId = instanceId;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

    }
}