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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.HashMap;
import java.util.Map;

/**
 * Root configuration properties for Open Agent Auth framework.
 * <p>
 * This class defines the top-level configuration properties for:
 * <ul>
 *   <li>Infrastructure: Shared infrastructure (trust domain, keys, JWKS, service discovery)</li>
 *   <li>Capabilities: Functional features that can be composed by roles</li>
 *   <li>Roles: Role instances that compose capabilities with role-specific overrides</li>
 *   <li>Security: CSRF and CORS configuration</li>
 *   <li>Audit: Audit logging configuration</li>
 *   <li>Monitoring: Metrics and tracing configuration</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   infrastructures:
 *     trust-domain: wimse://default.trust.domain
 *     jwks: {...}
 *   capabilities:
 *     oauth2-server: {...}
 *     operation-authorization: {...}
 *   roles:
 *     authorization-server:
 *       enabled: true
 *       issuer: http://localhost:8085
 *       capabilities:
 *         - oauth2-server
 *         - operation-authorization
 *   security:
 *     csrf:
 *       enabled: true
 *     cors:
 *       enabled: false
 *   audit:
 *     enabled: false
 *     provider: logging
 *   monitoring:
 *     metrics:
 *       enabled: true
 *       export-prometheus: true
 *     tracing:
 *       enabled: false
 * </pre>
 *
 * @since 1.0
 */
@ConfigurationProperties(prefix = "open-agent-auth")
public class OpenAgentAuthProperties {

    /**
     * Whether Open Agent Auth is enabled.
     */
    private boolean enabled = true;

    /**
     * Infrastructure configuration (shared across all roles).
     */
    @NestedConfigurationProperty
    private InfrastructureProperties infrastructures = new InfrastructureProperties();

    /**
     * Capabilities configuration (composable functional features).
     */
    @NestedConfigurationProperty
    private CapabilitiesProperties capabilities = new CapabilitiesProperties();

    /**
     * Roles configuration (role instances that compose capabilities).
     * <p>
     * Map of role configurations keyed by role name.
     * For example, configuration under {@code open-agent-auth.roles.agent-user-idp}
     * will be bound to a RoleProperties instance stored under the key "agent-user-idp".
     * </p>
     */
    private Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();

    /**
     * Security configuration.
     */
    private SecurityProperties security = new SecurityProperties();

    /**
     * Audit configuration.
     */
    private OpenAgentAuthAuditProperties audit = new OpenAgentAuthAuditProperties();

    /**
     * Monitoring configuration.
     */
    private MonitoringProperties monitoring = new MonitoringProperties();

    // ========== Getters and Setters ==========

    /**
     * Gets whether Open Agent Auth is enabled.
     *
     * @return whether Open Agent Auth is enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether Open Agent Auth is enabled.
     *
     * @param enabled whether Open Agent Auth is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the infrastructure configuration.
     * <p>
     * This configuration defines the shared infrastructure components used across all roles,
     * including trust domain, key management, JWKS, and service discovery.
     * </p>
     *
     * @return the infrastructure properties
     */
    public InfrastructureProperties getInfrastructures() {
        return infrastructures;
    }

    /**
     * Sets the infrastructure configuration.
     * <p>
     * This configuration controls the shared infrastructure components that are
     * used by all roles in the framework.
     * </p>
     *
     * @param infrastructures the infrastructure properties to set
     */
    public void setInfrastructures(InfrastructureProperties infrastructures) {
        this.infrastructures = infrastructures;
    }

    /**
     * Gets the capabilities configuration.
     * <p>
     * This configuration defines the functional features that can be composed by roles.
     * Each capability represents an independent feature that can be enabled or disabled.
     * </p>
     *
     * @return the capabilities properties
     */
    public CapabilitiesProperties getCapabilities() {
        return capabilities;
    }

    /**
     * Sets the capabilities configuration.
     * <p>
     * This configuration defines the functional features available for composition by roles.
     * </p>
     *
     * @param capabilities the capabilities properties to set
     */
    public void setCapabilities(CapabilitiesProperties capabilities) {
        this.capabilities = capabilities;
    }

    /**
     * Gets the roles configuration map.
     * <p>
     * This map contains role-specific configurations keyed by role name.
     * Each role composes a set of capabilities with role-specific overrides.
     * </p>
     *
     * @return the map of role name to role properties
     */
    public Map<String, RolesProperties.RoleProperties> getRoles() {
        return roles;
    }

    /**
     * Sets the roles configuration map.
     * <p>
     * This map defines role instances that compose capabilities with role-specific
     * configuration overrides. The existing roles are cleared before setting new ones.
     * </p>
     *
     * @param roles the map of role name to role properties to set
     */
    public void setRoles(Map<String, RolesProperties.RoleProperties> roles) {
        this.roles.clear();
        if (roles != null) {
            this.roles.putAll(roles);
        }
    }

    /**
     * Gets the security configuration.
     * <p>
     * This configuration defines security features including CSRF protection and CORS.
     * </p>
     *
     * @return the security properties
     */
    public SecurityProperties getSecurity() {
        return security;
    }

    /**
     * Sets the security configuration.
     * <p>
     * This configuration controls security features such as CSRF protection and CORS settings.
     * </p>
     *
     * @param security the security properties to set
     */
    public void setSecurity(SecurityProperties security) {
        this.security = security;
    }

    /**
     * Gets the audit configuration.
     * <p>
     * This configuration defines audit logging settings for tracking security events
     * and system activities.
     * </p>
     *
     * @return the audit properties
     */
    public OpenAgentAuthAuditProperties getAudit() {
        return audit;
    }

    /**
     * Sets the audit configuration.
     * <p>
     * This configuration controls audit logging functionality for security and compliance.
     * </p>
     *
     * @param audit the audit properties to set
     */
    public void setAudit(OpenAgentAuthAuditProperties audit) {
        this.audit = audit;
    }

    /**
     * Gets the monitoring configuration.
     * <p>
     * This configuration defines metrics and tracing settings for observability.
     * </p>
     *
     * @return the monitoring properties
     */
    public MonitoringProperties getMonitoring() {
        return monitoring;
    }

    /**
     * Sets the monitoring configuration.
     * <p>
     * This configuration controls metrics collection and distributed tracing for observability.
     * </p>
     *
     * @param monitoring the monitoring properties to set
     */
    public void setMonitoring(MonitoringProperties monitoring) {
        this.monitoring = monitoring;
    }

}