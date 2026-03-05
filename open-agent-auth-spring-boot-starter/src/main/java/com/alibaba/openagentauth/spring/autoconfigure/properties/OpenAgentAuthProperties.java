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

import com.alibaba.openagentauth.spring.autoconfigure.discovery.RoleAwareEnvironmentPostProcessor;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDefinitionProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
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
 *     oauth2-server:
 *       enabled: true
 *     operation-authorization:
 *       enabled: true
 *   roles:
 *     authorization-server:
 *       enabled: true
 *       issuer: http://localhost:8085
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
public class OpenAgentAuthProperties implements InitializingBean {

    /**
     * Logger for the Open Agent Auth properties.
     */
    private static final Logger logger = LoggerFactory.getLogger(OpenAgentAuthProperties.class);

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
     * Roles configuration (role instances).
     * <p>
     * Map of role configurations keyed by role name.
     * For example, configuration under {@code open-agent-auth.roles.agent-user-idp}
     * will be bound to a RoleProperties instance stored under the key "agent-user-idp".
     * </p>
     * <p>
     * Each role defines its identity (enabled, instance-id, issuer) but does not
     * declare which capabilities it uses. The required capabilities for each role
     * are determined by the framework's built-in mapping in {@code ConfigurationValidator},
     * and are activated via {@code open-agent-auth.capabilities.xxx.enabled=true}.
     * </p>
     */
    private Map<String, RolesProperties.RoleProperties> roles = new HashMap<>();

    /**
     * Peer service configurations.
     * <p>
     * Peers represent other services in the trust domain that this service
     * needs to communicate with. Declaring a peer automatically configures:
     * <ul>
     *   <li>JWKS consumer for fetching the peer's public keys</li>
     *   <li>Service discovery entry for the peer's base URL</li>
     * </ul>
     * This eliminates the need to separately configure {@code jwks.consumers}
     * and {@code service-discovery.services} for the same service.
     * </p>
     * <p>
     * <b>Configuration Example:</b></p>
     * <pre>
     * open-agent-auth:
     *   peers:
     *     agent-idp:
     *       issuer: http://localhost:8082
     *     authorization-server:
     *       issuer: http://localhost:8085
     * </pre>
     */
    private Map<String, PeerProperties> peers = new HashMap<>();

    /**
     * Security configuration.
     */
    private SecurityProperties security = new SecurityProperties();

    /**
     * Monitoring configuration.
     */
    private MonitoringProperties monitoring = new MonitoringProperties();

    /**
     * Admin console configuration.
     * <p>
     * Controls whether the admin UI is enabled and how access to admin endpoints
     * is protected. The admin console is disabled by default to follow the
     * principle of least privilege.
     * </p>
     */
    @NestedConfigurationProperty
    private AdminProperties admin = new AdminProperties();

    /**
     * Called by Spring after all properties have been bound.
     * <p>
     * Triggers role-aware configuration inference to fill in missing infrastructure
     * configuration (keys, JWKS consumers, service-discovery entries) based on the
     * enabled roles and declared peers. This ensures all inferred defaults are
     * available before any beans that depend on the configuration are created.
     * </p>
     * <p>
     * Since the YAML configuration has been refactored to use {@code peers} instead of
     * directly configuring {@code infrastructures.key-management.keys} etc., the nested
     * maps under {@code infrastructures} are expected to be empty at this point. The
     * inference logic populates them from {@code peers} and {@code roles}.
     * </p>
     */
    @Override
    public void afterPropertiesSet() {
        if (enabled) {
            logger.info("OpenAgentAuthProperties initialized, triggering role-aware configuration inference");
            new RoleAwareEnvironmentPostProcessor(this).processConfiguration();
        }
    }

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
     * Gets the peer service configurations.
     *
     * @return the map of peer name to peer properties
     */
    public Map<String, PeerProperties> getPeers() {
        return peers;
    }

    /**
     * Sets the peer service configurations.
     *
     * @param peers the map of peer name to peer properties to set
     */
    public void setPeers(Map<String, PeerProperties> peers) {
        this.peers.clear();
        if (peers != null) {
            this.peers.putAll(peers);
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

    /**
     * Gets the admin console configuration.
     * <p>
     * This configuration controls whether the admin UI is enabled and how
     * access to admin endpoints is protected.
     * </p>
     *
     * @return the admin properties
     */
    public AdminProperties getAdmin() {
        return admin;
    }

    /**
     * Sets the admin console configuration.
     *
     * @param admin the admin properties to set
     */
    public void setAdmin(AdminProperties admin) {
        this.admin = admin;
    }

    // ========== Convenience Accessors ==========
    // These methods reduce deep chaining (e.g., 6-layer getter chains) to a single call,
    // improving readability and adhering to the Law of Demeter.

    /**
     * Gets the trust domain string from infrastructure configuration.
     *
     * @return the trust domain URI, or the default value if not configured
     */
    public String getTrustDomain() {
        return infrastructures.getTrustDomain();
    }

    /**
     * Gets a key definition by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getKeyManagement().getKeys().get(keyName)}
     * </p>
     *
     * @param keyName the logical key name (e.g., {@code "par-jwt-signing"})
     * @return the key definition properties, or {@code null} if not found
     */
    public KeyDefinitionProperties getKeyDefinition(String keyName) {
        return infrastructures.getKeyManagement().getKeys().get(keyName);
    }

    /**
     * Gets a service definition by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getServiceDiscovery().getServices().get(serviceName)}
     * </p>
     *
     * @param serviceName the logical service name (e.g., {@code "authorization-server"})
     * @return the service definition properties, or {@code null} if not found
     */
    public ServiceDefinitionProperties getServiceDefinition(String serviceName) {
        return infrastructures.getServiceDiscovery().getServices().get(serviceName);
    }

    /**
     * Gets the base URL of a service by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getServiceDiscovery().getServices().get(serviceName).getBaseUrl()}
     * </p>
     *
     * @param serviceName the logical service name (e.g., {@code "authorization-server"})
     * @return the base URL, or {@code null} if the service is not found
     */
    public String getServiceUrl(String serviceName) {
        ServiceDefinitionProperties service = getServiceDefinition(serviceName);
        return service != null ? service.getBaseUrl() : null;
    }

    /**
     * Gets a JWKS consumer configuration by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getJwks().getConsumers().get(consumerName)}
     * </p>
     *
     * @param consumerName the logical consumer name (e.g., {@code "agent-idp"})
     * @return the JWKS consumer properties, or {@code null} if not found
     */
    public JwksConsumerProperties getJwksConsumer(String consumerName) {
        return infrastructures.getJwks().getConsumers().get(consumerName);
    }

    /**
     * Gets a role configuration by its logical name.
     * <p>
     * This is a convenience method for {@code getRoles().get(roleName)}.
     * </p>
     *
     * @param roleName the logical role name (e.g., {@code "agent"})
     * @return the role properties, or {@code null} if not found
     */
    public RolesProperties.RoleProperties getRole(String roleName) {
        return roles.get(roleName);
    }

    /**
     * Gets the issuer URL for a given role.
     * <p>
     * This is a convenience method that replaces the common pattern:
     * {@code getRoles().get(roleName).getIssuer()}
     * </p>
     *
     * @param roleName the logical role name (e.g., {@code "agent"})
     * @return the issuer URL, or {@code null} if the role is not found
     */
    public String getRoleIssuer(String roleName) {
        RolesProperties.RoleProperties role = getRole(roleName);
        return role != null ? role.getIssuer() : null;
    }

}