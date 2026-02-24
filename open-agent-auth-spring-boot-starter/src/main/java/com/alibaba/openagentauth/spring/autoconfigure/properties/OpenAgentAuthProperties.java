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
    private AuditProperties audit = new AuditProperties();

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
    public AuditProperties getAudit() {
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
    public void setAudit(AuditProperties audit) {
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

    // ========== Nested Configuration Classes ==========

    /**
     * Security configuration properties.
     * <p>
     * Controls security features including CSRF protection and CORS settings.
     * </p>
     */
    public static class SecurityProperties {
        /**
         * CSRF configuration.
         */
        private CsrfProperties csrf = new CsrfProperties();

        /**
         * CORS configuration.
         */
        private CorsProperties cors = new CorsProperties();

        /**
         * Gets the CSRF configuration.
         *
         * @return the CSRF properties
         */
        public CsrfProperties getCsrf() {
            return csrf;
        }

        /**
         * Sets the CSRF configuration.
         *
         * @param csrf the CSRF properties to set
         */
        public void setCsrf(CsrfProperties csrf) {
            this.csrf = csrf;
        }

        /**
         * Gets the CORS configuration.
         *
         * @return the CORS properties
         */
        public CorsProperties getCors() {
            return cors;
        }

        /**
         * Sets the CORS configuration.
         *
         * @param cors the CORS properties to set
         */
        public void setCors(CorsProperties cors) {
            this.cors = cors;
        }

        /**
         * CSRF configuration properties.
         * <p>
         * Controls Cross-Site Request Forgery protection for the application.
         * </p>
         */
        public static class CsrfProperties {
            /**
             * Whether CSRF protection is enabled.
             * <p>
             * When enabled, the application will generate and validate CSRF tokens
             * to protect against cross-site request forgery attacks.
             * </p>
             */
            private boolean enabled = true;

            /**
             * Gets whether CSRF protection is enabled.
             *
             * @return whether CSRF protection is enabled
             */
            public boolean isEnabled() {
                return enabled;
            }

            /**
             * Sets whether CSRF protection is enabled.
             *
             * @param enabled whether to enable CSRF protection
             */
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }

        /**
         * CORS configuration properties.
         * <p>
         * Controls Cross-Origin Resource Sharing settings for the application.
         * </p>
         */
        public static class CorsProperties {

            /**
             * Whether CORS is enabled.
             * <p>
             * When enabled, the application will allow cross-origin requests
             * based on the configured allowed origins.
             * </p>
             */
            private boolean enabled = false;

            /**
             * Allowed origins for CORS requests.
             * <p>
             * A comma-separated list of origin URLs that are allowed to make
             * cross-origin requests to this application.
             * </p>
             */
            private String allowedOrigins = "";

            /**
             * Gets whether CORS is enabled.
             *
             * @return whether CORS is enabled
             */
            public boolean isEnabled() {
                return enabled;
            }

            /**
             * Sets whether CORS is enabled.
             *
             * @param enabled whether to enable CORS
             */
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }

            /**
             * Gets the allowed origins for CORS requests.
             *
             * @return the comma-separated list of allowed origins
             */
            public String getAllowedOrigins() {
                return allowedOrigins;
            }

            /**
             * Sets the allowed origins for CORS requests.
             *
             * @param allowedOrigins the comma-separated list of allowed origins
             */
            public void setAllowedOrigins(String allowedOrigins) {
                this.allowedOrigins = allowedOrigins;
            }
        }
    }

    /**
     * Audit configuration properties.
     * <p>
     * Controls audit logging functionality for tracking security events,
     * user actions, agent operations, and system activities.
     * </p>
     */
    public static class AuditProperties {

        /**
         * Whether audit logging is enabled.
         * <p>
         * When enabled, the application will log security-relevant events
         * such as authentication, authorization, and data access operations.
         * </p>
         */
        private boolean enabled = false;

        /**
         * Audit provider implementation.
         * <p>
         * Specifies the provider implementation for audit logging.
         * Supported values include "logging" for file-based logging.
         * </p>
         */
        private String provider = "logging";

        /**
         * Gets whether audit logging is enabled.
         *
         * @return whether audit logging is enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether audit logging is enabled.
         *
         * @param enabled whether to enable audit logging
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the audit provider implementation.
         *
         * @return the audit provider name (e.g., "logging")
         */
        public String getProvider() {
            return provider;
        }

        /**
         * Sets the audit provider implementation.
         *
         * @param provider the audit provider name (e.g., "logging")
         */
        public void setProvider(String provider) {
            this.provider = provider;
        }
    }

    /**
     * Monitoring configuration properties.
     * <p>
     * Controls metrics collection and distributed tracing for observability.
     * </p>
     */
    public static class MonitoringProperties {
        /**
         * Metrics configuration.
         * <p>
         * Controls the collection and export of application metrics.
         * </p>
         */
        private MetricsProperties metrics = new MetricsProperties();

        /**
         * Tracing configuration.
         * <p>
         * Controls distributed tracing for request tracking and analysis.
         * </p>
         */
        private TracingProperties tracing = new TracingProperties();

        /**
         * Gets the metrics configuration.
         *
         * @return the metrics properties
         */
        public MetricsProperties getMetrics() {
            return metrics;
        }

        /**
         * Sets the metrics configuration.
         *
         * @param metrics the metrics properties to set
         */
        public void setMetrics(MetricsProperties metrics) {
            this.metrics = metrics;
        }

        /**
         * Gets the tracing configuration.
         *
         * @return the tracing properties
         */
        public TracingProperties getTracing() {
            return tracing;
        }

        /**
         * Sets the tracing configuration.
         *
         * @param tracing the tracing properties to set
         */
        public void setTracing(TracingProperties tracing) {
            this.tracing = tracing;
        }

        /**
         * Metrics configuration properties.
         * <p>
         * Controls application metrics collection and export.
         * </p>
         */
        public static class MetricsProperties {
            /**
             * Whether metrics collection is enabled.
             * <p>
             * When enabled, the application will collect runtime metrics
             * such as request counts, response times, and error rates.
             * </p>
             */
            private boolean enabled = true;

            /**
             * Whether to export metrics to Prometheus.
             * <p>
             * When enabled, metrics will be exposed in Prometheus format
             * at the /actuator/prometheus endpoint.
             * </p>
             */
            private boolean exportPrometheus = true;

            /**
             * Gets whether metrics collection is enabled.
             *
             * @return whether metrics collection is enabled
             */
            public boolean isEnabled() {
                return enabled;
            }

            /**
             * Sets whether metrics collection is enabled.
             *
             * @param enabled whether to enable metrics collection
             */
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }

            /**
             * Gets whether to export metrics to Prometheus.
             *
             * @return whether Prometheus export is enabled
             */
            public boolean isExportPrometheus() {
                return exportPrometheus;
            }

            /**
             * Sets whether to export metrics to Prometheus.
             *
             * @param exportPrometheus whether to enable Prometheus export
             */
            public void setExportPrometheus(boolean exportPrometheus) {
                this.exportPrometheus = exportPrometheus;
            }
        }

        /**
         * Tracing configuration properties.
         * <p>
         * Controls distributed tracing for request tracking.
         * </p>
         */
        public static class TracingProperties {
            /**
             * Whether distributed tracing is enabled.
             * <p>
             * When enabled, the application will generate and export trace spans
             * for distributed request tracking.
             * </p>
             */
            private boolean enabled = false;

            /**
             * Gets whether distributed tracing is enabled.
             *
             * @return whether distributed tracing is enabled
             */
            public boolean isEnabled() {
                return enabled;
            }

            /**
             * Sets whether distributed tracing is enabled.
             *
             * @param enabled whether to enable distributed tracing
             */
            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }
    }
}