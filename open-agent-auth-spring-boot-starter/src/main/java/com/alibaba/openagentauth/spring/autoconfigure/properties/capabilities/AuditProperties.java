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

import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;

/**
 * Audit capability properties.
 * <p>
 * This class defines configuration for the Audit capability,
 * which provides audit logging functionality for tracking security events,
 * user actions, and system operations across the Open Agent Auth framework.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link CapabilitiesProperties} and bound as part of
 * the {@code open-agent-auth.capabilities.audit} prefix through the parent class hierarchy.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     audit:
 *       enabled: true
 *       provider: logging
 *       endpoints:
 *         event:
 *           retrieve: /api/v1/audit/events/get
 *           list: /api/v1/audit/events/list
 * </pre>
 *
 * @since 2.0
 * @see AuditEndpointsProperties
 */
public class AuditProperties {

    /**
     * Whether Audit capability is enabled.
     * <p>
     * When enabled, the application will log audit events for security-related
     * operations such as authentication, authorization, and policy decisions.
     * </p>
     * <p>
     * Default value: {@code false}
     * </p>
     */
    private boolean enabled = false;

    /**
     * Audit provider implementation.
     * <p>
     * Specifies the backend implementation for storing audit events.
     * Supported providers include:
     * </p>
     * <ul>
     *   <li>{@code logging} - Logs audit events to application logs (default)</li>
     * </ul>
     * <p>
     * Default value: {@code logging}
     * </p>
     */
    private String provider = "logging";

    /**
     * Endpoint configurations for Audit.
     * <p>
     * Defines the REST API endpoints for audit event management,
     * including querying events by various criteria.
     * </p>
     */
    private AuditEndpointsProperties endpoints = new AuditEndpointsProperties();

    /**
     * Gets whether the Audit capability is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the Audit capability is enabled.
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the audit provider.
     *
     * @return the audit provider
     */
    public String getProvider() {
        return provider;
    }

    /**
     * Sets the audit provider.
     *
     * @param provider the audit provider to set
     */
    public void setProvider(String provider) {
        this.provider = provider;
    }

    /**
     * Gets the endpoint configurations.
     *
     * @return the endpoint configurations
     */
    public AuditEndpointsProperties getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the endpoint configurations.
     *
     * @param endpoints the endpoint configurations to set
     */
    public void setEndpoints(AuditEndpointsProperties endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Audit endpoints configuration.
     * <p>
     * This inner class defines REST API endpoints for the Audit capability,
     * including querying events by ID and time range.
     * </p>
     */
    public static class AuditEndpointsProperties {

        /**
         * Audit REST API endpoint configurations.
         * <p>
         * This nested class contains the specific endpoint paths for audit operations
         * such as getting events by ID and listing events.
         * </p>
         */
        private EventEndpointPaths event = new EventEndpointPaths();

        /**
         * Gets the event endpoint paths.
         *
         * @return the event endpoint paths
         */
        public EventEndpointPaths getEvent() {
            return event;
        }

        /**
         * Sets the event endpoint paths.
         *
         * @param event the event endpoint paths to set
         */
        public void setEvent(EventEndpointPaths event) {
            this.event = event;
        }

        /**
         * Event endpoint paths configuration.
         * <p>
         * This inner class defines the specific REST API endpoint paths for
         * audit event operations.
         * </p>
         */
        public static class EventEndpointPaths {

            /**
             * Retrieve audit event endpoint path.
             * <p>
             * Retrieves a specific audit event by its unique identifier.
             * </p>
             * <p>
             * Default value: {@code /api/v1/audit/events/get}
             * </p>
             */
            private String retrieve = "/api/v1/audit/events/get";

            /**
             * List audit events endpoint path.
             * <p>
             * Retrieves audit events, optionally filtered by criteria.
             * </p>
             * <p>
             * Default value: {@code /api/v1/audit/events/list}
             * </p>
             */
            private String list = "/api/v1/audit/events/list";

            /**
             * Gets the retrieve audit event endpoint path.
             *
             * @return the retrieve audit event endpoint path
             */
            public String getRetrieve() {
                return retrieve;
            }

            /**
             * Sets the retrieve audit event endpoint path.
             *
             * @param retrieve the retrieve audit event endpoint path to set
             */
            public void setRetrieve(String retrieve) {
                this.retrieve = retrieve;
            }

            /**
             * Gets the list audit events endpoint path.
             *
             * @return the list audit events endpoint path
             */
            public String getList() {
                return list;
            }

            /**
             * Sets the list audit events endpoint path.
             *
             * @param list the list audit events endpoint path to set
             */
            public void setList(String list) {
                this.list = list;
            }
        }
    }
}
