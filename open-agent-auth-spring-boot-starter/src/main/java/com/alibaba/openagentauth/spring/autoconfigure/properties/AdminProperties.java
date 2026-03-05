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

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the Admin Console.
 * <p>
 * Controls whether the admin UI is enabled and how access to admin endpoints
 * is protected. By default, the admin console is <b>disabled</b> to follow
 * the principle of least privilege — it must be explicitly enabled by the
 * application operator.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   admin:
 *     enabled: true
 *     access-control:
 *       enabled: true
 *       allowed-session-subjects:
 *         - admin
 *         - operator
 *     endpoints:
 *       dashboard: /admin
 *       workloads: /admin/workloads
 *       bindings: /admin/bindings
 *       policies: /admin/policies
 *       audit: /admin/audit
 * </pre>
 *
 * @since 1.0
 */
public class AdminProperties {

    /**
     * Whether the admin console is enabled.
     * <p>
     * When {@code false} (default), all admin UI controllers and endpoints are
     * excluded from the application context. This ensures that admin functionality
     * is not accidentally exposed in production environments.
     * </p>
     */
    private boolean enabled = false;

    /**
     * Access control configuration for admin endpoints.
     */
    private AccessControlProperties accessControl = new AccessControlProperties();

    /**
     * Admin endpoint path configuration.
     */
    private EndpointProperties endpoints = new EndpointProperties();

    /**
     * Gets whether the admin console is enabled.
     *
     * @return whether the admin console is enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the admin console is enabled.
     *
     * @param enabled whether to enable the admin console
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the access control configuration.
     *
     * @return the access control properties
     */
    public AccessControlProperties getAccessControl() {
        return accessControl;
    }

    /**
     * Sets the access control configuration.
     *
     * @param accessControl the access control properties to set
     */
    public void setAccessControl(AccessControlProperties accessControl) {
        this.accessControl = accessControl;
    }

    /**
     * Gets the endpoint path configuration.
     *
     * @return the endpoint properties
     */
    public EndpointProperties getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the endpoint path configuration.
     *
     * @param endpoints the endpoint properties to set
     */
    public void setEndpoints(EndpointProperties endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Access control configuration for admin endpoints.
     * <p>
     * When enabled, only authenticated users whose session subject matches one of
     * the {@code allowedSessionSubjects} are permitted to access admin pages.
     * This provides a lightweight, session-based access control mechanism that
     * integrates naturally with the framework's existing user authentication flow.
     * </p>
     * <p>
     * If access control is enabled but no subjects are configured, all admin
     * endpoints will be denied by default (fail-closed behavior).
     * </p>
     */
    public static class AccessControlProperties {

        /**
         * Whether access control is enabled for admin endpoints.
         * <p>
         * When {@code true}, admin endpoints require an authenticated session
         * with a subject that matches one of the {@code allowedSessionSubjects}.
         * When {@code false}, admin endpoints are accessible without authentication
         * (not recommended for production).
         * </p>
         */
        private boolean enabled = true;

        /**
         * List of session subjects (user identifiers) allowed to access admin endpoints.
         * <p>
         * These subjects are matched against the authenticated user's subject stored
         * in the HTTP session. The subject is typically set during the OAuth 2.0
         * authorization flow when the user authenticates.
         * </p>
         * <p>
         * If this list is empty and access control is enabled, no users will be
         * able to access admin endpoints (fail-closed).
         * </p>
         */
        private List<String> allowedSessionSubjects = new ArrayList<>();

        /**
         * Gets whether access control is enabled.
         *
         * @return whether access control is enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether access control is enabled.
         *
         * @param enabled whether to enable access control
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the list of allowed session subjects.
         *
         * @return the list of allowed session subjects
         */
        public List<String> getAllowedSessionSubjects() {
            return allowedSessionSubjects;
        }

        /**
         * Sets the list of allowed session subjects.
         *
         * @param allowedSessionSubjects the list of allowed session subjects
         */
        public void setAllowedSessionSubjects(List<String> allowedSessionSubjects) {
            this.allowedSessionSubjects = allowedSessionSubjects;
        }
    }

    /**
     * Admin endpoint path configuration.
     * <p>
     * Allows customization of the URL paths for each admin page.
     * </p>
     */
    public static class EndpointProperties {

        private String dashboard = "/admin";
        private String workloads = "/admin/workloads";
        private String bindings = "/admin/bindings";
        private String policies = "/admin/policies";
        private String audit = "/admin/audit";

        public String getDashboard() {
            return dashboard;
        }

        public void setDashboard(String dashboard) {
            this.dashboard = dashboard;
        }

        public String getWorkloads() {
            return workloads;
        }

        public void setWorkloads(String workloads) {
            this.workloads = workloads;
        }

        public String getBindings() {
            return bindings;
        }

        public void setBindings(String bindings) {
            this.bindings = bindings;
        }

        public String getPolicies() {
            return policies;
        }

        public void setPolicies(String policies) {
            this.policies = policies;
        }

        public String getAudit() {
            return audit;
        }

        public void setAudit(String audit) {
            this.audit = audit;
        }
    }
}
