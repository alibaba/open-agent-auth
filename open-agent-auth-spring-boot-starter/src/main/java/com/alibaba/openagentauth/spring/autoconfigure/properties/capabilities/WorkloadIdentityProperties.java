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
 * Workload Identity capability properties.
 * <p>
 * This class defines configuration for the Workload Identity capability,
 * which provides workload identity management and token issuance for
 * applications and services.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link CapabilitiesProperties} and bound as part of
 * the {@code open-agent-auth.capabilities.workload-identity} prefix through the parent class hierarchy.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     workload-identity:
 *       enabled: true
 *       endpoints:
 *         workload:
 *           revoke: /api/v1/workloads/revoke
 *           retrieve: /api/v1/workloads/get
 *           issue: /api/v1/workloads/token/issue
 * </pre>
 *
 * @since 2.0
 * @see WorkloadIdentityEndpointsProperties
 */
public class WorkloadIdentityProperties {

    /**
     * Whether Workload Identity capability is enabled.
     * <p>
     * When enabled, the application can manage workload identities and issue
     * workload-specific tokens for applications and services.
     * </p>
     * <p>
     * Default value: {@code false}
     * </p>
     */
    private boolean enabled = false;

    /**
     * Endpoint configurations for Workload Identity.
     * <p>
     * Defines the REST API endpoints for workload identity management,
     * including creating, issuing, revoking, and querying workloads.
     * </p>
     */
    private WorkloadIdentityEndpointsProperties endpoints = new WorkloadIdentityEndpointsProperties();

    /**
     * Gets whether the Workload Identity capability is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the Workload Identity capability is enabled.
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the endpoint configurations.
     *
     * @return the endpoint configurations
     */
    public WorkloadIdentityEndpointsProperties getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the endpoint configurations.
     *
     * @param endpoints the endpoint configurations to set
     */
    public void setEndpoints(WorkloadIdentityEndpointsProperties endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Workload Identity endpoints configuration.
     * <p>
     * This inner class defines all REST API endpoints for the Workload Identity capability,
     * including workload creation, token issuance, revocation, and querying.
     * </p>
     */
    public static class WorkloadIdentityEndpointsProperties {

        /**
         * Workload REST API endpoint configurations.
         * <p>
         * This nested class contains the specific endpoint paths for workload identity
         * operations such as create, issue, revoke, and get.
         * </p>
         */
        private WorkloadEndpointPaths workload = new WorkloadEndpointPaths();

        /**
         * Gets the workload endpoint paths.
         *
         * @return the workload endpoint paths
         */
        public WorkloadEndpointPaths getWorkload() {
            return workload;
        }

        /**
         * Sets the workload endpoint paths.
         *
         * @param workload the workload endpoint paths to set
         */
        public void setWorkload(WorkloadEndpointPaths workload) {
            this.workload = workload;
        }

        /**
         * Workload endpoint paths configuration.
         * <p>
         * This inner class defines the specific REST API endpoint paths for
         * workload identity management operations.
         * </p>
         */
        public static class WorkloadEndpointPaths {

            /**
             * Revoke workload endpoint path.
             * <p>
             * Revokes a workload identity and invalidates all associated tokens.
             * </p>
             * <p>
             * Default value: {@code /api/v1/workloads/revoke}
             * </p>
             */
            private String revoke = "/api/v1/workloads/revoke";

            /**
             * Retrieve workload endpoint path.
             * <p>
             * Retrieves information about a specific workload identity.
             * </p>
             * <p>
             * Default value: {@code /api/v1/workloads/get}
             * </p>
             */
            private String retrieve = "/api/v1/workloads/get";

            /**
             * Issue workload token endpoint path.
             * <p>
             * Issues a token for a workload identity without requiring the full
             * workload identity to be created first.
             * </p>
             * <p>
             * Default value: {@code /api/v1/workloads/token/issue}
             * </p>
             */
            private String issue = "/api/v1/workloads/token/issue";

            /**
             * Gets the revoke workload endpoint path.
             *
             * @return the revoke workload endpoint path
             */
            public String getRevoke() {
                return revoke;
            }

            /**
             * Sets the revoke workload endpoint path.
             *
             * @param revoke the revoke workload endpoint path to set
             */
            public void setRevoke(String revoke) {
                this.revoke = revoke;
            }

            /**
             * Gets the retrieve workload endpoint path.
             *
             * @return the retrieve workload endpoint path
             */
            public String getRetrieve() {
                return retrieve;
            }

            /**
             * Sets the retrieve workload endpoint path.
             *
             * @param retrieve the retrieve workload endpoint path to set
             */
            public void setRetrieve(String retrieve) {
                this.retrieve = retrieve;
            }

            /**
             * Gets the issue workload token endpoint path.
             *
             * @return the issue workload token endpoint path
             */
            public String getIssue() {
                return issue;
            }

            /**
             * Sets the issue workload token endpoint path.
             *
             * @param issue the issue workload token endpoint path to set
             */
            public void setIssue(String issue) {
                this.issue = issue;
            }
        }
    }
}