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
package com.alibaba.openagentauth.framework.role;

/**
 * Application role enumeration for the Open Agent Auth framework.
 * <p>
 * This enum defines all supported application roles in the Agent Operation Authorization protocol.
 * Each role represents a specific component in the authorization flow with distinct responsibilities.
 * </p>
 *
 * <h3>Role Descriptions:</h3>
 * <ul>
 *   <li><b>AGENT_USER_IDP</b>: Provides user authentication for AI Agent platforms</li>
 *   <li><b>AGENT_IDP</b>: Manages workload identity and issues WIT tokens</li>
 *   <li><b>AS_USER_IDP</b>: Provides user authentication for Authorization Server</li>
 *   <li><b>AUTHORIZATION_SERVER</b>: Handles authorization requests and issues AOAT tokens</li>
 *   <li><b>RESOURCE_SERVER</b>: Hosts protected resources and implements five-layer verification</li>
 *   <li><b>AGENT</b>: Represents AI Agent that acts on behalf of users</li>
 * </ul>
 *
 * @see RoleDetector
 * @since 1.0
 */
public enum ApplicationRole {
    
    /**
     * Agent User Identity Provider.
     * <p>
     * Responsible for authenticating users in the AI Agent platform and issuing ID Tokens.
     * This role is the trust anchor for user identity in the agent context.
     * </p>
     */
    AGENT_USER_IDP("agent-user-idp", "Agent User Identity Provider"),
    
    /**
     * Agent Identity Provider / WIMSE IDP.
     * <p>
     * Manages workload identity and issues Workload Identity Tokens (WIT).
     * Creates virtual workloads for each user request with temporary key pairs.
     * Binds workload identity to user identity for traceability.
     * </p>
     */
    AGENT_IDP("agent-idp", "Agent Identity Provider / WIMSE IDP"),
    
    /**
     * Authorization Server User Identity Provider.
     * <p>
     * Provides user authentication for the Authorization Server's authorization flow.
     * Ensures only legitimate users can approve authorization requests.
     * </p>
     */
    AS_USER_IDP("as-user-idp", "Authorization Server User Identity Provider"),
    
    /**
     * Authorization Server.
     * <p>
     * Handles OAuth 2.0 authorization requests with PAR extension.
     * Issues Agent Operation Authorization Tokens (AOAT).
     * Registers and manages OPA policies for fine-grained access control.
     * Validates identity consistency across the authorization flow.
     * </p>
     */
    AUTHORIZATION_SERVER("authorization-server", "Authorization Server"),
    
    /**
     * Resource Server.
     * <p>
     * Hosts protected resources and implements five-layer verification architecture.
     * Validates WIT, WPT, AOAT tokens and performs identity consistency checks.
     * Evaluates OPA policies for authorization decisions.
     * Records comprehensive audit trails for compliance.
     * </p>
     */
    RESOURCE_SERVER("resource-server", "Resource Server"),
    
    /**
     * AI Agent.
     * <p>
     * Represents AI Agent that acts on behalf of users.
     * Contains AOA Bridge for coordinating authorization flows.
     * Manages token lifecycle and authorization context.
     * Accesses protected resources on behalf of authenticated users.
     * </p>
     */
    AGENT("agent", "AI Agent");
    
    private final String code;
    private final String description;
    
    ApplicationRole(String code, String description) {
        this.code = code;
        this.description = description;
    }
    
    /**
     * Gets the role code used in configuration.
     *
     * @return the role code
     */
    public String getCode() {
        return code;
    }
    
    /**
     * Gets the human-readable description of this role.
     *
     * @return the description
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Finds the role by its code.
     *
     * @param code the role code
     * @return the matching role, or null if not found
     */
    public static ApplicationRole fromCode(String code) {
        if (code == null) {
            return null;
        }
        for (ApplicationRole role : values()) {
            if (role.code.equals(code)) {
                return role;
            }
        }
        return null;
    }
}
