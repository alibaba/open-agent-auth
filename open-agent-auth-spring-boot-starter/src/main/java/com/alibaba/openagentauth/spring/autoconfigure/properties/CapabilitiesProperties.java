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

import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.AuditProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OperationAuthorizationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.UserAuthenticationProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.WorkloadIdentityProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Capabilities configuration properties for the Open Agent Auth framework.
 * <p>
 * This class defines capability-level configurations that can be composed by roles.
 * Each capability represents a functional feature that can be enabled/disabled independently.
 * </p>
 * <p>
 * <b>Capabilities Overview:</b></p>
 * <ul>
 *   <li><b>OAuth2 Server</b> - Provides OAuth 2.0 authorization server functionality</li>
 *   <li><b>OAuth2 Client</b> - Provides OAuth 2.0 client functionality for authentication</li>
 *   <li><b>Workload Identity</b> - Manages workload identities and token issuance</li>
 *   <li><b>Operation Authorization</b> - Provides fine-grained authorization for agent operations</li>
 *   <li><b>User Authentication</b> - Provides user identity authentication and login page</li>
 *   <li><b>Audit</b> - Provides audit logging for security and compliance</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     oauth2-server:
 *       enabled: true
 *       endpoints:
 *         authorize: /oauth2/authorize
 *         token: /oauth2/token
 *     oauth2-client:
 *       enabled: true
 *       authentication:
 *         enabled: true
 *     operation-authorization:
 *       enabled: true
 *       prompt-encryption:
 *         enabled: true
 *     workload-identity:
 *       enabled: true
 *     user-authentication:
 *       enabled: true
 *     audit:
 *       enabled: true
 *       provider: logging
 * </pre>
 *
 * @since 1.0
 * @see OAuth2ServerProperties
 * @see OAuth2ClientProperties
 * @see WorkloadIdentityProperties
 * @see OperationAuthorizationProperties
 * @see UserAuthenticationProperties
 * @see AuditProperties
 */
@ConfigurationProperties(prefix = "open-agent-auth.capabilities")
public class CapabilitiesProperties {

    /**
     * OAuth 2.0 Server capability configuration.
     * <p>
     * Provides OAuth 2.0 authorization server functionality including authorization flows,
     * token issuance, and client management.
     * </p>
     */
    private OAuth2ServerProperties oauth2Server = new OAuth2ServerProperties();

    /**
     * OAuth 2.0 Client capability configuration.
     * <p>
     * Provides OAuth 2.0 client functionality for authenticating users and obtaining
     * tokens from authorization servers.
     * </p>
     */
    private OAuth2ClientProperties oauth2Client = new OAuth2ClientProperties();

    /**
     * Workload Identity capability configuration.
     * <p>
     * Provides workload identity management and token issuance for applications and services.
     * </p>
     */
    private WorkloadIdentityProperties workloadIdentity = new WorkloadIdentityProperties();

    /**
     * Operation Authorization capability configuration.
     * <p>
     * Provides fine-grained authorization for agent operations including prompt protection
     * and policy evaluation.
     * </p>
     */
    private OperationAuthorizationProperties operationAuthorization = new OperationAuthorizationProperties();

    /**
     * User Authentication capability configuration.
     * <p>
     * Provides user identity authentication including login page, user registry,
     * and session management.
     * </p>
     */
    private UserAuthenticationProperties userAuthentication = new UserAuthenticationProperties();

    /**
     * Audit capability configuration.
     * <p>
     * Provides audit logging functionality for tracking security events,
     * user actions, agent operations, and system activities.
     * </p>
     */
    private AuditProperties audit = new AuditProperties();

    /**
     * Gets the OAuth 2.0 Server capability configuration.
     *
     * @return the OAuth 2.0 Server capability configuration
     */
    public OAuth2ServerProperties getOAuth2Server() {
        return oauth2Server;
    }

    /**
     * Sets the OAuth 2.0 Server capability configuration.
     *
     * @param oauth2Server the OAuth 2.0 Server capability configuration to set
     */
    public void setOAuth2Server(OAuth2ServerProperties oauth2Server) {
        this.oauth2Server = oauth2Server;
    }

    /**
     * Gets the OAuth 2.0 Client capability configuration.
     *
     * @return the OAuth 2.0 Client capability configuration
     */
    public OAuth2ClientProperties getOAuth2Client() {
        return oauth2Client;
    }

    /**
     * Sets the OAuth 2.0 Client capability configuration.
     *
     * @param oauth2Client the OAuth 2.0 Client capability configuration to set
     */
    public void setOAuth2Client(OAuth2ClientProperties oauth2Client) {
        this.oauth2Client = oauth2Client;
    }

    /**
     * Gets the Workload Identity capability configuration.
     *
     * @return the Workload Identity capability configuration
     */
    public WorkloadIdentityProperties getWorkloadIdentity() {
        return workloadIdentity;
    }

    /**
     * Sets the Workload Identity capability configuration.
     *
     * @param workloadIdentity the Workload Identity capability configuration to set
     */
    public void setWorkloadIdentity(WorkloadIdentityProperties workloadIdentity) {
        this.workloadIdentity = workloadIdentity;
    }

    /**
     * Gets the Operation Authorization capability configuration.
     *
     * @return the Operation Authorization capability configuration
     */
    public OperationAuthorizationProperties getOperationAuthorization() {
        return operationAuthorization;
    }

    /**
     * Sets the Operation Authorization capability configuration.
     *
     * @param operationAuthorization the Operation Authorization capability configuration to set
     */
    public void setOperationAuthorization(OperationAuthorizationProperties operationAuthorization) {
        this.operationAuthorization = operationAuthorization;
    }

    /**
     * Gets the User Authentication capability configuration.
     *
     * @return the User Authentication capability configuration
     */
    public UserAuthenticationProperties getUserAuthentication() {
        return userAuthentication;
    }

    /**
     * Sets the User Authentication capability configuration.
     *
     * @param userAuthentication the User Authentication capability configuration to set
     */
    public void setUserAuthentication(UserAuthenticationProperties userAuthentication) {
        this.userAuthentication = userAuthentication;
    }

    /**
     * Gets the Audit capability configuration.
     *
     * @return the Audit capability configuration
     */
    public AuditProperties getAudit() {
        return audit;
    }

    /**
     * Sets the Audit capability configuration.
     *
     * @param audit the Audit capability configuration to set
     */
    public void setAudit(AuditProperties audit) {
        this.audit = audit;
    }
}