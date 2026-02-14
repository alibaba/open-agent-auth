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
package com.alibaba.openagentauth.framework.model.request;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.model.workload.WorkloadRequestContext;
import com.alibaba.openagentauth.framework.executor.config.AgentAapExecutorConfig;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Request for generating an authorization URL for agent operation authorization.
 * <p>
 * This class encapsulates the runtime parameters needed to initiate the OAuth 2.0
 * authorization flow with Pushed Authorization Requests (PAR) according to RFC 9126.
 * Configuration parameters (client_id, redirect_uri, channel, etc.) are managed
 * through {@link AgentAapExecutorConfig}.
 * </p>
 * <p>
 * <b>Design Philosophy:</b></p>
 * This request follows the separation of concerns principle:
 * <ul>
 *   <li><b>Identity Parameters (Required):</b> User authentication and session data</li>
 *   <li><b>Business Context (Required):</b> Operation-specific data encapsulated in {@link WorkloadRequestContext}</li>
 *   <li><b>Input Parameter (Required):</b> User's original natural language input for evidence generation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Required Parameters:</b></p>
 * <ul>
 *   <li><b>userIdentityToken:</b> User's ID Token from Agent User IDP for identity validation</li>
 *   <li><b>userOriginalInput:</b> User's original natural language input for evidence generation</li>
 *   <li><b>workloadContext:</b> Workload context containing operationType, resourceId, and metadata</li>
 * </ul>
 * <p>
 * <b>Optional Parameters:</b></p>
 * <ul>
 *   <li><b>sessionId:</b> Session ID for state generation (overrides default session handling)</li>
 * </ul>
 * <p>
 * <b>Configuration Parameters (Not in Request):</b></p>
 * The following parameters are configured via {@link AgentAapExecutorConfig}:
 * <ul>
 *   <li><b>clientId:</b> OAuth client identifier</li>
 *   <li><b>channel:</b> Channel information (e.g., "web", "mobile")</li>
 *   <li><b>language:</b> Language code (e.g., "zh-CN", "en-US")</li>
 *   <li><b>platform:</b> Platform identifier</li>
 *   <li><b>agentClient:</b> Agent client software identifier</li>
 *   <li><b>deviceFingerprint:</b> Device fingerprint (generated via configured strategy)</li>
 * </ul>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RequestAuthUrlRequest {

    /**
     * The user's ID Token from Agent User IDP.
     * <p>
     * This field is REQUIRED.
     * The framework uses this token to:
     * </p>
 * <ul>
     *   <li>Validate the user's identity through the Agent User IDP</li>
     *   <li>Extract the user identifier (sub claim) for workload binding</li>
     *   <li>Verify the token's signature and expiration</li>
     * </ul>
     * <p>
     * <b>Token Requirements:</b></p>
     * <ul>
     *   <li>MUST be a valid JWT signed by the Agent User IDP</li>
     *   <li>MUST contain the 'sub' (subject) claim identifying the user</li>
     *   <li>MUST not be expired</li>
     *   <li>Should contain 'iss' (issuer) claim for validation</li>
     * </ul>
     */
    @JsonProperty("userIdentityToken")
    private final String userIdentityToken;

    /**
     * The user's original natural language input.
     * <p>
     * This field is REQUIRED.
     * The framework will use this input to generate a Prompt VC for evidence.
     * According to draft-liu-agent-operation-authorization-01, the auditTrail.originalPromptText
     * MUST contain the user's original input (e.g., "i want to buy some programming book"),
     * NOT a system-generated description (e.g., "Execute tool: search_products").
     * </p>
     */
    @JsonProperty("userOriginalInput")
    private final String userOriginalInput;

    /**
     * The workload context containing operation-specific information.
     * <p>
     * This field is REQUIRED.
     * It encapsulates the operation type, resource identifier, and metadata needed
     * for workload creation and policy evaluation.
     * </p>
     */
    @JsonProperty("workloadContext")
    private final WorkloadRequestContext workloadContext;

    /**
     * Session ID for session restoration.
     * <p>
     * This field is OPTIONAL. Used by the state generation strategy to include session context.
     * If not provided, the framework will use the current session context.
     * </p>
     */
    @JsonProperty("sessionId")
    private final String sessionId;

    /**
     * Device fingerprint for the client device instance.
     * <p>
     * This field is OPTIONAL.
     * <p>
     * <b>Standard:</b> draft-liu-agent-operation-authorization-01, Table 1
     * <b>Requirement:</b> OPTIONAL
     * <b>Description:</b> A stable, privacy-preserving fingerprint derived from
     * hardware and application properties, serving as a unique identifier for the
     * client device instance.
     * </p>
     * <p>
     * <b>Usage:</b></p>
     * <ul>
     *   <li><b>Single-device deployments:</b> Leave this field null and configure
     *       {@link AgentAapExecutorConfig#getDeviceFingerprint()}
     *       instead.</li>
     *   <li><b>Multi-device deployments:</b> Provide device-specific fingerprints
     *       in each request to properly identify different devices.</li>
     * </ul>
     * <p>
     * <b>Priority:</b> If both configuration and request provide deviceFingerprint,
     * the request value takes precedence.
     * </p>
     * <p>
     * <b>Standard Locations:</b></p>
     * This fingerprint is used in:
     * <ul>
     *   <li>{@code agent_user_binding_proposal.device_fingerprint} (Table 1)</li>
     *   <li>{@code context.deviceFingerprint} (Figure 8)</li>
     *   <li>{@code evidence.credentialSubject.deviceFingerprint} (Figure 3)</li>
     * </ul>
     * </p>
     */
    @JsonProperty("deviceFingerprint")
    private final String deviceFingerprint;

    private RequestAuthUrlRequest(Builder builder) {
        this.userIdentityToken = builder.userIdentityToken;
        this.userOriginalInput = builder.userOriginalInput;
        this.workloadContext = builder.workloadContext;
        this.sessionId = builder.sessionId;
        this.deviceFingerprint = builder.deviceFingerprint;
    }

    public String getUserIdentityToken() {
        return userIdentityToken;
    }

    public String getUserOriginalInput() {
        return userOriginalInput;
    }

    public WorkloadRequestContext getWorkloadContext() {
        return workloadContext;
    }

    /**
     * Gets the operation type from the workload context.
     *
     * @return the operation type
     */
    public String getOperationType() {
        return workloadContext != null ? workloadContext.getOperationType() : null;
    }

    /**
     * Gets the resource ID from the workload context.
     *
     * @return the resource ID
     */
    public String getResourceId() {
        return workloadContext != null ? workloadContext.getResourceId() : null;
    }

    /**
     * Gets the metadata from the workload context.
     *
     * @return the metadata map
     */
    public java.util.Map<String, Object> getMetadata() {
        return workloadContext != null ? workloadContext.getMetadata() : null;
    }

    public String getSessionId() {
        return sessionId;
    }

    /**
     * Gets the device fingerprint for the client device instance.
     * <p>
     * This value is used to identify the device across the authorization flow.
     * If null, the framework will use the configured default device fingerprint.
     * </p>
     *
     * @return the device fingerprint, or null if not provided
     */
    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RequestAuthUrlRequest that = (RequestAuthUrlRequest) o;
        return Objects.equals(userIdentityToken, that.userIdentityToken) &&
               Objects.equals(userOriginalInput, that.userOriginalInput) &&
               Objects.equals(workloadContext, that.workloadContext) &&
               Objects.equals(sessionId, that.sessionId) &&
               Objects.equals(deviceFingerprint, that.deviceFingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userIdentityToken, userOriginalInput, workloadContext, sessionId, deviceFingerprint);
    }

    @Override
    public String toString() {
        return "RequestAuthUrlRequest{" +
                "userIdentityToken='[PROTECTED]'" +
                ", userOriginalInput='" + userOriginalInput + '\'' +
                ", workloadContext=" + workloadContext +
                ", sessionId='" + sessionId + '\'' +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link RequestAuthUrlRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link RequestAuthUrlRequest}.
     * <p>
     * This builder provides a fluent interface for constructing authorization URL requests.
     * Required fields must be set before calling build().
     * Optional fields have sensible defaults.
     * </p>
     */
    public static class Builder {
        private String userIdentityToken;
        private String userOriginalInput;
        private WorkloadRequestContext workloadContext;
        private String sessionId;
        private String deviceFingerprint;

        /**
         * Sets the user's ID Token from Agent User IDP.
         * <p>
         * This field is REQUIRED.
         * The framework needs this token to validate the user's identity and extract the user identifier
         * for binding to the workload identity.
         * </p>
         *
         * @param userIdentityToken the user's ID Token
         * @return this builder instance
         */
        public Builder userIdentityToken(String userIdentityToken) {
            this.userIdentityToken = userIdentityToken;
            return this;
        }

        /**
         * Sets the user's original natural language input.
         * <p>
         * This field is REQUIRED.
         * The framework will use this input to generate a Prompt VC for evidence.
         * </p>
         *
         * @param userOriginalInput the user's original input
         * @return this builder instance
         */
        public Builder userOriginalInput(String userOriginalInput) {
            this.userOriginalInput = userOriginalInput;
            return this;
        }

        /**
         * Sets the workload context.
         * <p>
         * This field is REQUIRED.
         * The workload context contains operation type, resource ID, and metadata.
         * </p>
         *
         * @param workloadContext the workload context
         * @return this builder instance
         */
        public Builder workloadContext(WorkloadRequestContext workloadContext) {
            this.workloadContext = workloadContext;
            return this;
        }

        /**
         * Sets the session ID for session restoration.
         * <p>
         * This field is OPTIONAL. Used by the state generation strategy.
         * </p>
         *
         * @param sessionId the session ID
         * @return this builder instance
         */
        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        /**
         * Sets the device fingerprint for the client device instance.
         * <p>
         * This field is OPTIONAL.
         * Provide device-specific fingerprints for multi-device deployments.
         * For single-device deployments, leave this field null and configure
         * {@link AgentAapExecutorConfig#getDeviceFingerprint()}
         * instead.
         * </p>
         * <p>
         * <b>Standard:</b> draft-liu-agent-operation-authorization-01, Table 1
         * <b>Requirement:</b> OPTIONAL
         * </p>
         *
         * @param deviceFingerprint the device fingerprint
         * @return this builder instance
         */
        public Builder deviceFingerprint(String deviceFingerprint) {
            this.deviceFingerprint = deviceFingerprint;
            return this;
        }

        /**
         * Builds the {@link RequestAuthUrlRequest}.
         * <p>
         * Validates that all required fields are set before building.
         * </p>
         *
         * @return the built request
         * @throws IllegalArgumentException if required fields are missing
         */
        public RequestAuthUrlRequest build() {
            if (ValidationUtils.isNullOrEmpty(userIdentityToken)) {
                throw new IllegalArgumentException("userIdentityToken is required");
            }
            if (ValidationUtils.isNullOrEmpty(userOriginalInput)) {
                throw new IllegalArgumentException("userOriginalInput is required");
            }
            if (workloadContext == null) {
                throw new IllegalArgumentException("workloadContext is required");
            }
            if (ValidationUtils.isNullOrEmpty(workloadContext.getOperationType())) {
                throw new IllegalArgumentException("workloadContext.operationType is required");
            }
            return new RequestAuthUrlRequest(this);
        }
    }
}
