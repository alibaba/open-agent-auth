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
package com.alibaba.openagentauth.core.model.proposal;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Represents an agent user binding proposal.
 * <p>
 * This claim is a structured JSON object proposed by the client (e.g., an AI agent)
 * to describe its own identity context when acting on behalf of a user.
 * In the Agent Operation Authorization Request (i.e., the PAR-JWT), this claim
 * represents a _proposal_ of the agent-to-user binding and is _not yet
 * cryptographically endorsed_ by the Authorization Server (AS).
 * </p>
 * <p>
 * The Authorization Server validates the user_identity_token and agent_workload_token
 * to establish the user's and agent's identities before issuing an authorization token.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentUserBindingProposal {

    /**
     * User Identity Token claim.
     * <p>
     * A verifiable identity token for the end user, issued by a trusted Identity Provider.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED
     * and MUST be an OpenID Connect ID Token or equivalent cryptographically signed token.
     * The Authorization Server will validate this token to establish the user's identity.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
     */
    @JsonProperty("user_identity_token")
    private final String userIdentityToken;

    /**
     * Agent Workload Token claim.
     * <p>
     * A verifiable workload identity token for the agent.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED
     * and MUST be a valid, signed workload identity credential.
     * Typically, a Workload Identity Token (WIT) as defined in draft-ietf-wimse-workload-creds.
     * The Authorization Server will validate this token to establish the agent's identity and trustworthiness.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">draft-ietf-wimse-workload-creds</a>
     */
    @JsonProperty("agent_workload_token")
    private final String agentWorkloadToken;

    /**
     * Device Fingerprint claim.
     * <p>
     * An optional unique identifier for the client device instance.
     * According to draft-liu-agent-operation-authorization, this field is OPTIONAL.
     * If provided, it SHOULD be a stable, privacy-preserving fingerprint
     * (e.g., derived from hardware and app properties).
     * Used by the AS to populate the client_instance field in the resulting agent_identity claim.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
     */
    @JsonProperty("device_fingerprint")
    private final String deviceFingerprint;

    /**
     * Constructor for Jackson deserialization.
     */
    @JsonCreator
    public AgentUserBindingProposal(
            @JsonProperty("user_identity_token") String userIdentityToken,
            @JsonProperty("agent_workload_token") String agentWorkloadToken,
            @JsonProperty("device_fingerprint") String deviceFingerprint
    ) {
        this.userIdentityToken = userIdentityToken;
        this.agentWorkloadToken = agentWorkloadToken;
        this.deviceFingerprint = deviceFingerprint;
    }

    private AgentUserBindingProposal(Builder builder) {
        this.userIdentityToken = builder.userIdentityToken;
        this.agentWorkloadToken = builder.agentWorkloadToken;
        this.deviceFingerprint = builder.deviceFingerprint;
    }

    /**
     * Gets the user identity token.
     *
     * @return the user identity token
     */
    public String getUserIdentityToken() {
        return userIdentityToken;
    }

    /**
     * Gets the agent workload token.
     *
     * @return the agent workload token
     */
    public String getAgentWorkloadToken() {
        return agentWorkloadToken;
    }

    /**
     * Gets the device fingerprint.
     *
     * @return the device fingerprint, or null if not present
     */
    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AgentUserBindingProposal that = (AgentUserBindingProposal) o;
        return Objects.equals(userIdentityToken, that.userIdentityToken) &&
               Objects.equals(agentWorkloadToken, that.agentWorkloadToken) &&
               Objects.equals(deviceFingerprint, that.deviceFingerprint);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userIdentityToken, agentWorkloadToken, deviceFingerprint);
    }

    @Override
    public String toString() {
        return "AgentUserBindingProposal{" +
                "userIdentityToken='" + userIdentityToken + '\'' +
                ", agentWorkloadToken='" + agentWorkloadToken + '\'' +
                ", deviceFingerprint='" + deviceFingerprint + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AgentUserBindingProposal}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AgentUserBindingProposal}.
     */
    public static class Builder {

        /**
         * Fields for {@link AgentUserBindingProposal}.
         */
        private String userIdentityToken;
        private String agentWorkloadToken;
        private String deviceFingerprint;

        /**
         * Sets the user identity token.
         * <p>
         * This field is REQUIRED and MUST be an OpenID Connect ID Token
         * or equivalent cryptographically signed token.
         * </p>
         *
         * @param userIdentityToken the user identity token
         * @return this builder instance
         */
        public Builder userIdentityToken(String userIdentityToken) {
            this.userIdentityToken = userIdentityToken;
            return this;
        }

        /**
         * Sets the agent workload token.
         * <p>
         * This field is REQUIRED and MUST be a valid, signed workload identity credential.
         * Typically, a Workload Identity Token (WIT).
         * </p>
         *
         * @param agentWorkloadToken the agent workload token
         * @return this builder instance
         */
        public Builder agentWorkloadToken(String agentWorkloadToken) {
            this.agentWorkloadToken = agentWorkloadToken;
            return this;
        }

        /**
         * Sets the device fingerprint.
         * <p>
         * This field is OPTIONAL.
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
         * Builds the {@link AgentUserBindingProposal}.
         *
         * @return the built proposal
         */
        public AgentUserBindingProposal build() {
            return new AgentUserBindingProposal(this);
        }
    }
}