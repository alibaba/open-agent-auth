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
package com.alibaba.openagentauth.core.binding;

import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a binding instance between a user identity and a workload identity.
 * <p>
 * This class encapsulates the binding relationship established by the Authorization Server
 * when validating an agent's authorization request. It contains both the user identity
 * and workload identity information, along with metadata about when the binding was created.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization, the binding instance is created
 * when the AS validates the agent_user_binding_proposal and issues an agent_identity claim
 * in the Agent Operation Authorization Token (AOAT).
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 * @since 1.0
 */
public class BindingInstance {

    /**
     * The unique identifier for this binding instance.
     * <p>
     * This corresponds to the agent_identity.id field in the AOAT.
     * It is a UUID-based URI that uniquely identifies this binding.
     * </p>
     */
    private final String bindingInstanceId;

    /**
     * The user identity that this agent is bound to.
     * <p>
     * This is the user ID from the validated user identity token (e.g., ID Token).
     * It corresponds to the agent_identity.issuedTo field in the AOAT.
     * </p>
     */
    private final String userIdentity;

    /**
     * The workload identity of the agent.
     * <p>
     * This is the workload identifier from the validated Workload Identity Token (WIT).
     * </p>
     */
    private final String workloadIdentity;

    /**
     * The agent identity claims.
     * <p>
     * Contains the complete agent identity information as issued by the AS.
     * </p>
     */
    private final AgentIdentity agentIdentity;

    /**
     * The timestamp when this binding was created.
     */
    private final Instant createdAt;

    /**
     * The timestamp when this binding expires.
     */
    private final Instant expiresAt;

    /**
     * Private constructor to enforce use of Builder.
     *
     * @param builder the builder instance
     */
    private BindingInstance(Builder builder) {
        this.bindingInstanceId = builder.bindingInstanceId;
        this.userIdentity = builder.userIdentity;
        this.workloadIdentity = builder.workloadIdentity;
        this.agentIdentity = builder.agentIdentity;
        this.createdAt = builder.createdAt;
        this.expiresAt = builder.expiresAt;
    }

    /**
     * JSON deserialization constructor for Jackson.
     *
     * @param bindingInstanceId the binding instance ID
     * @param userIdentity the user identity
     * @param workloadIdentity the workload identity
     * @param agentIdentity the agent identity
     * @param createdAt the creation timestamp
     * @param expiresAt the expiration timestamp
     */
    @JsonCreator
    private BindingInstance(
            @JsonProperty("bindingInstanceId") String bindingInstanceId,
            @JsonProperty("userIdentity") String userIdentity,
            @JsonProperty("workloadIdentity") String workloadIdentity,
            @JsonProperty("agentIdentity") AgentIdentity agentIdentity,
            @JsonProperty("createdAt") Instant createdAt,
            @JsonProperty("expiresAt") Instant expiresAt) {
        this.bindingInstanceId = bindingInstanceId;
        this.userIdentity = userIdentity;
        this.workloadIdentity = workloadIdentity;
        this.agentIdentity = agentIdentity;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    /**
     * Gets the binding instance ID.
     *
     * @return the binding instance ID
     */
    public String getBindingInstanceId() {
        return bindingInstanceId;
    }

    /**
     * Gets the user identity.
     *
     * @return the user identity
     */
    public String getUserIdentity() {
        return userIdentity;
    }

    /**
     * Gets the workload identity.
     *
     * @return the workload identity
     */
    public String getWorkloadIdentity() {
        return workloadIdentity;
    }

    /**
     * Gets the agent identity claims.
     *
     * @return the agent identity
     */
    public AgentIdentity getAgentIdentity() {
        return agentIdentity;
    }

    /**
     * Gets the creation timestamp.
     *
     * @return the creation timestamp
     */
    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Gets the expiration timestamp.
     *
     * @return the expiration timestamp
     */
    public Instant getExpiresAt() {
        return expiresAt;
    }

    /**
     * Checks if this binding has expired.
     *
     * @return true if expired, false otherwise
     */
    public boolean isExpired() {
        return expiresAt != null && Instant.now().isAfter(expiresAt);
    }

    /**
     * Checks if this binding is currently valid.
     *
     * @return true if valid, false otherwise
     */
    public boolean isValid() {
        return !isExpired();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BindingInstance that = (BindingInstance) o;
        return Objects.equals(bindingInstanceId, that.bindingInstanceId) &&
               Objects.equals(userIdentity, that.userIdentity) &&
               Objects.equals(workloadIdentity, that.workloadIdentity) &&
               Objects.equals(agentIdentity, that.agentIdentity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bindingInstanceId, userIdentity, workloadIdentity, agentIdentity);
    }

    @Override
    public String toString() {
        return "BindingInstance{" +
                "bindingInstanceId='" + bindingInstanceId + '\'' +
                ", userIdentity='" + userIdentity + '\'' +
                ", workloadIdentity='" + workloadIdentity + '\'' +
                ", agentIdentity=" + agentIdentity +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                '}';
    }

    /**
     * Creates a new builder for {@link BindingInstance}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link BindingInstance}.
     */
    public static class Builder {
        private String bindingInstanceId;
        private String userIdentity;
        private String workloadIdentity;
        private AgentIdentity agentIdentity;
        private Instant createdAt;
        private Instant expiresAt;

        /**
         * Sets the binding instance ID.
         *
         * @param bindingInstanceId the binding instance ID
         * @return this builder instance
         */
        public Builder bindingInstanceId(String bindingInstanceId) {
            this.bindingInstanceId = bindingInstanceId;
            return this;
        }

        /**
         * Sets the user identity.
         *
         * @param userIdentity the user identity
         * @return this builder instance
         */
        public Builder userIdentity(String userIdentity) {
            this.userIdentity = userIdentity;
            return this;
        }

        /**
         * Sets the workload identity.
         *
         * @param workloadIdentity the workload identity
         * @return this builder instance
         */
        public Builder workloadIdentity(String workloadIdentity) {
            this.workloadIdentity = workloadIdentity;
            return this;
        }

        /**
         * Sets the agent identity claims.
         *
         * @param agentIdentity the agent identity
         * @return this builder instance
         */
        public Builder agentIdentity(AgentIdentity agentIdentity) {
            this.agentIdentity = agentIdentity;
            return this;
        }

        /**
         * Sets the creation timestamp.
         *
         * @param createdAt the creation timestamp
         * @return this builder instance
         */
        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        /**
         * Sets the expiration timestamp.
         *
         * @param expiresAt the expiration timestamp
         * @return this builder instance
         */
        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        /**
         * Builds the {@link BindingInstance}.
         *
         * @return the built binding instance
         * @throws IllegalStateException if required fields are not set
         */
        public BindingInstance build() {
            if (bindingInstanceId == null || bindingInstanceId.isEmpty()) {
                throw new IllegalStateException("bindingInstanceId is REQUIRED");
            }
            if (userIdentity == null || userIdentity.isEmpty()) {
                throw new IllegalStateException("userIdentity is REQUIRED");
            }
            if (workloadIdentity == null || workloadIdentity.isEmpty()) {
                throw new IllegalStateException("workloadIdentity is REQUIRED");
            }
            if (createdAt == null) {
                createdAt = Instant.now();
            }
            return new BindingInstance(this);
        }
    }
}
