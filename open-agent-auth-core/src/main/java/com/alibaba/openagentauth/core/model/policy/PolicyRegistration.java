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
package com.alibaba.openagentauth.core.model.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a policy registration request and result.
 * <p>
 * When an agent submits an agent_operation_proposal via PAR, the Authorization Server
 * validates the policy and creates a registration record. This record contains the
 * original proposal, assigned policy ID, and registration metadata.
 * </p>
 * <p>
 * <b>Registration Flow:</b></p>
 * <ol>
 *   <li>Agent submits agent_operation_proposal in PAR request</li>
 *   <li>AS validates the Rego policy syntax and semantics</li>
 *   <li>AS validates the policy against security constraints</li>
 *   <li>AS assigns a unique policy_id</li>
 *   <li>AS stores the policy and creates a PolicyRegistration record</li>
 *   <li>AS includes policy_id in the issued access token</li>
 * </ol>
 * </p>
 *
 * @see Policy
 * @see PolicyMetadata
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyRegistration {

    /**
     * The registered policy.
     * <p>
     * Contains the complete policy definition including the assigned policy_id,
     * Rego policy content, and metadata.
     * </p>
     */
    @JsonProperty("policy")
    private final Policy policy;

    /**
     * The original Rego policy proposal.
     * <p>
     * The exact Rego policy string that was submitted by the agent in the
     * agent_operation_proposal claim. This is stored for audit purposes
     * to track the original submission.
     * </p>
     */
    @JsonProperty("original_proposal")
    private final String originalProposal;

    /**
     * Registration timestamp.
     * <p>
     * The time when the policy was successfully registered with the AS.
     * This field is REQUIRED and MUST conform to ISO 8601 UTC format.
     * </p>
     */
    @JsonProperty("registered_at")
    private final Instant registeredAt;

    /**
     * Registration status.
     * <p>
     * Indicates whether the registration was successful or failed.
     * Common values: "SUCCESS", "FAILED", "PENDING_VALIDATION".
     * </p>
     */
    @JsonProperty("status")
    private final String status;

    /**
     * Registration failure reason.
     * <p>
     * If registration failed, this field contains the reason for failure.
     * Common reasons include:
     * <ul>
     *   <li>INVALID_SYNTAX - Rego syntax error</li>
     *   <li>SECURITY_VIOLATION - Policy violates security constraints</li>
     *   <li>DUPLICATE_POLICY - Policy already exists</li>
     *   <li>VALIDATION_ERROR - Generic validation error</li>
     * </ul>
     * This field is REQUIRED when status is "FAILED".
     * </p>
     */
    @JsonProperty("failure_reason")
    private final String failureReason;

    /**
     * Creates a new PolicyRegistration instance.
     *
     * @param policy           the registered policy
     * @param originalProposal the original proposal
     * @param registeredAt     the registration timestamp
     * @param status           the registration status
     * @param failureReason    the failure reason
     */
    @JsonCreator
    private PolicyRegistration(
            @JsonProperty("policy") Policy policy,
            @JsonProperty("original_proposal") String originalProposal,
            @JsonProperty("registered_at") Instant registeredAt,
            @JsonProperty("status") String status,
            @JsonProperty("failure_reason") String failureReason) {
        this.policy = policy;
        this.originalProposal = originalProposal;
        this.registeredAt = registeredAt;
        this.status = status;
        this.failureReason = failureReason;
    }

    /**
     * Gets the registered policy.
     *
     * @return the policy
     */
    public Policy getPolicy() {
        return policy;
    }

    /**
     * Gets the original proposal.
     *
     * @return the original proposal string
     */
    public String getOriginalProposal() {
        return originalProposal;
    }

    /**
     * Gets the registration timestamp.
     *
     * @return the registration time
     */
    public Instant getRegisteredAt() {
        return registeredAt;
    }

    /**
     * Gets the registration status.
     *
     * @return the status
     */
    public String getStatus() {
        return status;
    }

    /**
     * Gets the failure reason.
     *
     * @return the failure reason, or null if registration succeeded
     */
    public String getFailureReason() {
        return failureReason;
    }

    /**
     * Checks if the registration was successful.
     *
     * @return true if successful, false otherwise
     */
    public boolean isSuccess() {
        return "SUCCESS".equals(status);
    }

    /**
     * Checks if the registration failed.
     *
     * @return true if failed, false otherwise
     */
    public boolean isFailed() {
        return "FAILED".equals(status);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyRegistration that = (PolicyRegistration) o;
        return Objects.equals(policy, that.policy) &&
                Objects.equals(originalProposal, that.originalProposal) &&
                Objects.equals(registeredAt, that.registeredAt) &&
                Objects.equals(status, that.status) &&
                Objects.equals(failureReason, that.failureReason);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policy, originalProposal, registeredAt, status, failureReason);
    }

    @Override
    public String toString() {
        return "PolicyRegistration{" +
                "policy=" + policy +
                ", originalProposal='" + originalProposal + '\'' +
                ", registeredAt=" + registeredAt +
                ", status='" + status + '\'' +
                ", failureReason='" + failureReason + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link PolicyRegistration}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link PolicyRegistration}.
     */
    public static class Builder {
        private Policy policy;
        private String originalProposal;
        private Instant registeredAt;
        private String status;
        private String failureReason;

        /**
         * Sets the registered policy.
         *
         * @param policy the policy
         * @return this builder instance
         */
        public Builder policy(Policy policy) {
            this.policy = policy;
            return this;
        }

        /**
         * Sets the original proposal.
         *
         * @param originalProposal the original proposal string
         * @return this builder instance
         */
        public Builder originalProposal(String originalProposal) {
            this.originalProposal = originalProposal;
            return this;
        }

        /**
         * Sets the registration timestamp.
         *
         * @param registeredAt the registration time
         * @return this builder instance
         */
        public Builder registeredAt(Instant registeredAt) {
            this.registeredAt = registeredAt;
            return this;
        }

        /**
         * Sets the registration status.
         *
         * @param status the status
         * @return this builder instance
         */
        public Builder status(String status) {
            this.status = status;
            return this;
        }

        /**
         * Sets the failure reason.
         *
         * @param failureReason the failure reason
         * @return this builder instance
         */
        public Builder failureReason(String failureReason) {
            this.failureReason = failureReason;
            return this;
        }

        /**
         * Builds the {@link PolicyRegistration}.
         *
         * @return the built registration
         */
        public PolicyRegistration build() {
            return new PolicyRegistration(policy, originalProposal, registeredAt, status, failureReason);
        }
    }
}
