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
package com.alibaba.openagentauth.core.model.identity;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents a delegation chain entry for agent-to-agent delegation.
 * <p>
 * Each entry in the chain is signed by the Authorization Server and contains
 * information about the delegating agent, delegation timestamp, and operation summary.
 * This enables end-to-end validation of delegation lineage without exposing raw credentials.
 * This is crucial for scenarios where agents need to delegate operations to other agents
 * while maintaining a complete audit trail.
 * </p>
 * <p>
 * <b>Delegation Chain Fields (per draft-liu-agent-operation-authorization):</b></p>
 * <ul>
 *   <li><b>delegator_jti</b>: Delegator JTI - the JWT ID of the delegator's authorization token (REQUIRED)</li>
 *   <li><b>delegator_agent_identity</b>: Delegator Agent Identity - the agent_identity of the delegating agent (REQUIRED)</li>
 *   <li><b>delegation_timestamp</b>: Delegation Timestamp - when this delegation was authorized (REQUIRED)</li>
 *   <li><b>operation_summary</b>: Operation Summary - human-readable description of the delegated operation (OPTIONAL)</li>
 *   <li><b>as_signature</b>: AS Signature - cryptographic signature from the AS over this delegation record (REQUIRED)</li>
 * </ul>
 * <p>
 * <b>Security Properties:</b></p>
 * <ul>
 *   <li>Each entry is cryptographically signed by the Authorization Server</li>
 *   <li>Enables end-to-end auditability back to the original human principal</li>
 *   <li>Prevents privilege escalation beyond the original authorization scope</li>
 *   <li>No exposure of raw credentials during delegation</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DelegationChain {

    /**
     * Delegator JTI claim.
     * <p>
     * The JWT ID (JTI) of the delegator's authorization token.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED
     * and MUST be a valid JWT ID that can be resolved by the Authorization Server.
     * It serves as a reference to the prior authorization in the delegation chain.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
     */
    @JsonProperty("delegator_jti")
    private final String delegatorJti;

    /**
     * Delegator Agent Identity claim.
     * <p>
     * The agent_identity of the delegating agent.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED
     * and MUST match the agent_identity structure defined in this specification.
     * It identifies the delegating agent in the delegation chain.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
     */
    @JsonProperty("delegator_agent_identity")
    private final AgentIdentity delegatorAgentIdentity;

    /**
     * Delegation Timestamp claim.
     * <p>
     * The time when this delegation was authorized by the Authorization Server.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED
     * and MUST conform to ISO 8601 UTC format.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
     */
    @JsonProperty("delegation_timestamp")
    private final Instant delegationTimestamp;

    /**
     * Operation Summary claim.
     * <p>
     * A human-readable description of the delegated operation.
     * According to draft-liu-agent-operation-authorization, this field is OPTIONAL.
     * It is useful for post-hoc analysis and compliance reporting purposes.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
     */
    @JsonProperty("operation_summary")
    private final String operationSummary;

    /**
     * AS Signature claim.
     * <p>
     * Cryptographic signature from the Authorization Server over this delegation record.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED
     * and MUST be verifiable using the AS's public key.
     * This ensures integrity and non-repudiation of the delegation entry.
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
     */
    @JsonProperty("as_signature")
    private final String asSignature;

    private DelegationChain(Builder builder) {
        this.delegatorJti = builder.delegatorJti;
        this.delegatorAgentIdentity = builder.delegatorAgentIdentity;
        this.delegationTimestamp = builder.delegationTimestamp;
        this.operationSummary = builder.operationSummary;
        this.asSignature = builder.asSignature;
    }

    /**
     * Gets the JWT ID of the delegating agent's authorization token.
     *
     * @return the delegator JTI
     */
    public String getDelegatorJti() {
        return delegatorJti;
    }

    /**
     * Gets the identity of the delegating agent.
     *
     * @return the delegator agent identity
     */
    public AgentIdentity getDelegatorAgentIdentity() {
        return delegatorAgentIdentity;
    }

    /**
     * Gets the timestamp when the delegation occurred.
     *
     * @return the delegation timestamp
     */
    public Instant getDelegationTimestamp() {
        return delegationTimestamp;
    }

    /**
     * Gets a summary of the operation being delegated.
     *
     * @return the operation summary
     */
    public String getOperationSummary() {
        return operationSummary;
    }

    /**
     * Gets the Authorization Server's signature on this delegation entry.
     *
     * @return the AS signature
     */
    public String getAsSignature() {
        return asSignature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DelegationChain that = (DelegationChain) o;
        return Objects.equals(delegatorJti, that.delegatorJti) &&
               Objects.equals(delegatorAgentIdentity, that.delegatorAgentIdentity) &&
               Objects.equals(delegationTimestamp, that.delegationTimestamp) &&
               Objects.equals(operationSummary, that.operationSummary) &&
               Objects.equals(asSignature, that.asSignature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(delegatorJti, delegatorAgentIdentity, delegationTimestamp, operationSummary, asSignature);
    }

    @Override
    public String toString() {
        return "DelegationChain{" +
                "delegatorJti='" + delegatorJti + '\'' +
                ", delegatorAgentIdentity=" + delegatorAgentIdentity +
                ", delegationTimestamp=" + delegationTimestamp +
                ", operationSummary='" + operationSummary + '\'' +
                ", asSignature='" + asSignature + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link DelegationChain}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link DelegationChain}.
     */
    public static class Builder {
        private String delegatorJti;
        private AgentIdentity delegatorAgentIdentity;
        private Instant delegationTimestamp;
        private String operationSummary;
        private String asSignature;

        /**
         * Sets the delegator JTI.
         *
         * @param delegatorJti the delegator JTI
         * @return this builder instance
         */
        public Builder delegatorJti(String delegatorJti) {
            this.delegatorJti = delegatorJti;
            return this;
        }

        /**
         * Sets the delegator agent identity.
         *
         * @param delegatorAgentIdentity the delegator agent identity
         * @return this builder instance
         */
        public Builder delegatorAgentIdentity(AgentIdentity delegatorAgentIdentity) {
            this.delegatorAgentIdentity = delegatorAgentIdentity;
            return this;
        }

        /**
         * Sets the delegation timestamp.
         *
         * @param delegationTimestamp the delegation timestamp
         * @return this builder instance
         */
        public Builder delegationTimestamp(Instant delegationTimestamp) {
            this.delegationTimestamp = delegationTimestamp;
            return this;
        }

        /**
         * Sets the operation summary.
         *
         * @param operationSummary the operation summary
         * @return this builder instance
         */
        public Builder operationSummary(String operationSummary) {
            this.operationSummary = operationSummary;
            return this;
        }

        /**
         * Sets the AS signature.
         *
         * @param asSignature the AS signature
         * @return this builder instance
         */
        public Builder asSignature(String asSignature) {
            this.asSignature = asSignature;
            return this;
        }

        /**
         * Builds the {@link DelegationChain}.
         *
         * @return the built delegation chain
         */
        public DelegationChain build() {
            return new DelegationChain(this);
        }
    }
}
