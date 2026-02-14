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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Represents an agent operation proposal.
 * <p>
 * This claim contains a Rego policy string proposed by an agent for authorization evaluation.
 * In the Agent Operation Authorization Request (i.e., the PAR-JWT), this claim
 * represents a _proposal_ of the operation policy and is _not yet
 * cryptographically endorsed_ by the Authorization Server (AS).
 * </p>
 * <p>
 * The Authorization Server validates and registers this policy, and upon successful
 * validation, issues an Agent Operation Authorization Token with a policy_id that
 * references this registered policy.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentOperationProposal {

    /**
     * Policy claim.
     * <p>
     * A Rego policy string that defines the authorization scope and rules for the operation.
     * According to draft-liu-agent-operation-authorization, this field is REQUIRED.
     * The policy is written in Rego (Open Policy Agent policy language) and describes
     * the conditions under which the agent is authorized to perform the operation.
     * </p>
     * <p>
     * The policy typically includes:
     * <ul>
     *   <li>Resource access rules</li>
     *   <li>Operation constraints</li>
     *   <li>Time-based restrictions</li>
     *   <li>Other authorization conditions</li>
     * </ul>
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
     * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a>
     */
    @JsonProperty("policy")
    private final String policy;

    private AgentOperationProposal(Builder builder) {
        this.policy = builder.policy;
    }

    /**
     * Gets the Rego policy string.
     *
     * @return the policy
     */
    public String getPolicy() {
        return policy;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AgentOperationProposal that = (AgentOperationProposal) o;
        return Objects.equals(policy, that.policy);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policy);
    }

    @Override
    public String toString() {
        return "AgentOperationProposal{" +
                "policy='" + policy + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AgentOperationProposal}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AgentOperationProposal}.
     */
    public static class Builder {
        private String policy;

        /**
         * Sets the Rego policy string.
         * <p>
         * This field is REQUIRED and MUST be a valid Rego policy.
         * </p>
         *
         * @param policy the Rego policy string
         * @return this builder instance
         */
        public Builder policy(String policy) {
            this.policy = policy;
            return this;
        }

        /**
         * Builds the {@link AgentOperationProposal}.
         *
         * @return the built proposal
         */
        public AgentOperationProposal build() {
            return new AgentOperationProposal(this);
        }
    }
}
