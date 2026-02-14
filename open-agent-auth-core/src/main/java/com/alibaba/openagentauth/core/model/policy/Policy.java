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
 * Represents a registered policy in the Agent Operation Authorization framework.
 * <p>
 * A policy is a set of authorization rules that define what operations an agent
 * is permitted to perform. Policies are written in Rego (Open Policy Agent policy language)
 * and are registered with the Authorization Server during the authorization request phase.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization:
 * <ul>
 *   <li>The agent proposes a policy via agent_operation_proposal claim</li>
 *   <li>The AS validates and registers the policy</li>
 *   <li>The AS issues a token with policy_id referencing the registered policy</li>
 *   <li>Resource servers use the policy_id to retrieve and enforce the policy</li>
 * </ul>
 * </p>
 * <p>
 * <b>Policy Lifecycle:</b></p>
 * <ol>
 *   <li><b>Proposal:</b> Agent submits policy in PAR request</li>
 *   <li><b>Validation:</b> AS validates Rego syntax and semantics</li>
 *   <li><b>Registration:</b> AS assigns policy_id and stores the policy</li>
 *   <li><b>Enforcement:</b> Resource servers evaluate the policy at runtime</li>
 *   <li><b>Expiration:</b> Policy expires based on metadata</li>
 * </ol>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a>
 * @see PolicyMetadata
 * @see PolicyRegistration
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Policy {

    /**
     * Unique identifier for the policy.
     * <p>
     * This ID is assigned by the Authorization Server upon successful registration.
     * The ID is used in the agent_operation_authorization claim to reference this policy.
     * Format: "policy-{UUID}" (e.g., "policy-550e8400-e29b-41d4-a716-446655440000")
     * </p>
     */
    @JsonProperty("policy_id")
    private final String policyId;

    /**
     * The Rego policy definition.
     * <p>
     * Contains the authorization rules written in Rego policy language.
     * The policy MUST be syntactically valid and SHOULD follow OPA best practices.
     * </p>
     * <p>
     * Example Rego policy:
     * <pre>{@code
     * package agent
     * allow {
     *     input.operation == "purchase"
     *     input.amount <= 50.0
     *     input.channel == "mobile-app"
     * }
     * }</pre>
     * </p>
     */
    @JsonProperty("rego_policy")
    private final String regoPolicy;

    /**
     * Human-readable description of the policy.
     * <p>
     * This field is OPTIONAL but RECOMMENDED for auditability and user understanding.
     * It should describe what the policy authorizes in clear, non-technical language.
     * </p>
     */
    @JsonProperty("description")
    private final String description;

    /**
     * Metadata about the policy.
     * <p>
     * Contains creation time, expiration time, version, and other metadata.
     * This field is REQUIRED for policy lifecycle management.
     * </p>
     */
    @JsonProperty("metadata")
    private final PolicyMetadata metadata;

    /**
     * Creates a new Policy instance.
     *
     * @param policyId     the unique policy identifier
     * @param regoPolicy   the Rego policy definition
     * @param description  the policy description
     * @param metadata     the policy metadata
     */
    @JsonCreator
    private Policy(
            @JsonProperty("policy_id") String policyId,
            @JsonProperty("rego_policy") String regoPolicy,
            @JsonProperty("description") String description,
            @JsonProperty("metadata") PolicyMetadata metadata) {
        this.policyId = policyId;
        this.regoPolicy = regoPolicy;
        this.description = description;
        this.metadata = metadata;
    }

    /**
     * Gets the policy ID.
     *
     * @return the policy ID
     */
    public String getPolicyId() {
        return policyId;
    }

    /**
     * Gets the Rego policy definition.
     *
     * @return the Rego policy string
     */
    public String getRegoPolicy() {
        return regoPolicy;
    }

    /**
     * Gets the policy description.
     *
     * @return the description, or null if not set
     */
    public String getDescription() {
        return description;
    }

    /**
     * Gets the policy metadata.
     *
     * @return the metadata
     */
    public PolicyMetadata getMetadata() {
        return metadata;
    }

    /**
     * Checks if the policy has expired.
     *
     * @return true if the policy is expired, false otherwise
     */
    public boolean isExpired() {
        return metadata != null && metadata.getExpirationTime() != null
                && Instant.now().isAfter(metadata.getExpirationTime());
    }

    /**
     * Checks if the policy is currently valid (not expired).
     *
     * @return true if the policy is valid, false otherwise
     */
    public boolean isValid() {
        return !isExpired();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Policy policy = (Policy) o;
        return Objects.equals(policyId, policy.policyId) &&
                Objects.equals(regoPolicy, policy.regoPolicy) &&
                Objects.equals(description, policy.description) &&
                Objects.equals(metadata, policy.metadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policyId, regoPolicy, description, metadata);
    }

    @Override
    public String toString() {
        return "Policy{" +
                "policyId='" + policyId + '\'' +
                ", regoPolicy='" + regoPolicy + '\'' +
                ", description='" + description + '\'' +
                ", metadata=" + metadata +
                '}';
    }

    /**
     * Creates a new builder for {@link Policy}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link Policy}.
     */
    public static class Builder {
        private String policyId;
        private String regoPolicy;
        private String description;
        private PolicyMetadata metadata;

        /**
         * Sets the policy ID.
         *
         * @param policyId the policy ID
         * @return this builder instance
         */
        public Builder policyId(String policyId) {
            this.policyId = policyId;
            return this;
        }

        /**
         * Sets the Rego policy definition.
         *
         * @param regoPolicy the Rego policy string
         * @return this builder instance
         */
        public Builder regoPolicy(String regoPolicy) {
            this.regoPolicy = regoPolicy;
            return this;
        }

        /**
         * Sets the policy description.
         *
         * @param description the description
         * @return this builder instance
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /**
         * Sets the policy metadata.
         *
         * @param metadata the metadata
         * @return this builder instance
         */
        public Builder metadata(PolicyMetadata metadata) {
            this.metadata = metadata;
            return this;
        }

        /**
         * Builds the {@link Policy}.
         *
         * @return the built policy
         */
        public Policy build() {
            return new Policy(policyId, regoPolicy, description, metadata);
        }
    }
}
