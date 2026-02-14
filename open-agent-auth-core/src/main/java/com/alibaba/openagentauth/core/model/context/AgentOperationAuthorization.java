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
package com.alibaba.openagentauth.core.model.context;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Represents the agent_operation_authorization claim.
 * <p>
 * This claim conveys authorization metadata for agent-performed operations,
 * including a reference to a registered policy via the policy_id field.
 * According to draft-liu-agent-operation-authorization, this claim is REQUIRED.
 * </p>
 * <p>
 * <b>Authorization Fields:</b></p>
 * <table border="1">
 *   <tr><th>Field</th><th>Description</th><th>Status</th></tr>
 *   <tr><td>policy_id</td><td>Policy ID - reference to a registered policy</td><td>REQUIRED</td></tr>
 * </table>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentOperationAuthorization {

    /**
     * Policy ID field.
     * <p>
     * Reference to a registered policy that defines the authorization scope.
     * This field is REQUIRED.
     * </p>
     */
    @JsonProperty("policy_id")
    private final String policyId;

    private AgentOperationAuthorization(Builder builder) {
        this.policyId = builder.policyId;
    }

    /**
     * Gets the policy ID.
     *
     * @return the policy ID
     */
    public String getPolicyId() {
        return policyId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AgentOperationAuthorization that = (AgentOperationAuthorization) o;
        return Objects.equals(policyId, that.policyId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policyId);
    }

    @Override
    public String toString() {
        return "AgentOperationAuthorization{" +
                "policyId='" + policyId + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AgentOperationAuthorization}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AgentOperationAuthorization}.
     */
    public static class Builder {
        private String policyId;

        /**
         * Sets the policy ID.
         * <p>
         * This field is REQUIRED.
         * </p>
         *
         * @param policyId the policy ID
         * @return this builder instance
         */
        public Builder policyId(String policyId) {
            this.policyId = policyId;
            return this;
        }

        /**
         * Builds the {@link AgentOperationAuthorization}.
         *
         * @return the built authorization
         */
        public AgentOperationAuthorization build() {
            return new AgentOperationAuthorization(this);
        }
    }
}
