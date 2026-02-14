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
 * Represents the references claim.
 * <p>
 * This claim contains optional references to related proposals or other resources.
 * According to draft-liu-agent-operation-authorization, this claim is OPTIONAL.
 * </p>
 * <p>
 * <b>References Fields:</b></p>
 * <table border="1">
 *   <tr><th>Field</th><th>Description</th><th>Status</th></tr>
 *   <tr><td>relatedProposalId</td><td>Related Proposal ID - reference to a related proposal</td><td>OPTIONAL</td></tr>
 * </table>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class References {

    @JsonProperty("related_proposal_id")
    private final String relatedProposalId;

    private References(Builder builder) {
        this.relatedProposalId = builder.relatedProposalId;
    }

    /**
     * Gets the related proposal ID.
     *
     * @return the related proposal ID
     */
    public String getRelatedProposalId() {
        return relatedProposalId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        References that = (References) o;
        return Objects.equals(relatedProposalId, that.relatedProposalId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(relatedProposalId);
    }

    @Override
    public String toString() {
        return "References{" +
                "relatedProposalId='" + relatedProposalId + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link References}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link References}.
     */
    public static class Builder {
        private String relatedProposalId;

        /**
         * Sets the related proposal ID.
         *
         * @param relatedProposalId the related proposal ID
         * @return this builder instance
         */
        public Builder relatedProposalId(String relatedProposalId) {
            this.relatedProposalId = relatedProposalId;
            return this;
        }

        /**
         * Builds the {@link References}.
         *
         * @return the built references
         */
        public References build() {
            return new References(this);
        }
    }
}
