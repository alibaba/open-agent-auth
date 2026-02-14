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
package com.alibaba.openagentauth.core.model.evidence;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Represents evidence in the form of a JWT-based Verifiable Credential (JWT-VC).
 * This evidence captures the user's original natural-language input and provides
 * cryptographic proof of its authenticity.
 * <p>
 * According to draft-liu-agent-operation-authorization-01 Section 4.2, the evidence
 * claim contains the following fields:
 * </p>
 * <table border="1">
 *   <tr><th>Field</th><th>Description</th><th>Status</th></tr>
 *   <tr><td>source_prompt_credential</td><td>Source Prompt Credential - JWT-VC containing the original prompt</td><td>REQUIRED</td></tr>
 * </table>
 * <p>
 * The evidence contains only the source_prompt_credential (a JWT string), not the full
 * VC structure. The actual VC structure is embedded within the JWT itself.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Evidence {

    @JsonProperty("source_prompt_credential")
    private final String sourcePromptCredential;

    private Evidence(Builder builder) {
        this.sourcePromptCredential = builder.sourcePromptCredential;
    }

    /**
     * Source Prompt Credential field.
     * <p>
     * A JWT-VC (Verifiable Credential) that holds the original user prompt credential,
     * providing cryptographic proof of the user's original intent.
     * According to draft-liu-agent-operation-authorization-01 Section 4.2, this field is REQUIRED
     * when the evidence claim is present.
     * </p>
     * <p>
     * The JWT contains the full Verifiable Credential structure with the user's
     * original input and cryptographic proof.
     * </p>
     *
     * @return the source prompt credential JWT
     */
    public String getSourcePromptCredential() {
        return sourcePromptCredential;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Evidence evidence = (Evidence) o;
        return Objects.equals(sourcePromptCredential, evidence.sourcePromptCredential);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourcePromptCredential);
    }

    @Override
    public String toString() {
        return "Evidence{" +
                "sourcePromptCredential='" + sourcePromptCredential + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link Evidence}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link Evidence}.
     */
    public static class Builder {
        private String sourcePromptCredential;

        /**
         * Sets the source prompt credential.
         * <p>
         * This field is REQUIRED.
         * </p>
         *
         * @param sourcePromptCredential the source prompt credential JWT
         * @return this builder instance
         */
        public Builder sourcePromptCredential(String sourcePromptCredential) {
            this.sourcePromptCredential = sourcePromptCredential;
            return this;
        }

        /**
         * Builds the {@link Evidence}.
         *
         * @return the built evidence
         */
        public Evidence build() {
            return new Evidence(this);
        }
    }
}