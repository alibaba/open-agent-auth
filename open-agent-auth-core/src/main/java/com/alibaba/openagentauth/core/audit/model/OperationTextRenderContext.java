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
package com.alibaba.openagentauth.core.audit.model;

import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;

import java.time.Instant;
import java.util.Objects;

/**
 * Immutable context object for operation text rendering.
 * <p>
 * This class encapsulates all the information needed by an {@link OperationTextRenderer}
 * to generate a human-readable description of an authorized operation. It follows the
 * Parameter Object pattern to avoid long parameter lists and provides a clean API
 * for rendering strategies.
 * </p>
 * <p>
 * The context includes:
 * </p>
 * <ul>
 *   <li><b>operationProposal</b>: The Rego policy string from the agent's proposal</li>
 *   <li><b>originalPrompt</b>: The user's original natural-language input (decrypted)</li>
 *   <li><b>requestContext</b>: Contextual information (channel, agent, user)</li>
 *   <li><b>verifiedCredential</b>: The verified (and possibly decrypted) evidence VC</li>
 *   <li><b>tokenExpiration</b>: When the authorization token expires</li>
 * </ul>
 *
 * @see OperationTextRenderer
 * @since 1.0
 */
public class OperationTextRenderContext {

    /**
     * The Rego policy string from the agent's operation proposal.
     * Describes the authorized operations in a machine-readable format.
     */
    private final String operationProposal;

    /**
     * The user's original natural-language input (decrypted from the JWT-VC evidence).
     * Used to provide intent provenance in the audit trail.
     */
    private final String originalPrompt;

    /**
     * Contextual information about the request, including channel, agent, and user details.
     */
    private final OperationRequestContext requestContext;

    /**
     * The verified (and possibly decrypted) Verifiable Credential from the evidence.
     * Contains the source prompt credential and associated metadata.
     */
    private final VerifiableCredential verifiedCredential;

    /**
     * The expiration time of the authorization token being generated.
     * Used to include validity period information in the rendered text.
     */
    private final Instant tokenExpiration;

    /**
     * Constructs a new context from the given builder.
     *
     * @param builder the builder containing all context values
     */
    private OperationTextRenderContext(Builder builder) {
        this.operationProposal = builder.operationProposal;
        this.originalPrompt = builder.originalPrompt;
        this.requestContext = builder.requestContext;
        this.verifiedCredential = builder.verifiedCredential;
        this.tokenExpiration = builder.tokenExpiration;
    }

    /**
     * Returns the Rego policy string from the agent's operation proposal.
     *
     * @return the operation proposal, or null if not set
     */
    public String getOperationProposal() {
        return operationProposal;
    }

    /**
     * Returns the user's original natural-language input.
     *
     * @return the original prompt, or null if not available
     */
    public String getOriginalPrompt() {
        return originalPrompt;
    }

    /**
     * Returns the contextual information about the request.
     *
     * @return the request context, or null if not set
     */
    public OperationRequestContext getRequestContext() {
        return requestContext;
    }

    /**
     * Returns the verified Verifiable Credential from the evidence.
     *
     * @return the verified credential, or null if not available
     */
    public VerifiableCredential getVerifiedCredential() {
        return verifiedCredential;
    }

    /**
     * Returns the expiration time of the authorization token.
     *
     * @return the token expiration instant, or null if not set
     */
    public Instant getTokenExpiration() {
        return tokenExpiration;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OperationTextRenderContext that = (OperationTextRenderContext) o;
        return Objects.equals(operationProposal, that.operationProposal)
                && Objects.equals(originalPrompt, that.originalPrompt)
                && Objects.equals(requestContext, that.requestContext)
                && Objects.equals(verifiedCredential, that.verifiedCredential)
                && Objects.equals(tokenExpiration, that.tokenExpiration);
    }

    @Override
    public int hashCode() {
        return Objects.hash(operationProposal, originalPrompt, requestContext,
                verifiedCredential, tokenExpiration);
    }

    @Override
    public String toString() {
        return "OperationTextRenderContext{" +
                "operationProposal='" + (operationProposal != null
                    ? operationProposal.substring(0, Math.min(operationProposal.length(), 50)) + "..."
                    : "null") + '\'' +
                ", originalPrompt='" + originalPrompt + '\'' +
                ", requestContext=" + requestContext +
                ", tokenExpiration=" + tokenExpiration +
                '}';
    }

    /**
     * Creates a new builder for constructing {@link OperationTextRenderContext} instances.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing {@link OperationTextRenderContext} instances.
     * <p>
     * All fields are optional; unset fields default to null.
     * </p>
     */
    public static class Builder {

        private String operationProposal;
        private String originalPrompt;
        private OperationRequestContext requestContext;
        private VerifiableCredential verifiedCredential;
        private Instant tokenExpiration;

        /**
         * Sets the Rego policy string from the agent's operation proposal.
         *
         * @param operationProposal the operation proposal policy
         * @return this builder for chaining
         */
        public Builder operationProposal(String operationProposal) {
            this.operationProposal = operationProposal;
            return this;
        }

        /**
         * Sets the user's original natural-language input.
         *
         * @param originalPrompt the original user prompt
         * @return this builder for chaining
         */
        public Builder originalPrompt(String originalPrompt) {
            this.originalPrompt = originalPrompt;
            return this;
        }

        /**
         * Sets the contextual information about the request.
         *
         * @param requestContext the request context
         * @return this builder for chaining
         */
        public Builder requestContext(OperationRequestContext requestContext) {
            this.requestContext = requestContext;
            return this;
        }

        /**
         * Sets the verified Verifiable Credential from the evidence.
         *
         * @param verifiedCredential the verified credential
         * @return this builder for chaining
         */
        public Builder verifiedCredential(VerifiableCredential verifiedCredential) {
            this.verifiedCredential = verifiedCredential;
            return this;
        }

        /**
         * Sets the expiration time of the authorization token.
         *
         * @param tokenExpiration the token expiration instant
         * @return this builder for chaining
         */
        public Builder tokenExpiration(Instant tokenExpiration) {
            this.tokenExpiration = tokenExpiration;
            return this;
        }

        /**
         * Builds a new {@link OperationTextRenderContext} from this builder's values.
         *
         * @return a new immutable context instance
         */
        public OperationTextRenderContext build() {
            return new OperationTextRenderContext(this);
        }
    }
}
