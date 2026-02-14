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
package com.alibaba.openagentauth.core.protocol.wimse.workload.model;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Request for issuing a Workload Identity Token (WIT).
 * <p>
 * This class encapsulates the parameters needed to issue a Workload Identity Token
 * according to the WIMSE (Workload Identity Management and Secure Exchange) protocol.
 * It combines the operation request context with the agent-user binding proposal
 * to establish a secure identity binding between the agent and the user.
 * </p>
 * <p>
 * According to draft-ietf-wimse-workload-creds, this request structure enables:
 * </p>
 * <ul>
 *   <li><b>Contextual Information:</b> Provides comprehensive context for policy evaluation</li>
 *   <li><b>Identity Binding:</b> Establishes the relationship between user and agent identities</li>
 *   <li><b>Trust Validation:</b> Enables validation of both user and agent credentials</li>
 *   <li><b>Policy Enforcement:</b> Supports authorization decisions based on operation context</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">draft-ietf-wimse-workload-creds</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IssueWitRequest {

    /**
     * The operation request context.
     * <p>
     * This field is REQUIRED and contains comprehensive contextual information
     * for policy evaluation, including user identity, agent identity, device
     * characteristics, channel, and locale information.
     * </p>
     * <p>
     * This context enables fine-grained authorization decisions based on
     * various factors in the request environment.
     * </p>
     */
    @JsonProperty("context")
    private final OperationRequestContext context;

    /**
     * The agent-user binding proposal.
     * <p>
     * This field is REQUIRED and contains the structured proposal for binding
     * the agent's identity to the user's identity. It includes:
     * </p>
     * <ul>
     *   <li>user_identity_token: A verifiable identity token for the end user</li>
     *   <li>agent_workload_token: A verifiable workload identity token for the agent</li>
     *   <li>device_fingerprint: An optional device identifier for enhanced security</li>
     * </ul>
     * <p>
     * The Authorization Server validates these tokens to establish the identity
     * of both the user and the agent before issuing the Workload Identity Token.
     * </p>
     */
    @JsonProperty("proposal")
    private final AgentUserBindingProposal proposal;

    /**
     * The public key for the workload identity.
     * <p>
     * This field is REQUIRED as a framework extension to the standard model.
     * It contains the public key that will be used to verify the workload identity
     * token (WIT) signature. The corresponding private key is held by the agent
     * and used to sign the workload identity token.
     * </p>
     * <p>
     * <b>Framework Extension:</b> This field is not part of the standard
     * draft-liu-agent-operation-authorization specification but is required
     * by the framework for workload identity token generation and validation.
     * </p>
     * <p>
     * The public key format should be in PEM or JWK format, depending on the
     * cryptographic algorithm being used (e.g., RSA, ECDSA, EdDSA).
     * </p>
     */
    @JsonProperty("publicKey")
    private final String publicKey;

    /**
     * The OAuth 2.0 client identifier.
     * <p>
     * This field is REQUIRED and identifies the OAuth 2.0 client that initiated
     * the authentication request. The client_id is used to:
     * </p>
     * <ul>
     *   <li>Identify the application or service making the request</li>
     *   <li>Apply client-specific policies and restrictions</li>
     *   <li>Track usage and audit access patterns</li>
     *   <li>Support multi-tenant scenarios with multiple clients</li>
     * </ul>
     * <p>
     * This field aligns with OAuth 2.0 (RFC 6749) and OpenID Connect (OIDC)
     * specifications for client identification. The Authorization Server uses
     * this identifier to look up client registration metadata, validate client
     * credentials, and enforce client-specific authorization policies.
     * </p>
     */
    @JsonProperty("oauthClientId")
    private final String oauthClientId;

    /**
     * Constructor for Jackson deserialization.
     *
     * @param context the operation request context
     * @param proposal the agent-user binding proposal
     * @param publicKey the public key for the workload identity (framework extension)
     * @param oauthClientId the OAuth 2.0 client identifier
     */
    @JsonCreator
    public IssueWitRequest(
            @JsonProperty("context") OperationRequestContext context,
            @JsonProperty("proposal") AgentUserBindingProposal proposal,
            @JsonProperty("publicKey") String publicKey,
            @JsonProperty("oauthClientId") String oauthClientId
    ) {
        this.context = context;
        this.proposal = proposal;
        this.publicKey = publicKey;
        this.oauthClientId = oauthClientId;
    }

    /**
     * Constructor for builder pattern.
     *
     * @param builder the builder instance
     */
    private IssueWitRequest(Builder builder) {
        this.context = builder.context;
        this.proposal = builder.proposal;
        this.publicKey = builder.publicKey;
        this.oauthClientId = builder.oauthClientId;
    }

    /**
     * Gets the operation request context.
     *
     * @return the operation request context
     */
    public OperationRequestContext getContext() {
        return context;
    }

    /**
     * Gets the agent-user binding proposal.
     *
     * @return the agent-user binding proposal
     */
    public AgentUserBindingProposal getProposal() {
        return proposal;
    }

    /**
     * Gets the public key for the workload identity.
     *
     * @return the public key
     */
    public String getPublicKey() {
        return publicKey;
    }

    /**
     * Gets the OAuth 2.0 client identifier.
     *
     * @return the OAuth client identifier
     */
    public String getOauthClientId() {
        return oauthClientId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssueWitRequest that = (IssueWitRequest) o;
        return Objects.equals(context, that.context) &&
               Objects.equals(proposal, that.proposal) &&
               Objects.equals(publicKey, that.publicKey) &&
               Objects.equals(oauthClientId, that.oauthClientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(context, proposal, publicKey, oauthClientId);
    }

    @Override
    public String toString() {
        return "IssueWitRequest{" +
                "context=" + context +
                ", proposal=" + proposal +
                ", publicKey='" + publicKey + '\'' +
                ", oauthClientId='" + oauthClientId + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link IssueWitRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link IssueWitRequest}.
     * <p>
     * This builder provides a fluent API for constructing IssueWitRequest instances
     * with proper validation of required fields.
     * </p>
     */
    public static class Builder {

        /**
         * Fields for {@link IssueWitRequest}.
         */
        private OperationRequestContext context;
        private AgentUserBindingProposal proposal;
        private String publicKey;
        private String oauthClientId;

        /**
         * Sets the operation request context.
         * <p>
         * This field is REQUIRED and must contain comprehensive contextual
         * information for policy evaluation.
         * </p>
         *
         * @param context the operation request context
         * @return this builder instance
         */
        public Builder context(OperationRequestContext context) {
            this.context = context;
            return this;
        }

        /**
         * Sets the agent-user binding proposal.
         * <p>
         * This field is REQUIRED and must contain the proposal for binding
         * the agent's identity to the user's identity.
         * </p>
         *
         * @param proposal the agent-user binding proposal
         * @return this builder instance
         */
        public Builder proposal(AgentUserBindingProposal proposal) {
            this.proposal = proposal;
            return this;
        }

        /**
         * Sets the public key for the workload identity.
         * <p>
         * This field is REQUIRED and must contain the public key that will be
         * used to verify the workload identity token signature.
         * </p>
         *
         * @param publicKey the public key
         * @return this builder instance
         */
        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        /**
         * Sets the OAuth 2.0 client identifier.
         * <p>
         * This field is REQUIRED and must contain the client identifier that
         * initiated the authentication request.
         * </p>
         *
         * @param oauthClientId the OAuth client identifier
         * @return this builder instance
         */
        public Builder oauthClientId(String oauthClientId) {
            this.oauthClientId = oauthClientId;
            return this;
        }

        /**
         * Builds the {@link IssueWitRequest}.
         * <p>
         * This method validates that all required fields are present before
         * constructing the request object.
         * </p>
         *
         * @return the built issue WIT request
         * @throws IllegalArgumentException if any required field is null
         */
        public IssueWitRequest build() {
            ValidationUtils.validateNotNull(context, "Operation request context is required");
            ValidationUtils.validateNotNull(proposal, "Agent user binding proposal is required");
            ValidationUtils.validateNotNull(oauthClientId, "OAuth client identifier is required");
            return new IssueWitRequest(this);
        }
    }
}