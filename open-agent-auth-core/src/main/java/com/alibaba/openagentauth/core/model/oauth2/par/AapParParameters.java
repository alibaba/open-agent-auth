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
package com.alibaba.openagentauth.core.model.oauth2.par;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.Objects;

/**
 * Parameter object for constructing a Pushed Authorization Request JWT (PAR-JWT).
 * <p>
 * This class encapsulates all required parameters and metadata needed to generate
 * a PAR-JWT according to the IETF draft-liu-agent-operation-authorization-01 specification.
 * It implements the Parameter Object pattern (Martin Fowler) to reduce method parameter count
 * and improve API usability.
 * </p>
 * <p>
 * <b>Protocol Context:</b></p>
 * <p>
 * In the Agent Operation Authorization framework, the PAR-JWT serves as the initial
 * authorization request from an AI agent to the Authorization Server (AS). It contains:
 * </p>
 * <ul>
 *   <li><b>Evidence:</b> Cryptographic proof of the user's original input (JWT-VC format)</li>
 *   <li><b>Agent User Binding Proposal:</b> Proposed binding between user and agent identities</li>
 *   <li><b>Agent Operation Proposal:</b> Rego policy defining the requested authorization scope</li>
 *   <li><b>Context:</b> Runtime environment information for policy evaluation</li>
 * </ul>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * // Build the PAR-JWT parameters
 * ParJwtParameters parameters = ParJwtParameters.builder()
 *     .agentUserBindingProposal(bindingProposal)
 *     .evidence(evidence)
 *     .operationProposal(operationProposal)
 *     .context(context)
 *     .expirationSeconds(3600) // 1 hour expiration
 *     .build();
 *
 * // Generate the PAR-JWT
 * String parJwt = parJwtGenerator.generateParJwt(parameters);
 * }</pre>
 * <p>
 * <b>Security Considerations:</b></p>
 * <ul>
 *   <li>The expirationSeconds value SHOULD be set appropriately based on the
 *       sensitivity of the operation and the expected authorization latency</li>
 *   <li>All contained objects (Evidence, Proposals, Context) MUST be properly
 *       validated by the generator before JWT creation</li>
 *   <li>The generated PAR-JWT MUST be signed before transmission to the AS</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
 *     draft-liu-agent-operation-authorization - Agent Operation Authorization</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">
 *     draft-ietf-wimse-workload-creds - Workload Identity Credentials</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
 * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a>
 * @since 1.0
 */
public class AapParParameters {

    private final AgentUserBindingProposal agentUserBindingProposal;
    private final Evidence evidence;
    private final AgentOperationProposal operationProposal;
    private final OperationRequestContext context;
    private final long expirationSeconds;
    private final String userId;
    private final String clientId;
    private final String redirectUri;
    private final String state;

    private AapParParameters(Builder builder) {
        this.agentUserBindingProposal = builder.agentUserBindingProposal;
        this.evidence = builder.evidence;
        this.operationProposal = builder.operationProposal;
        this.context = builder.context;
        this.expirationSeconds = builder.expirationSeconds;
        this.userId = builder.userId;
        this.clientId = builder.clientId;
        this.redirectUri = builder.redirectUri;
        this.state = builder.state;
    }

    /**
     * Returns the agent user binding proposal.
     * <p>
     * This field represents the proposed binding between the agent and the user.
     * It contains:
     * </p>
     * <ul>
     *   <li><b>user_identity_token:</b> OpenID Connect ID Token or equivalent
     *       verifiable identity token for the end user</li>
     *   <li><b>agent_workload_token:</b> Workload Identity Token (WIT) for the agent
     *       as defined in draft-ietf-wimse-workload-creds</li>
     *   <li><b>device_fingerprint:</b> Optional device identifier for enhanced security</li>
     * </ul>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED
     * </p>
     * <p>
     * <b>Security Note:</b> The Authorization Server MUST validate both tokens
     * to establish the identities of the user and agent before issuing an authorization token.
     * This proposal is not yet cryptographically endorsed by the AS.
     * </p>
     *
     * @return the agent user binding proposal, never null
     * @see AgentUserBindingProposal
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     */
    public AgentUserBindingProposal getAgentUserBindingProposal() {
        return agentUserBindingProposal;
    }

    /**
     * Returns the evidence claim.
     * <p>
     * This field contains the user's original natural-language input in the form of
     * a JWT-based Verifiable Credential (JWT-VC). It provides cryptographic proof of
     * the user's original intent and serves as the evidentiary starting point for
     * the authorization request.
     * </p>
     * <p>
     * The evidence structure contains:
     * </p>
     * <ul>
     *   <li><b>sourcePromptCredential:</b> A JWT-VC holding the original user prompt
     *       with cryptographic proof</li>
     * </ul>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED
     * </p>
     * <p>
     * <b>Security Note:</b> The evidence MUST be validated to ensure it has not been
     * tampered with and was issued by a trusted agent client. This prevents
     * manipulation of the user's original input.
     * </p>
     *
     * @return the evidence claim, never null
     * @see Evidence
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 4.2</a>
     * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
     */
    public Evidence getEvidence() {
        return evidence;
    }

    /**
     * Gets the agent operation proposal.
     * <p>
     * This field contains a Rego policy string proposed by the agent for authorization
     * evaluation. The policy defines the authorization scope and rules for the operation
     * the agent is requesting to perform on behalf of the user.
     * </p>
     * <p>
     * The policy is written in Rego (Open Policy Agent policy language) and typically
     * includes:
     * </p>
     * <ul>
     *   <li>Resource access rules</li>
     *   <li>Operation constraints</li>
     *   <li>Time-based restrictions</li>
     *   <li>Context-based authorization conditions</li>
     * </ul>
     * <p>
     * Example policy: {@code "package agent\nallow { input.transaction.amount <= 50.0 }"}
     * </p>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED
     * </p>
     * <p>
     * <b>Security Note:</b> The Authorization Server MUST validate this policy to ensure
     * it does not contain malicious or overly broad permissions. Upon successful validation,
     * the AS registers the policy and issues an authorization token with a policy_id
     * referencing this registered policy.
     * </p>
     *
     * @return the agent operation proposal, never null
     * @see AgentOperationProposal
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Rego Policy Language</a>
     */
    public AgentOperationProposal getOperationProposal() {
        return operationProposal;
    }

    /**
     * Returns the operation request context.
     * <p>
     * This field provides contextual information for policy evaluation, serving as
     * input data for Open Policy Agent (OPA) enforcement decisions. It enables
     * fine-grained authorization decisions based on various environmental factors.
     * </p>
     * <p>
     * The context structure contains:
     * </p>
     * <ul>
     *   <li><b>channel:</b> Communication channel (e.g., "mobile-app", "web")</li>
     *   <li><b>deviceFingerprint:</b> Device identifier for security tracking</li>
     *   <li><b>language:</b> Language/locale (e.g., "en-US", "zh-CN")</li>
     *   <li><b>user:</b> User-specific context (ID, attributes)</li>
     *   <li><b>agent:</b> Agent-specific context (instance, platform, client)</li>
     * </ul>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED
     * </p>
     * <p>
     * <b>Usage Note:</b> The context data is directly used as input to the Rego policy
     * evaluation engine. Ensure all required fields are populated for proper policy enforcement.
     * </p>
     *
     * @return the operation request context, never null
     * @see OperationRequestContext
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     */
    public OperationRequestContext getContext() {
        return context;
    }

    /**
     * Returns the token expiration time in seconds from now.
     * <p>
     * This value determines when the generated PAR-JWT will expire. The expiration
     * time is calculated as {@code current_time + expirationSeconds} when the JWT
     * is generated.
     * </p>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED, MUST be positive
     * </p>
     * <p>
     * <b>Security Note:</b> Choose an appropriate expiration time based on:
     * </p>
     * <ul>
     *   <li>Sensitivity of the requested operation</li>
     *   <li>Expected authorization latency</li>
     *   <li>User interaction requirements (if consent is needed)</li>
     * </ul>
     * <p>
     * Recommended values:
     * </p>
     * <ul>
     *   <li>300-600 seconds (5-10 minutes): For operations requiring user consent</li>
     *   <li>1800-3600 seconds (30-60 minutes): For automated operations</li>
     * </ul>
     * <p>
     * Implementations MUST reject PAR-JWTs with expiration times in the past.
     * </p>
     *
     * @return the expiration time in seconds, always positive
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</a>
     */
    public long getExpirationSeconds() {
        return expirationSeconds;
    }

    /**
     * Returns the user identifier.
     * <p>
     * This field identifies the user on behalf of whom the agent is acting.
     * It is typically extracted from the user identity token or provided separately
     * for client-side API convenience.
     * </p>
     * <p>
     * <b>Protocol Requirement:</b> OPTIONAL
     * </p>
     * <p>
     * <b>Usage Note:</b> This field is used for client identification and logging.
     * The actual user authentication is performed via the user_identity_token
     * in the agentUserBindingProposal.
     * </p>
     *
     * @return the user identifier, or null if not provided
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns the OAuth client identifier.
     * <p>
     * This field identifies the OAuth client making the PAR request.
     * According to RFC 9126, when using the pure JWT form, the client_id
     * MUST be included in the JWT claims.
     * </p>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED for RFC 9126 compliance
     * </p>
     *
     * @return the client identifier, or null if not provided
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Returns the redirect URI.
     * <p>
     * This field specifies the URI to which the authorization server will redirect
     * the user after authorization. According to RFC 9126, when using the pure JWT form,
     * the redirect_uri MUST be included in the JWT claims.
     * </p>
     * <p>
     * <b>Protocol Requirement:</b> REQUIRED for RFC 9126 compliance
     * </p>
     *
     * @return the redirect URI, or null if not provided
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Returns the state parameter.
     * <p>
     * This field is an opaque value used to maintain state between the request
     * and the callback. It is used for CSRF protection and session restoration
     * in the OAuth 2.0 authorization flow.
     * </p>
     * <p>
     * <b>Protocol Requirement:</b> OPTIONAL
     * </p>
     *
     * @return the state parameter, or null if not provided
     */
    public String getState() {
        return state;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AapParParameters that = (AapParParameters) o;
        return expirationSeconds == that.expirationSeconds &&
                Objects.equals(agentUserBindingProposal, that.agentUserBindingProposal) &&
                Objects.equals(evidence, that.evidence) &&
                Objects.equals(operationProposal, that.operationProposal) &&
                Objects.equals(context, that.context) &&
                Objects.equals(userId, that.userId) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(state, that.state);
    }

    @Override
    public int hashCode() {
        return Objects.hash(agentUserBindingProposal, evidence, operationProposal, context, expirationSeconds, userId, clientId, redirectUri, state);
    }

    @Override
    public String toString() {
        return "ParJwtParameters{" +
                "agentUserBindingProposal=" + agentUserBindingProposal +
                ", evidence=" + evidence +
                ", operationProposal=" + operationProposal +
                ", context=" + context +
                ", expirationSeconds=" + expirationSeconds +
                ", userId='" + userId + '\'' +
                ", clientId='" + clientId + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", state='" + state + '\'' +
                '}';
    }

    /**
     * Builder for creating {@link AapParParameters} instances.
     * <p>
     * This builder provides a fluent API for constructing PAR-JWT parameters
     * with compile-time type safety and validation at build time.
     * </p>
     * <p>
     * <b>Usage Example:</b></p>
     * <pre>{@code
     * ParJwtParameters parameters = ParJwtParameters.builder()
     *     .agentUserBindingProposal(bindingProposal)
     *     .evidence(evidence)
     *     .operationProposal(operationProposal)
     *     .context(context)
     *     .expirationSeconds(3600)
     *     .build();
     * }</pre>
     * <p>
     * <b>Validation:</b> All required fields are validated in the {@link #build()} method,
     * throwing {@link IllegalArgumentException} if any validation fails.
     * </p>
     *
     * @see <a href="https://www.oreilly.com/library/view/effective-java/9780134686097/">Effective Java, Third Edition - Item 2: Consider a builder when faced with many constructor parameters</a>
     */
    public static class Builder {

        private AgentUserBindingProposal agentUserBindingProposal;
        private Evidence evidence;
        private AgentOperationProposal operationProposal;
        private OperationRequestContext context;
        private long expirationSeconds;
        private String userId;
        private String clientId;
        private String redirectUri;
        private String state;

        /**
         * Sets the agent user binding proposal.
         * <p>
         * This field is REQUIRED and establishes the proposed binding between
         * the agent and user identities. It contains the user identity token
         * and agent workload token for authentication.
         * </p>
         *
         * @param agentUserBindingProposal the agent user binding proposal, must not be null
         * @return this builder instance for method chaining
         * @throws IllegalArgumentException if the parameter is null (validated on build)
         */
        public Builder agentUserBindingProposal(AgentUserBindingProposal agentUserBindingProposal) {
            this.agentUserBindingProposal = agentUserBindingProposal;
            return this;
        }

        /**
         * Sets the evidence claim.
         * <p>
         * This field is REQUIRED and contains the JWT-VC proving the provenance
         * of the user's original input. It provides cryptographic proof that the
         * agent's proposal is based on the user's actual original request.
         * </p>
         *
         * @param evidence the evidence claim, must not be null
         * @return this builder instance for method chaining
         * @throws IllegalArgumentException if the parameter is null (validated on build)
         */
        public Builder evidence(Evidence evidence) {
            this.evidence = evidence;
            return this;
        }

        /**
         * Sets the agent operation proposal.
         * <p>
         * This field is REQUIRED and contains the Rego policy string defining
         * the requested authorization scope. The policy will be evaluated by
         * the Authorization Server to determine if the operation should be permitted.
         * </p>
         *
         * @param operationProposal the agent operation proposal, must not be null
         * @return this builder instance for method chaining
         * @throws IllegalArgumentException if the parameter is null (validated on build)
         */
        public Builder operationProposal(AgentOperationProposal operationProposal) {
            this.operationProposal = operationProposal;
            return this;
        }

        /**
         * Sets the operation request context.
         * <p>
         * This field is REQUIRED and provides contextual information for policy
         * evaluation. This includes user and agent attributes, device information,
         * channel, and locale, which serve as input data for the Rego policy engine.
         * </p>
         *
         * @param context the operation request context, must not be null
         * @return this builder instance for method chaining
         * @throws IllegalArgumentException if the parameter is null (validated on build)
         */
        public Builder context(OperationRequestContext context) {
            this.context = context;
            return this;
        }

        /**
         * Sets the token expiration time in seconds from the current time.
         * <p>
         * This field is REQUIRED and MUST be a positive value. The expiration time
         * determines how long the generated PAR-JWT remains valid. Choose an appropriate
         * value based on the operation's sensitivity and expected authorization latency.
         * </p>
         *
         * @param expirationSeconds the expiration time in seconds, must be positive
         * @return this builder instance for method chaining
         * @throws IllegalArgumentException if the parameter is not positive (validated on build)
         */
        public Builder expirationSeconds(long expirationSeconds) {
            if (expirationSeconds <= 0) {
                throw new IllegalArgumentException("Expiration seconds must be positive");
            }
            this.expirationSeconds = expirationSeconds;
            return this;
        }

        /**
         * Sets the user identifier.
         * <p>
         * This field is OPTIONAL and identifies the user on behalf of whom the agent is acting.
         * It is typically extracted from the user identity token or provided separately
         * for client-side API convenience.
         * </p>
         *
         * @param userId the user identifier
         * @return this builder instance for method chaining
         */
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        /**
         * Sets the OAuth client identifier.
         * <p>
         * This field is REQUIRED for RFC 9126 compliance when using pure JWT form.
         * The client_id will be included in the JWT claims.
         * </p>
         *
         * @param clientId the client identifier
         * @return this builder instance for method chaining
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the redirect URI.
         * <p>
         * This field is REQUIRED for RFC 9126 compliance when using pure JWT form.
         * The redirect_uri will be included in the JWT claims.
         * </p>
         *
         * @param redirectUri the redirect URI
         * @return this builder instance
         */
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        /**
         * Sets the state parameter.
         * <p>
         * This field is OPTIONAL and is used to maintain state between the request
         * and the callback. It is used for CSRF protection and session restoration
         * in the OAuth 2.0 authorization flow.
         * </p>
         *
         * @param state the state parameter
         * @return this builder instance
         */
        public Builder state(String state) {
            this.state = state;
            return this;
        }

        /**
         * Builds the {@link AapParParameters} instance.
         * <p>
         * This method validates all required fields following the fail-fast principle
         * and throws an exception if any validation fails. This ensures that only
         * valid parameter objects can be created.
         * </p>
         * <p>
         * <b>Validation Rules:</b></p>
         * <ul>
         *   <li>agentUserBindingProposal: must not be null</li>
         *   <li>evidence: must not be null</li>
         *   <li>operationProposal: must not be null</li>
         *   <li>context: must not be null</li>
         *   <li>expirationSeconds: must be positive</li>
         * </ul>
         *
         * @return a new ParJwtParameters instance with all fields set
         * @throws IllegalArgumentException if any required field is null or invalid
         */
        public AapParParameters build() {
            validate();
            return new AapParParameters(this);
        }

        /**
         * Validates the builder state.
         * <p>
         * This method performs fail-fast validation of all required fields
         * to catch errors early in the construction process. Validation is
         * performed before object instantiation to prevent the creation of
         * invalid parameter objects.
         * </p>
         *
         * @throws IllegalArgumentException if any required field is null or invalid
         */
        private void validate() {
            ValidationUtils.validateNotNull(agentUserBindingProposal, "Agent user binding proposal");
            ValidationUtils.validateNotNull(evidence, "Evidence");
            ValidationUtils.validateNotNull(operationProposal, "Operation proposal");
            ValidationUtils.validateNotNull(context, "Context");
            if (expirationSeconds <= 0) {
                throw new IllegalArgumentException("Expiration seconds must be positive");
            }
        }
    }

    /**
     * Creates a new builder for {@link AapParParameters}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
}