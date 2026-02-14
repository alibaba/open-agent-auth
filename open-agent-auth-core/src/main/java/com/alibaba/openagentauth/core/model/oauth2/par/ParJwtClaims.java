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
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Immutable representation of claims extracted from a validated Pushed Authorization Request JWT (PAR-JWT).
 * <p>
 * This class provides a structured view of the authorization request data as defined in
 * IETF draft-liu-agent-operation-authorization-01. The PAR-JWT is used in the first phase of the
 * Agent Operation Authorization framework to deliver the user's original input and the agent-proposed
 * operational strategy to the Authorization Server (AS).
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * </p>
 * <pre>{@code
 * ParJwtClaims claims = ParJwtClaims.builder()
 *     .issuer("https://client.myassistant.example")
 *     .subject("user_12345@myassistant.example")
 *     .audience(List.of("https://as.online-shop.example"))
 *     .issueTime(new Date())
 *     .expirationTime(new Date(System.currentTimeMillis() + 3600000))
 *     .jwtId(UUID.randomUUID().toString())
 *     .evidence(evidence)
 *     .agentUserBindingProposal(bindingProposal)
 *     .operationProposal("package agent\nallow { input.transaction.amount <= 50.0 }")
 *     .context(context)
 *     .build();
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9126">RFC 9126 - OAuth 2.0 Pushed Authorization Requests</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
 *     draft-liu-agent-operation-authorization-01 - Agent Operation Authorization</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">
 *     draft-ietf-wimse-workload-creds - Workload Identity Credentials</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ParJwtClaims {

    /**
     * Issuer claim (iss).
     * <p>
     * Identifies the principal that issued the PAR-JWT.
     * According to RFC 7519 Section 4.1.1, this claim identifies the issuer
     * of the JWT. In the context of Agent Operation Authorization, the issuer
     * is typically the AI Agent client identifier (e.g., "https://client.myassistant.example").
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 Section 4.1.1</a>
     */
    @JsonProperty("iss")
    private final String issuer;

    /**
     * Subject claim (sub).
     * <p>
     * Identifies the principal that is the subject of the PAR-JWT.
     * According to RFC 7519 Section 4.1.2, this claim identifies the subject
     * of the JWT. In the context of Agent Operation Authorization, the subject
     * is the user identifier on behalf of whom the agent is acting
     * (e.g., "user_12345@myassistant.example").
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 Section 4.1.2</a>
     */
    @JsonProperty("sub")
    private final String subject;

    /**
     * Audience claim (aud).
     * <p>
     * Identifies the recipients that the JWT is intended for.
     * According to RFC 7519 Section 4.1.3, this claim identifies the recipients
     * that the JWT is intended for. In the context of Agent Operation Authorization,
     * the audience MUST be the Authorization Server URI (e.g., "https://as.online-shop.example").
     * </p>
     * <p>
     * <b>Security Note:</b> The audience claim MUST be validated to ensure the PAR-JWT
     * is only processed by the intended Authorization Server, preventing token redirection attacks.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</a>
     */
    @JsonProperty("aud")
    private final List<String> audience;

    /**
     * Issued At claim (iat).
     * <p>
     * Identifies the time at which the JWT was issued.
     * According to RFC 7519 Section 4.1.6, this claim identifies the time at which
     * the JWT was issued. This value MUST be a NumericDate representing seconds
     * since 1970-01-01T00:00:00Z UTC.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</a>
     */
    @JsonProperty("iat")
    private final Date issueTime;

    /**
     * Expiration Time claim (exp).
     * <p>
     * Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
     * According to RFC 7519 Section 4.1.4, this claim identifies the expiration time.
     * This value MUST be a NumericDate representing seconds since 1970-01-01T00:00:00Z UTC.
     * </p>
     * <p>
     * <b>Security Note:</b> Implementations MUST reject JWTs with an expiration time in the past.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</a>
     */
    @JsonProperty("exp")
    private final Date expirationTime;

    /**
     * JWT ID claim (jti).
     * <p>
     * Provides a unique identifier for the JWT.
     * According to RFC 7519 Section 4.1.7, this claim provides a unique identifier
     * for the JWT. The identifier value MUST be assigned in a manner that ensures
     * that there is a negligible probability that the same value will be accidentally
     * assigned to a different JWT.
     * </p>
     * <p>
     * <b>Security Note:</b> The jti claim can be used to prevent replay attacks.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 Section 4.1.7</a>
     */
    @JsonProperty("jti")
    private final String jwtId;

    /**
     * Evidence claim.
     * <p>
     * Contains the user's original natural-language input in the form of a JWT-based
     * Verifiable Credential (JWT-VC). This provides cryptographic proof of the user's
     * original intent and serves as the evidentiary starting point for the authorization request.
     * </p>
     * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 3, the evidence
     * field is a JWT in JSON-VC format, generated by the agent client and included in
     * the PAR-JWT. The evidence contains a sourcePromptCredential JWT that holds the
     * original user prompt with cryptographic proof.
     * </p>
     * <p>
     * <b>Security Note:</b> The evidence MUST be validated to ensure it has not been tampered
     * with and was issued by a trusted agent client.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C Verifiable Credentials Data Model</a>
     */
    @JsonProperty("evidence")
    private final Evidence evidence;

    /**
     * Agent User Binding Proposal claim.
     * <p>
     * A structured JSON object proposed by the client (e.g., an AI agent) to describe
     * its own identity context when acting on behalf of a user. In the Agent Operation
     * Authorization Request (i.e., the PAR-JWT), this claim represents a _proposal_
     * of the agent-to-user binding and is _not yet cryptographically endorsed_ by the
     * Authorization Server (AS).
     * </p>
     * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 3, this claim contains:
     * </p>
     * <ul>
     *   <li>{@code user_identity_token}: A verifiable identity token (OpenID Connect ID Token)</li>
     *   <li>{@code agent_workload_token}: A verifiable workload identity token (WIT)</li>
     *   <li>{@code device_fingerprint}: An optional device identifier</li>
     * </ul>
     * <p>
     * <b>Security Note:</b> The Authorization Server MUST validate both the user_identity_token
     * and agent_workload_token to establish the identities of the user and agent before
     * issuing an authorization token.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">
     *     draft-ietf-wimse-workload-creds</a>
     */
    @JsonProperty("agent_user_binding_proposal")
    private final AgentUserBindingProposal agentUserBindingProposal;

    /**
     * Agent Operation Proposal claim.
     * <p>
     * A Rego policy string proposed by the agent for authorization evaluation.
     * This claim is used in the initial authorization request to convey a policy that,
     * upon validation and registration by the Authorization Server, will be referenced
     * via a policy_id in subsequent access tokens.
     * </p>
     * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 3, this field
     * should be a valid Rego policy string for OPA (Open Policy Agent) enforcement.
     * Example: "package agent\nallow { input.transaction.amount <= 50.0 }"
     * </p>
     * <p>
     * <b>Security Note:</b> The policy MUST be validated by the Authorization Server to ensure
     * it does not contain malicious or overly broad permissions.
     * </p>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     * @see <a href="https://www.openpolicyagent.org/">Open Policy Agent (OPA)</a>
     */
    @JsonProperty("agent_operation_proposal")
    private final String operationProposal;

    /**
     * Context claim.
     * <p>
     * A structured claim providing contextual information for policy evaluation,
     * including user and agent identity attributes, device characteristics, channel,
     * and locale. This claim serves as the input data for Open Policy Agent (OPA)
     * enforcement decisions.
     * </p>
    * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 3, the context
     * field is a structured input format for OPA decision-making and contains:
     * </p>
     * <ul>
     *   <li>{@code channel}: The communication channel (e.g., "mobile-app")</li>
     *   <li>{@code deviceFingerprint}: The device identifier</li>
     *   <li>{@code language}: The language/locale (e.g., "zh-CN")</li>
     *   <li>{@code user}: User-specific context information</li>
     *   <li>{@code agent}: Agent-specific context information</li>
     * </ul>
     * <p>
     * <b>Requirement:</b> REQUIRED
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 Section 3</a>
     * @see <a href="https://datatracker.ietf.org/doc/html/draft-liu-agent-operation-authorization/">
     *     draft-liu-agent-operation-authorization-01 - context claim registration</a>
     */
    @JsonProperty("context")
    private final OperationRequestContext context;

    /**
     * State claim.
     * <p>
     * An opaque value used to maintain state between the request and the callback.
     * This parameter is used for CSRF protection and session restoration in the
     * OAuth 2.0 authorization flow. According to RFC 6749 Section 4.1.1, the state
     * parameter is RECOMMENDED to prevent CSRF attacks.
     * </p>
     * <p>
     * <b>Security Note:</b> The state parameter MUST be validated in the callback
     * to ensure it matches the value sent in the initial authorization request.
     * This prevents CSRF attacks where an attacker attempts to trick the user
     * into authorizing a malicious client.
     * </p>
     * <p>
     * <b>Requirement:</b> OPTIONAL
     * </p>
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">RFC 6749 Section 4.1.1</a>
     */
    @JsonProperty("state")
    private final String state;

    /**
     * Constructs a new ParJwtClaims object.
     *
     * @param builder the builder used to construct this object
     */
    private ParJwtClaims(Builder builder) {
        this.issuer = builder.issuer;
        this.subject = builder.subject;
        this.audience = builder.audience;
        this.issueTime = builder.issueTime;
        this.expirationTime = builder.expirationTime;
        this.jwtId = builder.jwtId;
        this.evidence = builder.evidence;
        this.agentUserBindingProposal = builder.agentUserBindingProposal;
        this.operationProposal = builder.operationProposal;
        this.context = builder.context;
        this.state = builder.state;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public List<String> getAudience() {
        return audience;
    }

    public Date getIssueTime() {
        return issueTime;
    }

    public Date getExpirationTime() {
        return expirationTime;
    }

    public String getJwtId() {
        return jwtId;
    }

    public Evidence getEvidence() {
        return evidence;
    }

    public AgentUserBindingProposal getAgentUserBindingProposal() {
        return agentUserBindingProposal;
    }

    public String getOperationProposal() {
        return operationProposal;
    }

    public OperationRequestContext getContext() {
        return context;
    }

    public String getState() {
        return state;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParJwtClaims that = (ParJwtClaims) o;
        return Objects.equals(issuer, that.issuer) &&
               Objects.equals(subject, that.subject) &&
               Objects.equals(audience, that.audience) &&
               Objects.equals(issueTime, that.issueTime) &&
               Objects.equals(expirationTime, that.expirationTime) &&
               Objects.equals(jwtId, that.jwtId) &&
               Objects.equals(evidence, that.evidence) &&
               Objects.equals(agentUserBindingProposal, that.agentUserBindingProposal) &&
               Objects.equals(operationProposal, that.operationProposal) &&
               Objects.equals(context, that.context) &&
               Objects.equals(state, that.state);
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, subject, audience, issueTime, expirationTime,
                          jwtId, evidence, agentUserBindingProposal, operationProposal, context, state);
    }

    @Override
    public String toString() {
        return "ParJwtClaims{" +
                "issuer='" + issuer + '\'' +
                ", subject='" + subject + '\'' +
                ", audience=" + audience +
                ", issueTime=" + issueTime +
                ", expirationTime=" + expirationTime +
                ", jwtId='" + jwtId + '\'' +
                ", evidence=" + evidence +
                ", agentUserBindingProposal=" + agentUserBindingProposal +
                ", operationProposal='" + operationProposal + '\'' +
                ", context=" + context +
                ", state='" + state + '\'' +
                '}';
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link ParJwtClaims}.
     */
    public static class Builder {
        private String issuer;
        private String subject;
        private List<String> audience;
        private Date issueTime;
        private Date expirationTime;
        private String jwtId;
        private Evidence evidence;
        private AgentUserBindingProposal agentUserBindingProposal;
        private String operationProposal;
        private OperationRequestContext context;
        private String state;

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder subject(String subject) {
            this.subject = subject;
            return this;
        }

        public Builder audience(List<String> audience) {
            this.audience = audience;
            return this;
        }

        public Builder issueTime(Date issueTime) {
            this.issueTime = issueTime;
            return this;
        }

        public Builder expirationTime(Date expirationTime) {
            this.expirationTime = expirationTime;
            return this;
        }

        public Builder jwtId(String jwtId) {
            this.jwtId = jwtId;
            return this;
        }

        public Builder evidence(Evidence evidence) {
            this.evidence = evidence;
            return this;
        }

        public Builder agentUserBindingProposal(AgentUserBindingProposal agentUserBindingProposal) {
            this.agentUserBindingProposal = agentUserBindingProposal;
            return this;
        }

        public Builder operationProposal(String operationProposal) {
            this.operationProposal = operationProposal;
            return this;
        }

        public Builder context(OperationRequestContext context) {
            this.context = context;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public ParJwtClaims build() {
            return new ParJwtClaims(this);
        }
    }
}