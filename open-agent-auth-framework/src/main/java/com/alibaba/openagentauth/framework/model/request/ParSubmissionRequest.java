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
package com.alibaba.openagentauth.framework.model.request;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.proposal.AgentOperationProposal;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * Request for submitting a Pushed Authorization Request (PAR) to the Authorization Server.
 * <p>
 * This class encapsulates all the parameters needed to submit a PAR request according to
 * RFC 9126 and draft-liu-agent-operation-authorization-01 specification.
 * </p>
 * <p>
 * The Builder pattern allows developers to construct requests with only the parameters
 * they need, while sensible defaults are provided for optional fields.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ParSubmissionRequest {
    
    /**
     * The workload context containing WIT and user identity.
     * This field is REQUIRED.
     */
    private final WorkloadContext workloadContext;
    
    /**
     * The operation proposal containing the Rego policy.
     * This field is REQUIRED.
     */
    private final AgentOperationProposal operationProposal;
    
    /**
     * The evidence supporting the authorization request (e.g., Prompt VC).
     * This field is REQUIRED.
     */
    private final Evidence evidence;
    
    /**
     * The user identity token (ID Token) for user binding.
     * This field is REQUIRED for the agent user binding proposal.
     */
    private final String userIdentityToken;
    
    /**
     * The operation request context for policy evaluation.
     * This field is OPTIONAL. If not provided, defaults will be constructed from workloadContext.
     */
    private final OperationRequestContext context;
    
    /**
     * The expiration time in seconds for the PAR-JWT.
     * This field is OPTIONAL. Default is 3600 seconds (1 hour).
     */
    private final Integer expirationSeconds;

    /**
     * The state parameter for CSRF protection and session restoration.
     * This field is OPTIONAL. If provided, it will be passed through the OAuth flow.
     */
    private final String state;

    private ParSubmissionRequest(Builder builder) {
        this.workloadContext = builder.workloadContext;
        this.operationProposal = builder.operationProposal;
        this.evidence = builder.evidence;
        this.userIdentityToken = builder.userIdentityToken;
        this.context = builder.context;
        this.expirationSeconds = builder.expirationSeconds;
        this.state = builder.state;
    }
    
    public WorkloadContext getWorkloadContext() {
        return workloadContext;
    }
    
    public AgentOperationProposal getOperationProposal() {
        return operationProposal;
    }
    
    public Evidence getEvidence() {
        return evidence;
    }
    
    public String getUserIdentityToken() {
        return userIdentityToken;
    }
    
    public OperationRequestContext getContext() {
        return context;
    }
    
    public Integer getExpirationSeconds() {
        return expirationSeconds;
    }

    public String getState() {
        return state;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ParSubmissionRequest that = (ParSubmissionRequest) o;
        return Objects.equals(workloadContext, that.workloadContext) &&
               Objects.equals(operationProposal, that.operationProposal) &&
               Objects.equals(evidence, that.evidence) &&
               Objects.equals(userIdentityToken, that.userIdentityToken) &&
               Objects.equals(context, that.context) &&
               Objects.equals(expirationSeconds, that.expirationSeconds) &&
               Objects.equals(state, that.state);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(workloadContext, operationProposal, evidence, userIdentityToken, context, expirationSeconds);
    }
    
    @Override
    public String toString() {
        return "ParSubmissionRequest{" +
                "workloadContext=" + workloadContext +
                ", operationProposal=" + operationProposal +
                ", evidence=" + evidence +
                ", userIdentityToken='" + userIdentityToken + '\'' +
                ", context=" + context +
                ", expirationSeconds=" + expirationSeconds +
                ", state='" + state + '\'' +
                '}';
    }
    
    /**
     * Creates a new builder for {@link ParSubmissionRequest}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for {@link ParSubmissionRequest}.
     * <p>
     * This builder provides a fluent interface for constructing PAR submission requests.
     * Required fields must be set before calling build().
     * Optional fields have sensible defaults.
     * </p>
     */
    public static class Builder {
        private WorkloadContext workloadContext;
        private AgentOperationProposal operationProposal;
        private Evidence evidence;
        private String userIdentityToken;
        private OperationRequestContext context;
        private Integer expirationSeconds = 3600; // Default: 1 hour
        private String state;
        
        /**
         * Sets the workload context.
         * <p>
         * This field is REQUIRED.
         * </p>
         *
         * @param workloadContext the workload context
         * @return this builder instance
         */
        public Builder workloadContext(WorkloadContext workloadContext) {
            this.workloadContext = workloadContext;
            return this;
        }
        
        /**
         * Sets the operation proposal.
         * <p>
         * This field is REQUIRED.
         * </p>
         *
         * @param operationProposal the operation proposal
         * @return this builder instance
         */
        public Builder operationProposal(AgentOperationProposal operationProposal) {
            this.operationProposal = operationProposal;
            return this;
        }
        
        /**
         * Sets the evidence.
         * <p>
         * This field is REQUIRED.
         * </p>
         *
         * @param evidence the evidence
         * @return this builder instance
         */
        public Builder evidence(Evidence evidence) {
            this.evidence = evidence;
            return this;
        }
        
        /**
         * Sets the user identity token.
         * <p>
         * This field is REQUIRED for the agent user binding proposal.
         * </p>
         *
         * @param userIdentityToken the user identity token (ID Token)
         * @return this builder instance
         */
        public Builder userIdentityToken(String userIdentityToken) {
            this.userIdentityToken = userIdentityToken;
            return this;
        }
        
        /**
         * Sets the operation request context.
         * <p>
         * This field is OPTIONAL. If not provided, defaults will be constructed from workloadContext.
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
         * Sets the expiration time in seconds for the PAR-JWT.
         * <p>
         * This field is OPTIONAL. Default is 3600 seconds (1 hour).
         * </p>
         *
         * @param expirationSeconds the expiration time in seconds
         * @return this builder instance
         */
        public Builder expirationSeconds(Integer expirationSeconds) {
            this.expirationSeconds = expirationSeconds;
            return this;
        }

        /**
         * Sets the state parameter for CSRF protection and session restoration.
         * <p>
         * This field is OPTIONAL. If provided, it will be passed through the OAuth flow.
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
         * Builds the {@link ParSubmissionRequest}.
         * <p>
         * Validates that all required fields are set before building.
         * </p>
         *
         * @return the built request
         * @throws IllegalArgumentException if required fields are missing
         */
        public ParSubmissionRequest build() {
            ValidationUtils.validateNotNull(workloadContext, "workloadContext");
            ValidationUtils.validateNotNull(operationProposal, "operationProposal");
            ValidationUtils.validateNotNull(evidence, "evidence is required");
            ValidationUtils.validateNotEmpty(userIdentityToken, "userIdentityToken");
            return new ParSubmissionRequest(this);
        }
    }
}