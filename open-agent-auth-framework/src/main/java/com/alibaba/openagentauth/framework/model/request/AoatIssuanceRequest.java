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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Map;

/**
 * Request for issuing an Agent Operation Authorization Token.
 * <p>
 * This class contains all the information needed to generate an AOAT,
 * including user identity, workload identity, operation proposal, and
 * audit trail information.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AoatIssuanceRequest {
    
    @JsonProperty("userId")
    private final String userId;
    
    @JsonProperty("workloadId")
    private final String workloadId;
    
    @JsonProperty("policyId")
    private final String policyId;
    
    @JsonProperty("operationProposal")
    private final String operationProposal;

    @JsonProperty("evidence")
    private final Map<String, Object> evidence;

    @JsonProperty("auditTrail")
    private final Map<String, Object> auditTrail;
    
    @JsonProperty("expiresAt")
    private final Instant expiresAt;
    
    @JsonProperty("authorizationCode")
    private final String authorizationCode;
    
    @JsonProperty("redirectUri")
    private final String redirectUri;
    
    @JsonCreator
    public AoatIssuanceRequest(
            @JsonProperty("userId") String userId,
            @JsonProperty("workloadId") String workloadId,
            @JsonProperty("policyId") String policyId,
            @JsonProperty("operationProposal") String operationProposal,
            @JsonProperty("evidence") Map<String, Object> evidence,
            @JsonProperty("auditTrail") Map<String, Object> auditTrail,
            @JsonProperty("expiresAt") Instant expiresAt,
            @JsonProperty("authorizationCode") String authorizationCode,
            @JsonProperty("redirectUri") String redirectUri
    ) {
        this.userId = userId;
        this.workloadId = workloadId;
        this.policyId = policyId;
        this.operationProposal = operationProposal;
        this.evidence = evidence;
        this.auditTrail = auditTrail;
        this.expiresAt = expiresAt;
        this.authorizationCode = authorizationCode;
        this.redirectUri = redirectUri;
    }
    
    public String getUserId() { return userId; }
    public String getWorkloadId() { return workloadId; }
    public String getPolicyId() { return policyId; }
    public String getOperationProposal() { return operationProposal; }
    public Map<String, Object> getEvidence() { return evidence; }
    public Map<String, Object> getAuditTrail() { return auditTrail; }
    public Instant getExpiresAt() { return expiresAt; }
    public String getAuthorizationCode() { return authorizationCode; }
    public String getRedirectUri() { return redirectUri; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String userId;
        private String workloadId;
        private String policyId;
        private String operationProposal;
        private Map<String, Object> evidence;
        private Map<String, Object> auditTrail;
        private Instant expiresAt;
        private String authorizationCode;
        private String redirectUri;
        
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }
        
        public Builder workloadId(String workloadId) {
            this.workloadId = workloadId;
            return this;
        }
        
        public Builder policyId(String policyId) {
            this.policyId = policyId;
            return this;
        }
        
        public Builder operationProposal(String operationProposal) {
            this.operationProposal = operationProposal;
            return this;
        }
        
        public Builder evidence(Map<String, Object> evidence) {
            this.evidence = evidence;
            return this;
        }
        
        public Builder auditTrail(Map<String, Object> auditTrail) {
            this.auditTrail = auditTrail;
            return this;
        }
        
        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }
        
        public Builder authorizationCode(String authorizationCode) {
            this.authorizationCode = authorizationCode;
            return this;
        }
        
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        
        public AoatIssuanceRequest build() {
            return new AoatIssuanceRequest(userId, workloadId, policyId, operationProposal, 
                                         evidence, auditTrail, expiresAt, authorizationCode, redirectUri);
        }
    }
}
