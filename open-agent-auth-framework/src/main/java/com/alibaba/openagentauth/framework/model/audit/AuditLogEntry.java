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
package com.alibaba.openagentauth.framework.model.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Audit log entry for access attempts.
 * <p>
 * This class encapsulates information about an access attempt for audit
 * purposes, including request details, validation results, and authorization decision.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditLogEntry {
    
    @JsonProperty("timestamp")
    private final Instant timestamp;
    
    @JsonProperty("userId")
    private final String userId;
    
    @JsonProperty("workloadId")
    private final String workloadId;
    
    @JsonProperty("operationType")
    private final String operationType;
    
    @JsonProperty("resourceId")
    private final String resourceId;
    
    @JsonProperty("decision")
    private final String decision;
    
    @JsonProperty("reason")
    private final String reason;
    
    @JsonProperty("ipAddress")
    private final String ipAddress;
    
    @JsonProperty("userAgent")
    private final String userAgent;
    
    @JsonCreator
    public AuditLogEntry(
            @JsonProperty("timestamp") Instant timestamp,
            @JsonProperty("userId") String userId,
            @JsonProperty("workloadId") String workloadId,
            @JsonProperty("operationType") String operationType,
            @JsonProperty("resourceId") String resourceId,
            @JsonProperty("decision") String decision,
            @JsonProperty("reason") String reason,
            @JsonProperty("ipAddress") String ipAddress,
            @JsonProperty("userAgent") String userAgent
    ) {
        this.timestamp = timestamp;
        this.userId = userId;
        this.workloadId = workloadId;
        this.operationType = operationType;
        this.resourceId = resourceId;
        this.decision = decision;
        this.reason = reason;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }
    
    public Instant getTimestamp() { return timestamp; }
    public String getUserId() { return userId; }
    public String getWorkloadId() { return workloadId; }
    public String getOperationType() { return operationType; }
    public String getResourceId() { return resourceId; }
    public String getDecision() { return decision; }
    public String getReason() { return reason; }
    public String getIpAddress() { return ipAddress; }
    public String getUserAgent() { return userAgent; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private Instant timestamp;
        private String userId;
        private String workloadId;
        private String operationType;
        private String resourceId;
        private String decision;
        private String reason;
        private String ipAddress;
        private String userAgent;
        
        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }
        
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }
        
        public Builder workloadId(String workloadId) {
            this.workloadId = workloadId;
            return this;
        }
        
        public Builder operationType(String operationType) {
            this.operationType = operationType;
            return this;
        }
        
        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }
        
        public Builder decision(String decision) {
            this.decision = decision;
            return this;
        }
        
        public Builder reason(String reason) {
            this.reason = reason;
            return this;
        }
        
        public Builder ipAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }
        
        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }
        
        public AuditLogEntry build() {
            return new AuditLogEntry(timestamp, userId, workloadId, operationType,
                                     resourceId, decision, reason, ipAddress, userAgent);
        }
    }
}
