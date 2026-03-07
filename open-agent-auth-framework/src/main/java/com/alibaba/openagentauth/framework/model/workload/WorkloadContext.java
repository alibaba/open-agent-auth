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
package com.alibaba.openagentauth.framework.model.workload;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Context for a virtual workload.
 * <p>
 * This class encapsulates the context information for a virtual workload,
 * including the WIT, key pair, and lifecycle information.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkloadContext {
    
    @JsonProperty("workloadId")
    private final String workloadId;
    
    @JsonProperty("userId")
    private final String userId;
    
    @JsonProperty("wit")
    private final String wit;
    
    @JsonProperty("publicKey")
    private final String publicKey;
    
    @JsonIgnore
    private final String privateKey;
    
    @JsonProperty("expiresAt")
    private final Instant expiresAt;

    /**
     * The OAuth 2.0 client_id obtained from Dynamic Client Registration (DCR).
     * <p>
     * This field stores the client_id returned by the Authorization Server after
     * a successful DCR request (RFC 7591). It is used for subsequent PAR and Token
     * requests to identify this workload as a registered OAuth client.
     * </p>
     */
    @JsonProperty("oauthClientId")
    private final String oauthClientId;
    
    @JsonCreator
    public WorkloadContext(
            @JsonProperty("workloadId") String workloadId,
            @JsonProperty("userId") String userId,
            @JsonProperty("wit") String wit,
            @JsonProperty("publicKey") String publicKey,
            @JsonProperty("privateKey") String privateKey,
            @JsonProperty("expiresAt") Instant expiresAt,
            @JsonProperty("oauthClientId") String oauthClientId
    ) {
        this.workloadId = workloadId;
        this.userId = userId;
        this.wit = wit;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.expiresAt = expiresAt;
        this.oauthClientId = oauthClientId;
    }
    
    public String getWorkloadId() { return workloadId; }
    public String getUserId() { return userId; }
    public String getWit() { return wit; }
    public String getPublicKey() { return publicKey; }
    @JsonIgnore
    public String getPrivateKey() { return privateKey; }
    public Instant getExpiresAt() { return expiresAt; }
    public String getOauthClientId() { return oauthClientId; }
    
    public boolean isExpired() {
        if (expiresAt == null) {
            return false;
        }
        return Instant.now().isAfter(expiresAt);
    }
    
    @Override
    public String toString() {
        return "WorkloadContext{"
                + "workloadId='" + workloadId + '\''
                + ", userId='" + userId + '\''
                + ", wit='" + (wit != null ? wit.substring(0, Math.min(wit.length(), 8)) + "..." : "null") + '\''
                + ", publicKey='" + (publicKey != null ? publicKey.substring(0, Math.min(publicKey.length(), 8)) + "..." : "null") + '\''
                + ", privateKey='[REDACTED]'"
                + ", expiresAt=" + expiresAt
                + ", oauthClientId='" + oauthClientId + '\''
                + '}';
    }

    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String workloadId;
        private String userId;
        private String wit;
        private String publicKey;
        private String privateKey;
        private Instant expiresAt;
        private String oauthClientId;
        
        public Builder workloadId(String workloadId) {
            this.workloadId = workloadId;
            return this;
        }
        
        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }
        
        public Builder wit(String wit) {
            this.wit = wit;
            return this;
        }
        
        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }
        
        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }
        
        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder oauthClientId(String oauthClientId) {
            this.oauthClientId = oauthClientId;
            return this;
        }
        
        public WorkloadContext build() {
            return new WorkloadContext(workloadId, userId, wit, publicKey, privateKey, expiresAt, oauthClientId);
        }
    }
}
