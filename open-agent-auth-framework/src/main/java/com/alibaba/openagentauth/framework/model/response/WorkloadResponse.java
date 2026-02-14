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
package com.alibaba.openagentauth.framework.model.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Response DTO for workload information.
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkloadResponse {

    @JsonProperty("workloadId")
    private String workloadId;

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("publicKey")
    private String publicKey;

    @JsonProperty("createdAt")
    private Instant createdAt;

    @JsonProperty("expiresAt")
    private Instant expiresAt;

    @JsonProperty("status")
    private String status;

    public String getWorkloadId() {
        return workloadId;
    }

    public void setWorkloadId(String workloadId) {
        this.workloadId = workloadId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String workloadId;
        private String userId;
        private String publicKey;
        private Instant createdAt;
        private Instant expiresAt;
        private String status;

        public Builder workloadId(String workloadId) {
            this.workloadId = workloadId;
            return this;
        }

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder createdAt(Instant createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder expiresAt(Instant expiresAt) {
            this.expiresAt = expiresAt;
            return this;
        }

        public Builder status(String status) {
            this.status = status;
            return this;
        }

        public WorkloadResponse build() {
            WorkloadResponse response = new WorkloadResponse();
            response.workloadId = this.workloadId;
            response.userId = this.userId;
            response.publicKey = this.publicKey;
            response.createdAt = this.createdAt;
            response.expiresAt = this.expiresAt;
            response.status = this.status;
            return response;
        }
    }
}
