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
package com.alibaba.openagentauth.framework.model.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response for policy registration.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PolicyRegistrationResponse {
    
    @JsonProperty("policyId")
    private final String policyId;
    
    @JsonProperty("success")
    private final boolean success;
    
    @JsonProperty("message")
    private final String message;
    
    @JsonCreator
    public PolicyRegistrationResponse(
            @JsonProperty("policyId") String policyId,
            @JsonProperty("success") boolean success,
            @JsonProperty("message") String message
    ) {
        this.policyId = policyId;
        this.success = success;
        this.message = message;
    }
    
    public String getPolicyId() { return policyId; }
    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String policyId;
        private boolean success;
        private String message;
        
        public Builder policyId(String policyId) {
            this.policyId = policyId;
            return this;
        }
        
        public Builder success(boolean success) {
            this.success = success;
            return this;
        }
        
        public Builder message(String message) {
            this.message = message;
            return this;
        }
        
        public PolicyRegistrationResponse build() {
            return new PolicyRegistrationResponse(policyId, success, message);
        }
    }
}
