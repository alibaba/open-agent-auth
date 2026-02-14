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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

/**
 * Request for creating a virtual workload.
 * <p>
 * This class encapsulates the parameters needed to create a new virtual workload
 * with a unique identity and temporary key pair.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CreateWorkloadRequest {
    
    /**
     * The user's ID Token from Agent User IDP.
     * This field is REQUIRED.
     * Agent IDP needs to validate the ID Token's signature and validity,
     * and extract the user identity (sub claim) for binding.
     */
    @JsonProperty("idToken")
    private final String idToken;
    
    /**
     * The request context.
     * This field is REQUIRED.
     */
    @JsonProperty("context")
    private final AgentRequestContext context;
    
    @JsonCreator
    public CreateWorkloadRequest(
            @JsonProperty("idToken") String idToken,
            @JsonProperty("context") AgentRequestContext context
    ) {
        this.idToken = idToken;
        this.context = context;
    }
    
    public CreateWorkloadRequest(Builder builder) {
        this.idToken = builder.idToken;
        this.context = builder.context;
    }
    
    public String getIdToken() {
        return idToken;
    }
    
    public AgentRequestContext getContext() {
        return context;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CreateWorkloadRequest that = (CreateWorkloadRequest) o;
        return Objects.equals(idToken, that.idToken) &&
               Objects.equals(context, that.context);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(idToken, context);
    }
    
    @Override
    public String toString() {
        return "CreateWorkloadRequest{" +
                "idToken='" + idToken + '\'' +
                ", context=" + context +
                '}';
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String idToken;
        private AgentRequestContext context;
        
        public Builder idToken(String idToken) {
            this.idToken = idToken;
            return this;
        }
        
        public Builder context(AgentRequestContext context) {
            this.context = context;
            return this;
        }
        
        public CreateWorkloadRequest build() {
            if (ValidationUtils.isNullOrEmpty(idToken)) {
                throw new IllegalArgumentException("idToken is required");
            }
            ValidationUtils.validateNotNull(context, "context is required");
            return new CreateWorkloadRequest(this);
        }
    }
}