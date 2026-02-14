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

import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Objects;

/**
 * Request for preparing authorization context for tool execution.
 * <p>
 * This class encapsulates the parameters needed to generate the necessary
 * authorization context (WIT, WPT, AOAT) for tool execution.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PrepareAuthorizationContextRequest {
    
    /**
     * The workload context containing WIT.
     * This field is REQUIRED.
     */
    private final WorkloadContext workloadContext;
    
    /**
     * The Agent Operation Authorization Token.
     * This field is REQUIRED.
     */
    private final AgentOperationAuthToken aoat;
    
    private PrepareAuthorizationContextRequest(Builder builder) {
        this.workloadContext = builder.workloadContext;
        this.aoat = builder.aoat;
    }
    
    public WorkloadContext getWorkloadContext() {
        return workloadContext;
    }
    
    public AgentOperationAuthToken getAoat() {
        return aoat;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrepareAuthorizationContextRequest that = (PrepareAuthorizationContextRequest) o;
        return Objects.equals(workloadContext, that.workloadContext) &&
               Objects.equals(aoat, that.aoat);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(workloadContext, aoat);
    }
    
    @Override
    public String toString() {
        return "PrepareAuthorizationContextRequest{" +
                "workloadContext=" + workloadContext +
                ", aoat=" + aoat +
                '}';
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private WorkloadContext workloadContext;
        private AgentOperationAuthToken aoat;
        
        public Builder workloadContext(WorkloadContext workloadContext) {
            this.workloadContext = workloadContext;
            return this;
        }
        
        public Builder aoat(AgentOperationAuthToken aoat) {
            this.aoat = aoat;
            return this;
        }
        
        public PrepareAuthorizationContextRequest build() {
            ValidationUtils.validateNotNull(workloadContext, "workloadContext");
            ValidationUtils.validateNotNull(aoat, "aoat");
            return new PrepareAuthorizationContextRequest(this);
        }
    }
}