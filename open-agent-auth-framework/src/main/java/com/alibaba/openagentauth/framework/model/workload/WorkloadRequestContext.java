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
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Context information for workload creation.
 * <p>
 * This class provides contextual information needed when creating a virtual
 * workload, such as the operation type, resource requirements, and metadata.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkloadRequestContext {
    
    @JsonProperty("operationType")
    private final String operationType;
    
    @JsonProperty("resourceId")
    private final String resourceId;
    
    @JsonProperty("metadata")
    private final Map<String, Object> metadata;
    
    @JsonCreator
    public WorkloadRequestContext(
            @JsonProperty("operationType") String operationType,
            @JsonProperty("resourceId") String resourceId,
            @JsonProperty("metadata") Map<String, Object> metadata
    ) {
        this.operationType = operationType;
        this.resourceId = resourceId;
        this.metadata = metadata;
    }
    
    public String getOperationType() { return operationType; }
    public String getResourceId() { return resourceId; }
    public Map<String, Object> getMetadata() { return metadata; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String operationType;
        private String resourceId;
        private Map<String, Object> metadata;
        
        public Builder operationType(String operationType) {
            this.operationType = operationType;
            return this;
        }
        
        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }
        
        public Builder metadata(Map<String, Object> metadata) {
            this.metadata = metadata;
            return this;
        }
        
        public WorkloadRequestContext build() {
            return new WorkloadRequestContext(operationType, resourceId, metadata);
        }
    }
}
