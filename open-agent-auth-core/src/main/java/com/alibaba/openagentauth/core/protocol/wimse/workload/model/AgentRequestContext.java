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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Context for an agent request.
 * <p>
 * This class provides contextual information for agent requests, including
 * the operation type, resource information, and metadata.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentRequestContext {
    
    @JsonProperty("operationType")
    private final String operationType;
    
    @JsonProperty("resourceId")
    private final String resourceId;
    
    @JsonProperty("metadata")
    private final Map<String, Object> metadata;
    
    @JsonProperty("prompt")
    private final String prompt;
    
    @JsonProperty("publicKey")
    private final String publicKey;

    @JsonProperty("clientId")
    private final String clientId;

    @JsonCreator
    public AgentRequestContext(
            @JsonProperty("operationType") String operationType,
            @JsonProperty("resourceId") String resourceId,
            @JsonProperty("metadata") Map<String, Object> metadata,
            @JsonProperty("prompt") String prompt,
            @JsonProperty("publicKey") String publicKey,
            @JsonProperty("clientId") String clientId
    ) {
        this.operationType = operationType;
        this.resourceId = resourceId;
        this.metadata = metadata;
        this.prompt = prompt;
        this.publicKey = publicKey;
        this.clientId = clientId;
    }
    
    public String getOperationType() { return operationType; }
    public String getResourceId() { return resourceId; }
    public Map<String, Object> getMetadata() { return metadata; }
    public String getPrompt() { return prompt; }
    public String getPublicKey() { return publicKey; }
    public String getClientId() { return clientId; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String operationType;
        private String resourceId;
        private Map<String, Object> metadata;
        private String prompt;
        private String publicKey;
        private String clientId;

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

        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public AgentRequestContext build() {
            return new AgentRequestContext(operationType, resourceId, metadata, prompt, publicKey, clientId);
        }
    }
}
