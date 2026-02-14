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
package com.alibaba.openagentauth.core.model.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * OPA (Open Policy Agent) policy model.
 * <p>
 * Represents a Rego policy that can be evaluated by the Open Policy Agent.
 * This model encapsulates the Rego policy definition along with metadata
 * needed for evaluation via OPA REST API.
 * </p>
 * <p>
 * <b>Example Policy:</b></p>
 * <pre>
 * {
 *   "version": "1.0",
 *   "packageName": "authz",
 *   "ruleName": "allow",
 *   "description": "Agent operation authorization policy",
 *   "regoPolicy": "package authz\n\nallow {\n  input.user == input.resource.owner\n}",
 *   "data": {
 *     "roles": ["admin", "user"],
 *     "permissions": ["read", "write"]
 *   }
 * }
 * </pre>
 * </p>
 *
 * @see <a href="https://www.openpolicyagent.org/docs/latest/policy-language/">OPA Policy Language</a>
 * @see <a href="https://www.openpolicyagent.org/docs/latest/rest-api/">OPA REST API</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OpaPolicy {
    
    @JsonProperty("version")
    private final String version;
    
    @JsonProperty("packageName")
    private final String packageName;
    
    @JsonProperty("ruleName")
    private final String ruleName;
    
    @JsonProperty("regoPolicy")
    private final String regoPolicy;
    
    @JsonProperty("description")
    private final String description;
    
    @JsonProperty("data")
    private final Map<String, Object> data;
    
    @JsonCreator
    private OpaPolicy(
        @JsonProperty("version") String version,
        @JsonProperty("packageName") String packageName,
        @JsonProperty("ruleName") String ruleName,
        @JsonProperty("regoPolicy") String regoPolicy,
        @JsonProperty("description") String description,
        @JsonProperty("data") Map<String, Object> data
    ) {
        this.version = version != null ? version : "1.0";
        this.packageName = packageName != null ? packageName : "default";
        this.ruleName = ruleName != null ? ruleName : "allow";
        this.regoPolicy = regoPolicy;
        this.description = description;
        this.data = data != null ? Collections.unmodifiableMap(data) : Map.of();
    }
    
    public String getVersion() {
        return version;
    }
    
    public String getPackageName() {
        return packageName;
    }
    
    public String getRuleName() {
        return ruleName;
    }
    
    public String getRegoPolicy() {
        return regoPolicy;
    }
    
    public String getDescription() {
        return description;
    }
    
    public Map<String, Object> getData() {
        return data;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OpaPolicy opaPolicy = (OpaPolicy) o;
        return Objects.equals(version, opaPolicy.version) &&
                Objects.equals(packageName, opaPolicy.packageName) &&
                Objects.equals(ruleName, opaPolicy.ruleName) &&
                Objects.equals(regoPolicy, opaPolicy.regoPolicy) &&
                Objects.equals(description, opaPolicy.description) &&
                Objects.equals(data, opaPolicy.data);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(version, packageName, ruleName, regoPolicy, description, data);
    }
    
    @Override
    public String toString() {
        return "OpaPolicy{" +
                "version='" + version + '\'' +
                ", packageName='" + packageName + '\'' +
                ", ruleName='" + ruleName + '\'' +
                ", regoPolicy='" + (regoPolicy != null ? regoPolicy.substring(0, Math.min(50, regoPolicy.length())) + "..." : "null") + '\'' +
                ", description='" + description + '\'' +
                ", data=" + data +
                '}';
    }
    
    /**
     * Builder for creating OpaPolicy instances.
     */
    public static class Builder {
        private String version;
        private String packageName;
        private String ruleName;
        private String regoPolicy;
        private String description;
        private Map<String, Object> data;
        
        public Builder() {
        }
        
        public Builder version(String version) {
            this.version = version;
            return this;
        }
        
        public Builder packageName(String packageName) {
            this.packageName = packageName;
            return this;
        }
        
        public Builder ruleName(String ruleName) {
            this.ruleName = ruleName;
            return this;
        }
        
        public Builder regoPolicy(String regoPolicy) {
            this.regoPolicy = regoPolicy;
            return this;
        }
        
        public Builder description(String description) {
            this.description = description;
            return this;
        }
        
        public Builder data(Map<String, Object> data) {
            this.data = data;
            return this;
        }
        
        public OpaPolicy build() {
            return new OpaPolicy(version, packageName, ruleName, regoPolicy, description, data);
        }
    }
}
