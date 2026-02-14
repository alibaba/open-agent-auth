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
import java.util.List;
import java.util.Objects;

/**
 * OAuth Scope policy model.
 * <p>
 * Follows OAuth 2.0 standards (RFC 6749, RFC 8707) for scope-based authorization.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScopePolicy {
    
    @JsonProperty("version")
    private final String version;
    
    @JsonProperty("scopes")
    private final List<ScopeDefinition> scopes;
    
    @JsonCreator
    private ScopePolicy(
        @JsonProperty("version") String version,
        @JsonProperty("scopes") List<ScopeDefinition> scopes
    ) {
        this.version = version != null ? version : "1.0";
        this.scopes = scopes != null ? Collections.unmodifiableList(scopes) : List.of();
    }
    
    public String getVersion() {
        return version;
    }
    
    public List<ScopeDefinition> getScopes() {
        return scopes;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ScopePolicy that = (ScopePolicy) o;
        return Objects.equals(version, that.version) &&
                Objects.equals(scopes, that.scopes);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(version, scopes);
    }
    
    @Override
    public String toString() {
        return "ScopePolicy{" +
                "version='" + version + '\'' +
                ", scopes=" + scopes +
                '}';
    }
    
    /**
     * Scope definition.
     */
    public static class ScopeDefinition {
        
        @JsonProperty("name")
        private final String name;
        
        @JsonProperty("description")
        private final String description;
        
        @JsonProperty("resources")
        private final List<String> resources;
        
        @JsonCreator
        private ScopeDefinition(
            @JsonProperty("name") String name,
            @JsonProperty("description") String description,
            @JsonProperty("resources") List<String> resources
        ) {
            this.name = name;
            this.description = description;
            this.resources = resources != null ? Collections.unmodifiableList(resources) : List.of();
        }
        
        public String getName() {
            return name;
        }
        
        public String getDescription() {
            return description;
        }
        
        public List<String> getResources() {
            return resources;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ScopeDefinition that = (ScopeDefinition) o;
            return Objects.equals(name, that.name) &&
                    Objects.equals(description, that.description) &&
                    Objects.equals(resources, that.resources);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(name, description, resources);
        }
        
        @Override
        public String toString() {
            return "ScopeDefinition{" +
                    "name='" + name + '\'' +
                    ", description='" + description + '\'' +
                    ", resources=" + resources +
                    '}';
        }
    }
}
