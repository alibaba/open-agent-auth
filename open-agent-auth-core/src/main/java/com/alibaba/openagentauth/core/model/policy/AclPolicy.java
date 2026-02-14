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
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * ACL (Access Control List) policy model.
 * <p>
 * Simple and intuitive permission model with principal-resource-permission mappings.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AclPolicy {
    
    @JsonProperty("version")
    private final String version;
    
    @JsonProperty("entries")
    private final List<AclEntry> entries;
    
    @JsonCreator
    private AclPolicy(
        @JsonProperty("version") String version,
        @JsonProperty("entries") List<AclEntry> entries
    ) {
        this.version = version != null ? version : "1.0";
        this.entries = entries != null ? Collections.unmodifiableList(entries) : List.of();
    }
    
    public String getVersion() {
        return version;
    }
    
    public List<AclEntry> getEntries() {
        return entries;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AclPolicy aclPolicy = (AclPolicy) o;
        return Objects.equals(version, aclPolicy.version) &&
                Objects.equals(entries, aclPolicy.entries);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(version, entries);
    }
    
    @Override
    public String toString() {
        return "AclPolicy{" +
                "version='" + version + '\'' +
                ", entries=" + entries +
                '}';
    }
    
    /**
     * ACL entry.
     */
    public static class AclEntry {
        
        @JsonProperty("principal")
        private final String principal;
        
        @JsonProperty("resource")
        private final String resource;
        
        @JsonProperty("permissions")
        private final Set<String> permissions;
        
        @JsonProperty("effect")
        private final AclEffect effect;
        
        @JsonCreator
        private AclEntry(
            @JsonProperty("principal") String principal,
            @JsonProperty("resource") String resource,
            @JsonProperty("permissions") List<String> permissions,
            @JsonProperty("effect") AclEffect effect
        ) {
            this.principal = principal;
            this.resource = resource;
            this.permissions = permissions != null 
                ? Collections.unmodifiableSet(new HashSet<>(permissions)) 
                : Set.of();
            this.effect = effect != null ? effect : AclEffect.ALLOW;
        }
        
        public String getPrincipal() {
            return principal;
        }
        
        public String getResource() {
            return resource;
        }
        
        public Set<String> getPermissions() {
            return permissions;
        }
        
        public AclEffect getEffect() {
            return effect;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AclEntry aclEntry = (AclEntry) o;
            return Objects.equals(principal, aclEntry.principal) &&
                    Objects.equals(resource, aclEntry.resource) &&
                    Objects.equals(permissions, aclEntry.permissions) &&
                    effect == aclEntry.effect;
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(principal, resource, permissions, effect);
        }
        
        @Override
        public String toString() {
            return "AclEntry{" +
                    "principal='" + principal + '\'' +
                    ", resource='" + resource + '\'' +
                    ", permissions=" + permissions +
                    ", effect=" + effect +
                    '}';
        }
    }
    
    /**
     * ACL effect enum.
     */
    public enum AclEffect {
        ALLOW, DENY
    }
}
