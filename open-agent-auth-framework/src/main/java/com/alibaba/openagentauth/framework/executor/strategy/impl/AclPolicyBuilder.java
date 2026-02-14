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
package com.alibaba.openagentauth.framework.executor.strategy.impl;

import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.executor.strategy.PolicyBuilder;

import java.util.Map;

/**
 * ACL (Access Control List) policy builder implementation.
 * <p>
 * Generates ACL policies with principal-resource-permission mappings.
 * This builder creates JSON-formatted policies with entries defining access rules.
 * </p>
 *
 * @since 1.0
 */
public class AclPolicyBuilder implements PolicyBuilder {
    
    /**
     * Default policy version.
     */
    private static final String DEFAULT_VERSION = "1.0";
    
    private final String version;
    
    /**
     * Creates a new AclPolicyBuilder with default version.
     */
    public AclPolicyBuilder() {
        this(DEFAULT_VERSION);
    }
    
    /**
     * Creates a new AclPolicyBuilder with custom version.
     *
     * @param version the policy version
     */
    public AclPolicyBuilder(String version) {
        this.version = version;
    }
    
    @Override
    public String buildPolicy(RequestAuthUrlRequest request) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"version\": \"").append(version).append("\",\n");
        json.append("  \"entries\": [\n");
        json.append("    {\n");
        
        // Principal (extracted from metadata or use operation type)
        String principal = request.getMetadata() != null 
            ? (String) request.getMetadata().getOrDefault("principal", request.getOperationType())
            : request.getOperationType();
        json.append("      \"principal\": \"").append(principal).append("\",\n");
        
        // Resource
        if (request.getResourceId() != null) {
            json.append("      \"resource\": \"").append(request.getResourceId()).append("\",\n");
        } else {
            json.append("      \"resource\": \"*\",\n");
        }
        
        // Permissions (use operation type as permission)
        json.append("      \"permissions\": [\"").append(request.getOperationType()).append("\"],\n");
        
        // Effect
        json.append("      \"effect\": \"ALLOW\"\n");
        json.append("    }\n");
        
        // Add additional entries from metadata if specified
        if (request.getMetadata() != null && request.getMetadata().containsKey("acl_entries")) {
            Object entries = request.getMetadata().get("acl_entries");
            if (entries instanceof java.util.List) {
                for (Object entry : (java.util.List<?>) entries) {
                    if (entry instanceof Map<?, ?> entryMap) {
                        json.append("    ,{\n");

                        if (entryMap.containsKey("principal")) {
                            json.append("      \"principal\": \"").append(entryMap.get("principal")).append("\",\n");
                        }
                        if (entryMap.containsKey("resource")) {
                            json.append("      \"resource\": \"").append(entryMap.get("resource")).append("\",\n");
                        }
                        if (entryMap.containsKey("permissions")) {
                            Object perms = entryMap.get("permissions");
                            if (perms instanceof java.util.List) {
                                json.append("      \"permissions\": [");
                                boolean first = true;
                                for (Object perm : (java.util.List<?>) perms) {
                                    if (!first) {
                                        json.append(", ");
                                    }
                                    json.append("\"").append(perm).append("\"");
                                    first = false;
                                }
                                json.append("],\n");
                            }
                        }
                        if (entryMap.containsKey("effect")) {
                            json.append("      \"effect\": \"").append(entryMap.get("effect")).append("\"\n");
                        } else {
                            json.append("      \"effect\": \"ALLOW\"\n");
                        }
                        json.append("    }\n");
                    }
                }
            }
        }
        
        json.append("  ]\n");
        json.append("}");
        
        return json.toString();
    }
    
    /**
     * Creates a new AclPolicyBuilder with default settings.
     *
     * @return a new AclPolicyBuilder instance
     */
    public static AclPolicyBuilder create() {
        return new AclPolicyBuilder();
    }
    
    /**
     * Creates a new AclPolicyBuilder with custom version.
     *
     * @param version the policy version
     * @return a new AclPolicyBuilder instance
     */
    public static AclPolicyBuilder create(String version) {
        return new AclPolicyBuilder(version);
    }
}
