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

/**
 * OAuth Scope policy builder implementation.
 * <p>
 * Generates OAuth 2.0 scope-based policies following RFC 6749 and RFC 8707 standards.
 * This builder creates JSON-formatted policies with scope definitions and resources.
 * </p>
 *
 * @since 1.0
 */
public class ScopePolicyBuilder implements PolicyBuilder {
    
    /**
     * Default policy version.
     */
    private static final String DEFAULT_VERSION = "1.0";
    
    private final String version;
    
    /**
     * Creates a new ScopePolicyBuilder with default version.
     */
    public ScopePolicyBuilder() {
        this(DEFAULT_VERSION);
    }
    
    /**
     * Creates a new ScopePolicyBuilder with custom version.
     *
     * @param version the policy version
     */
    public ScopePolicyBuilder(String version) {
        this.version = version;
    }
    
    @Override
    public String buildPolicy(RequestAuthUrlRequest request) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"version\": \"").append(version).append("\",\n");
        json.append("  \"scopes\": [\n");
        json.append("    {\n");
        json.append("      \"name\": \"").append(request.getOperationType()).append("\",\n");
        json.append("      \"description\": \"Scope for operation: ").append(request.getOperationType()).append("\",\n");
        json.append("      \"resources\": [");
        
        if (request.getResourceId() != null) {
            json.append("\n        \"").append(request.getResourceId()).append("\"");
        } else {
            json.append("\"*\"");
        }
        
        // Add additional resources from metadata
        if (request.getMetadata() != null && request.getMetadata().containsKey("resources")) {
            Object resources = request.getMetadata().get("resources");
            if (resources instanceof java.util.List) {
                for (Object res : (java.util.List<?>) resources) {
                    json.append(",\n        \"").append(res).append("\"");
                }
            }
        }
        
        json.append("\n      ]\n");
        json.append("    }\n");
        json.append("  ]\n");
        json.append("}");
        
        return json.toString();
    }
    
    /**
     * Creates a new ScopePolicyBuilder with default settings.
     *
     * @return a new ScopePolicyBuilder instance
     */
    public static ScopePolicyBuilder create() {
        return new ScopePolicyBuilder();
    }
    
    /**
     * Creates a new ScopePolicyBuilder with custom version.
     *
     * @param version the policy version
     * @return a new ScopePolicyBuilder instance
     */
    public static ScopePolicyBuilder create(String version) {
        return new ScopePolicyBuilder(version);
    }
}
