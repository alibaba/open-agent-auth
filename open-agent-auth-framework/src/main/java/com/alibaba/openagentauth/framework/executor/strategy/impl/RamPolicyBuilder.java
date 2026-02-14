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
 * RAM (Resource Access Management) policy builder implementation.
 * <p>
 * Generates RAM policies similar to AWS IAM and Alibaba Cloud RAM structure.
 * This builder creates JSON-formatted policies with statements, actions, and resources.
 * </p>
 *
 * @since 1.0
 */
public class RamPolicyBuilder implements PolicyBuilder {
    
    /**
     * Default policy version.
     */
    private static final String DEFAULT_VERSION = "1.0";
    
    private final String version;
    
    /**
     * Creates a new RamPolicyBuilder with default version.
     */
    public RamPolicyBuilder() {
        this(DEFAULT_VERSION);
    }
    
    /**
     * Creates a new RamPolicyBuilder with custom version.
     *
     * @param version the policy version
     */
    public RamPolicyBuilder(String version) {
        this.version = version;
    }
    
    @Override
    public String buildPolicy(RequestAuthUrlRequest request) {
        try {
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"version\": \"").append(version).append("\",\n");
            json.append("  \"statement\": [\n");
            json.append("    {\n");
            json.append("      \"effect\": \"ALLOW\",\n");
            json.append("      \"action\": [\"").append(request.getOperationType()).append("\"],\n");
            
            if (request.getResourceId() != null) {
                json.append("      \"resource\": [\"").append(request.getResourceId()).append("\"],\n");
            } else {
                json.append("      \"resource\": [\"*\"],\n");
            }
            
            // Add conditions if metadata exists
            if (request.getMetadata() != null && !request.getMetadata().isEmpty()) {
                json.append("      \"condition\": {\n");
                json.append("        \"operator\": \"StringEquals\",\n");
                json.append("        \"key\": \"context\",\n");
                json.append("        \"value\": {\n");
                boolean first = true;
                for (var entry : request.getMetadata().entrySet()) {
                    if (!first) {
                        json.append(",\n");
                    }
                    json.append("          \"").append(entry.getKey()).append("\": \"").append(entry.getValue()).append("\"");
                    first = false;
                }
                json.append("\n        }\n");
                json.append("      }\n");
            } else {
                // Remove trailing comma
                json.deleteCharAt(json.length() - 1);
                json.deleteCharAt(json.length() - 1);
            }
            
            json.append("    }\n");
            json.append("  ]\n");
            json.append("}");
            
            return json.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build RAM policy", e);
        }
    }
    
    /**
     * Creates a new RamPolicyBuilder with default settings.
     *
     * @return a new RamPolicyBuilder instance
     */
    public static RamPolicyBuilder create() {
        return new RamPolicyBuilder();
    }
    
    /**
     * Creates a new RamPolicyBuilder with custom version.
     *
     * @param version the policy version
     * @return a new RamPolicyBuilder instance
     */
    public static RamPolicyBuilder create(String version) {
        return new RamPolicyBuilder(version);
    }
}
