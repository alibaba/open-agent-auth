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
package com.alibaba.openagentauth.framework.executor.strategy;

import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;

/**
 * Strategy interface for building Rego policy strings.
 * <p>
 * This interface defines the contract for generating Rego policies from authorization requests.
 * It follows the Strategy Pattern, allowing different policy generation implementations
 * to be plugged in without modifying the orchestration logic.
 * </p>
 *
 * @since 1.0
 */
@FunctionalInterface
public interface PolicyBuilder {
    
    /**
     * Builds a Rego policy string from the authorization request.
     *
     * @param request the authorization request
     * @return the Rego policy string
     */
    String buildPolicy(RequestAuthUrlRequest request);
    
    /**
     * Default policy builder implementation.
     * <p>
     * Generates a standard Rego policy based on operation type, resource ID, and metadata.
     * </p>
     *
     * @return the default policy builder
     */
    static PolicyBuilder defaultBuilder() {
        return request -> {
            StringBuilder rego = new StringBuilder();
            rego.append("package agent\n");
            rego.append("allow {\n");
            rego.append("  input.operationType == \"").append(request.getOperationType()).append("\"\n");
            
            if (request.getResourceId() != null) {
                rego.append("  input.resourceId == \"").append(request.getResourceId()).append("\"\n");
            }
            
            if (request.getMetadata() != null && !request.getMetadata().isEmpty()) {
                rego.append("  # Additional context constraints\n");
                request.getMetadata().forEach((key, value) -> {
                    rego.append("  input.context.").append(key).append(" == \"").append(value).append("\"\n");
                });
            }
            
            rego.append("}\n");
            return rego.toString();
        };
    }
}
