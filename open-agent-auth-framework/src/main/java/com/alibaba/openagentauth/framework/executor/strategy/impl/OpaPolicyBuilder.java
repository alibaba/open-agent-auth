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
 * OPA (Open Policy Agent) policy builder implementation.
 * <p>
 * Generates Rego policies formatted for OPA evaluation with proper package structure.
 * This builder creates policies that can be directly evaluated by OPA servers.
 * </p>
 *
 * @since 1.0
 */
public class OpaPolicyBuilder implements PolicyBuilder {
    
    /**
     * Default package name for OPA policies.
     */
    private static final String DEFAULT_PACKAGE = "agent";
    
    /**
     * Default rule name for OPA policies.
     */
    private static final String DEFAULT_RULE = "allow";
    
    private final String packageName;
    private final String ruleName;
    
    /**
     * Creates a new OpaPolicyBuilder with default package and rule names.
     */
    public OpaPolicyBuilder() {
        this(DEFAULT_PACKAGE, DEFAULT_RULE);
    }
    
    /**
     * Creates a new OpaPolicyBuilder with custom package and rule names.
     *
     * @param packageName the package name for the Rego policy
     * @param ruleName    the rule name for the Rego policy
     */
    public OpaPolicyBuilder(String packageName, String ruleName) {
        this.packageName = packageName;
        this.ruleName = ruleName;
    }
    
    @Override
    public String buildPolicy(RequestAuthUrlRequest request) {
        StringBuilder rego = new StringBuilder();

        // Package declaration
        rego.append("package ").append(packageName).append("\n");

        // Allow rule
        rego.append(ruleName).append(" {\n");

        // Operation type constraint
        if (request.getOperationType() != null) {
            rego.append("  input.operationType == \"").append(request.getOperationType()).append("\"\n");
        }

        // Resource ID constraint
        if (request.getResourceId() != null) {
            rego.append("  input.resourceId == \"").append(request.getResourceId()).append("\"\n");
        }

        // Additional context constraints
        if (request.getMetadata() != null && !request.getMetadata().isEmpty()) {
            rego.append("  # Additional context constraints\n");
            request.getMetadata().forEach((key, value) -> {
                rego.append("  input.context.").append(key).append(" == \"").append(value).append("\"\n");
            });
        }

        rego.append("}\n");

        return rego.toString();
    }
    
    /**
     * Creates a new OpaPolicyBuilder with default settings.
     *
     * @return a new OpaPolicyBuilder instance
     */
    public static OpaPolicyBuilder create() {
        return new OpaPolicyBuilder();
    }
    
    /**
     * Creates a new OpaPolicyBuilder with custom package name.
     *
     * @param packageName the package name
     * @return a new OpaPolicyBuilder instance
     */
    public static OpaPolicyBuilder create(String packageName) {
        return new OpaPolicyBuilder(packageName, DEFAULT_RULE);
    }
    
    /**
     * Creates a new OpaPolicyBuilder with custom package and rule names.
     *
     * @param packageName the package name
     * @param ruleName    the rule name
     * @return a new OpaPolicyBuilder instance
     */
    public static OpaPolicyBuilder create(String packageName, String ruleName) {
        return new OpaPolicyBuilder(packageName, ruleName);
    }
}
