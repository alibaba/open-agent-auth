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
package com.alibaba.openagentauth.core.policy.util;

import java.util.List;

/**
 * Resource validator for OAuth Scope policies.
 */
public class ResourceValidator {
    
    private final PatternMatcher patternMatcher;
    
    /**
     * Creates a new ResourceValidator.
     */
    public ResourceValidator() {
        this.patternMatcher = new PatternMatcher();
    }
    
    /**
     * Validates if a resource is allowed by a list of resource patterns.
     *
     * @param allowedResources the list of allowed resource patterns
     * @param resource        the resource to validate
     * @return true if the resource is allowed, false otherwise
     */
    public boolean validate(List<String> allowedResources, String resource) {
        if (resource == null) {
            return false;
        }
        
        // If no resource restrictions, allow any resource
        if (allowedResources == null || allowedResources.isEmpty()) {
            return true;
        }
        
        // Check if resource matches any allowed pattern
        return patternMatcher.match(allowedResources, resource);
    }
}
