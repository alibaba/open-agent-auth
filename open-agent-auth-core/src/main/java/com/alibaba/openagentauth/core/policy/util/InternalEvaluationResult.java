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

/**
 * Internal evaluation result for RAM statements.
 * <p>
 * This is used internally by RAM and ACL evaluators to track
 * whether a statement matched and was allowed.
 * </p>
 */
public class InternalEvaluationResult {
    private final boolean allowed;
    private final boolean matched;
    private final String reasoning;
    
    private InternalEvaluationResult(boolean allowed, boolean matched, String reasoning) {
        this.allowed = allowed;
        this.matched = matched;
        this.reasoning = reasoning;
    }
    
    /**
     * Creates an allowed result.
     */
    public static InternalEvaluationResult allowed(String reasoning) {
        return new InternalEvaluationResult(true, true, reasoning);
    }
    
    /**
     * Creates a denied result.
     */
    public static InternalEvaluationResult denied(String reasoning) {
        return new InternalEvaluationResult(false, true, reasoning);
    }
    
    /**
     * Creates a not matched result.
     */
    public static InternalEvaluationResult notMatched(String reasoning) {
        return new InternalEvaluationResult(false, false, reasoning);
    }
    
    public boolean isAllowed() {
        return allowed;
    }
    
    public boolean isMatched() {
        return matched;
    }
    
    public String getReasoning() {
        return reasoning;
    }
}
