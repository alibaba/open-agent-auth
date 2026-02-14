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
package com.alibaba.openagentauth.mcp.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ThreadLocal holder for MCP authentication context.
 * <p>
 * This class provides a thread-safe mechanism to store and retrieve
 * authentication context for the current thread. It uses ThreadLocal
 * to ensure that each thread has its own isolated authentication context.
 * </p>
 * <p>
 * This design allows multiple concurrent MCP requests to have different
 * authentication credentials without interfering with each other.
 * </p>
 *
 * @see McpAuthContext
 * @since 1.0
 */
public class McpAuthContextHolder {
    
    private static final Logger logger = LoggerFactory.getLogger(McpAuthContextHolder.class);
    
    /**
     * ThreadLocal storage for authentication context.
     */
    private static final ThreadLocal<McpAuthContext> CONTEXT_HOLDER = new ThreadLocal<>();
    
    /**
     * Sets the authentication context for the current thread.
     *
     * @param context the authentication context to set
     */
    public static void setContext(McpAuthContext context) {
        if (context == null) {
            logger.warn("Attempted to set null authentication context, clearing instead");
            clearContext();
            return;
        }
        CONTEXT_HOLDER.set(context);
        logger.debug("MCP authentication context set for current thread");
    }
    
    /**
     * Gets the authentication context for the current thread.
     *
     * @return the authentication context, or null if not set
     */
    public static McpAuthContext getContext() {
        return CONTEXT_HOLDER.get();
    }
    
    /**
     * Clears the authentication context for the current thread.
     * <p>
     * This method should be called after the MCP request is completed
     * to prevent memory leaks.
     * </p>
     */
    public static void clearContext() {
        CONTEXT_HOLDER.remove();
        logger.debug("MCP authentication context cleared for current thread");
    }
    
    /**
     * Checks if an authentication context is set for the current thread.
     *
     * @return true if a context is set and valid
     */
    public static boolean hasContext() {
        McpAuthContext context = CONTEXT_HOLDER.get();
        return context != null && context.isValid();
    }
}
