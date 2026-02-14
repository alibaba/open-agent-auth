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

import com.alibaba.openagentauth.core.util.ValidationUtils;

/**
 * Authentication context for MCP Client requests.
 * <p>
 * This class holds the authentication credentials needed for MCP client
 * to communicate with MCP servers protected by Agent Operation Authorization.
 * </p>
 * <p>
 * The context is stored in ThreadLocal to ensure thread-safe access
 * during concurrent MCP requests.
 * </p>
 *
 * @see McpAuthContextHolder
 * @since 1.0
 */
public class McpAuthContext {
    
    private final String agentOaToken;
    private final String wit;
    private final String wpt;
    
    /**
     * Creates a new authentication context.
     *
     * @param agentOaToken the Agent Operation Authorization Token
     * @param wit the Workload Identity Token
     * @param wpt the Workload Proof Token
     */
    public McpAuthContext(String agentOaToken, String wit, String wpt) {
        this.agentOaToken = agentOaToken;
        this.wit = wit;
        this.wpt = wpt;
    }
    
    /**
     * Gets the Agent Operation Authorization Token.
     *
     * @return the AOAT, or null if not set
     */
    public String getAgentOaToken() {
        return agentOaToken;
    }
    
    /**
     * Gets the Workload Identity Token.
     *
     * @return the WIT, or null if not set
     */
    public String getWit() {
        return wit;
    }
    
    /**
     * Gets the Workload Proof Token.
     *
     * @return the WPT, or null if not set
     */
    public String getWpt() {
        return wpt;
    }
    
    /**
     * Checks if this context has valid authentication credentials.
     *
     * @return true if at least the AOAT is present
     */
    public boolean isValid() {
        return !ValidationUtils.isNullOrEmpty(agentOaToken);
    }
}
