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
package com.alibaba.openagentauth.sample.agent.adapter.properties;

import com.alibaba.openagentauth.sample.agent.adapter.api.ApiServerConfig;
import com.alibaba.openagentauth.sample.agent.adapter.mcp.McpServerConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Tool adapter configuration properties class.
 * <p>
 * This class defines configuration properties for tool adapters,
 * including MCP servers and API servers configuration.
 * </p>
 *
 * @since 1.0
 */
@ConfigurationProperties(prefix = "agent")
public class ToolAdapterProperties {

    /**
     * List of MCP server configurations.
     * <p>
     * Each configuration defines an MCP server that the agent can connect to.
     * </p>
     */
    private List<McpServerConfig> mcpServers;

    /**
     * List of API server configurations.
     * <p>
     * Each configuration defines an API server that the agent can interact with.
     * </p>
     */
    private List<ApiServerConfig> apiServers;

    public List<McpServerConfig> getMcpServers() {
        return mcpServers;
    }

    public void setMcpServers(List<McpServerConfig> mcpServers) {
        this.mcpServers = mcpServers;
    }

    public List<ApiServerConfig> getApiServers() {
        return apiServers;
    }

    public void setApiServers(List<ApiServerConfig> apiServers) {
        this.apiServers = apiServers;
    }
}
