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
package com.alibaba.openagentauth.sample.agent.adapter.mcp;

/**
 * MCP server configuration.
 * <p>
 * Represents the configuration for a Model Context Protocol (MCP) server
 * that can be integrated with the agent for tool access.
 * </p>
 */
public class McpServerConfig {

    private String name;
    private String url;
    private String description;
    private boolean enabled = true;

    /**
     * Gets the name of the MCP server.
     *
     * @return the server name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the name of the MCP server.
     *
     * @param name the server name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the URL of the MCP server.
     *
     * @return the server URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets the URL of the MCP server.
     *
     * @param url the server URL
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Gets the description of the MCP server.
     *
     * @return the server description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the description of the MCP server.
     *
     * @param description the server description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Checks if the MCP server is enabled.
     *
     * @return true if enabled, false otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the MCP server is enabled.
     *
     * @param enabled true to enable, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
