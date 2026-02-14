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
package com.alibaba.openagentauth.sample.agent.config;

import com.alibaba.openagentauth.mcp.client.OpenAgentAuthMcpClient;
import com.alibaba.openagentauth.sample.agent.adapter.mcp.McpServerConfig;
import com.alibaba.openagentauth.sample.agent.adapter.mcp.McpToolAdapter;
import com.alibaba.openagentauth.sample.agent.adapter.properties.ToolAdapterProperties;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.integration.llm.mock.MockConfig;
import com.alibaba.openagentauth.sample.agent.integration.llm.mock.MockLLMClientWrapper;
import com.alibaba.openagentauth.sample.agent.integration.qwen.QwenClientWrapper;
import com.alibaba.openagentauth.sample.agent.service.ToolAdapterManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.List;

/**
 * Agent configuration class
 *
 * Configures tool adapters, MCP clients and other components for the Agent
 */
@Configuration
public class AgentConfiguration {

    /**
     * Logger for this agent configuration class
     */
    private static final Logger log = LoggerFactory.getLogger(AgentConfiguration.class);

    /**
     * Tool adapter configuration properties
     */
    @Bean
    public ToolAdapterProperties toolAdapterProperties() {
        return new ToolAdapterProperties();
    }

    /**
     * Initialize MCP tool adapter
     */
    @ConditionalOnProperty(prefix = "agent.tools.mcp", name = "enabled", havingValue = "true")
    @Bean
    public McpToolAdapter mcpToolAdapter(
            ToolAdapterProperties toolAdapterProperties,
            OpenAgentAuthMcpClient mcpClient,
            ToolAdapterManager toolAdapterManager
    ) {

        // Get MCP server configuration from properties
        List<McpServerConfig> mcpServers = toolAdapterProperties.getMcpServers();
        if (mcpServers == null || mcpServers.isEmpty()) {
            log.warn("No MCP servers configured, skipping MCP tool adapter initialization");
            return null;
        }

        McpServerConfig serverConfig = mcpServers.get(0);
        String serverName = serverConfig.getName();
        String serverUrl = serverConfig.getUrl();
        boolean serverEnabled = serverConfig.isEnabled();

        // Validate that URL is configured
        if (serverUrl == null || serverUrl.isEmpty()) {
            log.error("MCP server URL is not configured for server: {}. " +
                    "Please configure the URL in ToolAdapterProperties.", serverName);
            return null;
        }

        log.info("Initializing MCP tool adapter with server: {} at {}", serverName, serverUrl);

        if (!serverEnabled) {
            log.info("MCP server {} is disabled, skipping registration", serverName);
            return null;
        }

        log.info("Registering MCP tool adapter for server: {}", serverName);

        McpToolAdapter adapter = new McpToolAdapter(
                serverName,
                serverUrl,
                mcpClient
        );

        toolAdapterManager.registerAdapter(serverName, adapter);

        return adapter;
    }

    /**
     * Mock LLM Client Bean
     *
     * This bean is created when agent.mock.enabled is true.
     * Provides a mock implementation of LLMClient for testing and development
     * without requiring a real LLM backend.
     */
    @Bean
    @ConditionalOnProperty(prefix = "agent.mock", name = "enabled", havingValue = "true", matchIfMissing = false)
    public LLMClient mockLLMClient(MockConfig mockConfig) {
        log.info("Creating MockLLMClient bean with {} strategies", mockConfig.getStrategies().size());
        return new MockLLMClientWrapper(mockConfig);
    }

    /**
     * Qwen LLM Client Bean
     *
     * This bean is created when agent.mock.enabled is false or not set.
     * Provides the real Qwen LLM implementation.
     *
     * @Primary marks this as the default LLMClient implementation
     */
    @Bean
    @Primary
    @ConditionalOnProperty(prefix = "agent.mock", name = "enabled", havingValue = "false", matchIfMissing = true)
    public LLMClient qwenLLMClient(
            @Value("${qwen.model:qwen3-coder-flash}") String model,
            @Value("${qwen.timeout:120}") long timeout) {
        log.info("Creating QwenLLMClient bean with model: {}, timeout: {}s", model, timeout);
        return new QwenClientWrapper();
    }

    /**
     * Mock Configuration Bean
     *
     * This bean loads the mock LLM configuration from application.yml.
     * It is only created when mock mode is enabled.
     */
    @Bean
    @ConditionalOnProperty(prefix = "agent.mock", name = "enabled", havingValue = "true", matchIfMissing = false)
    public MockConfig mockConfig() {
        log.info("Creating MockConfig bean");
        return new MockConfig();
    }
}