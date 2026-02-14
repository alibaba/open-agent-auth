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
package com.alibaba.openagentauth.mcp.config;

import com.alibaba.openagentauth.framework.actor.ResourceServer;
import com.alibaba.openagentauth.mcp.client.OpenAgentAuthMcpClient;
import com.alibaba.openagentauth.mcp.server.OpenAgentAuthMcpServer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration for Open Agent Auth MCP Adapter.
 * <p>
 * This class provides Spring Boot auto-configuration for MCP client and server
 * components with Agent Operation Authorization support. It automatically
 * configures beans when the MCP SDK is present on the classpath and the
 * agent role is enabled.
 * </p>
 * <p>
 * <b>Activation Conditions:</b></p>
 * <ul>
 *   <li>MCP SDK must be present on the classpath</li>
 *   <li>Agent role must be enabled: {@code open-agent-auth.roles.agent.enabled=true}</li>
 * </ul>
 *
 * @see OpenAgentAuthMcpClient
 * @see OpenAgentAuthMcpServer
 * @since 1.0
 */
@Configuration
@ConditionalOnClass(name = "io.modelcontextprotocol.client.McpSyncClient")
@ConditionalOnProperty(prefix = "open-agent-auth.roles.agent", name = "enabled", havingValue = "true")
public class OpenAgentAuthMcpAutoConfiguration {
    
    /**
     * Configures the Open Agent Auth MCP Client bean.
     * <p>
     * This bean provides MCP client functionality with automatic authentication
     * header injection for Agent Operation Authorization.
     * </p>
     *
     * @return the MCP client instance
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "open-agent-auth.mcp.client", name = "enabled", havingValue = "true", matchIfMissing = true)
    public OpenAgentAuthMcpClient openAgentAuthMcpClient() {
        return new OpenAgentAuthMcpClient();
    }
    
    /**
     * Configures the Open Agent Auth MCP Server bean.
     * <p>
     * This bean provides MCP server functionality with five-layer verification
     * architecture for incoming MCP requests.
     * </p>
     * <p>
     * <b>Note:</b> This bean requires the ResourceServer to be available,
     * which is only created when the resource-server role is enabled.
     * If you are using a different role (e.g., agent, agent-idp), you may
     * need to manually create ResourceServer or disable this bean.
     * </p>
     *
     * @param resourceServer the resource server service
     * @return the MCP server instance
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "open-agent-auth.mcp.server", name = "enabled", havingValue = "true", matchIfMissing = false)
    @ConditionalOnBean(ResourceServer.class)
    public OpenAgentAuthMcpServer openAgentAuthMcpServer(ResourceServer resourceServer) {
        return new OpenAgentAuthMcpServer(resourceServer);
    }

}
