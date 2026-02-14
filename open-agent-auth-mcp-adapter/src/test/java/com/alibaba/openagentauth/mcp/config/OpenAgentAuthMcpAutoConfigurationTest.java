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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link OpenAgentAuthMcpAutoConfiguration}.
 *
 * @since 1.0
 */
@DisplayName("OpenAgentAuthMcpAutoConfiguration Tests")
class OpenAgentAuthMcpAutoConfigurationTest {

    @Test
    @DisplayName("Should create OpenAgentAuthMcpClient instance")
    void shouldCreateOpenAgentAuthMcpClientInstance() {
        OpenAgentAuthMcpAutoConfiguration configuration = new OpenAgentAuthMcpAutoConfiguration();
        OpenAgentAuthMcpClient client = configuration.openAgentAuthMcpClient();
        
        assertNotNull(client);
    }

    @Test
    @DisplayName("Should create OpenAgentAuthMcpServer instance with resource server")
    void shouldCreateOpenAgentAuthMcpServerInstanceWithResourceServer() {
        OpenAgentAuthMcpAutoConfiguration configuration = new OpenAgentAuthMcpAutoConfiguration();
        ResourceServer resourceServer = mock(ResourceServer.class);
        OpenAgentAuthMcpServer server = configuration.openAgentAuthMcpServer(resourceServer);
        
        assertNotNull(server);
    }

    @Test
    @DisplayName("Should create OpenAgentAuthMcpServer instance with null resource server")
    void shouldCreateOpenAgentAuthMcpServerInstanceWithNullResourceServer() {
        OpenAgentAuthMcpAutoConfiguration configuration = new OpenAgentAuthMcpAutoConfiguration();
        OpenAgentAuthMcpServer server = configuration.openAgentAuthMcpServer(null);
        
        assertNotNull(server);
    }

    @Test
    @DisplayName("Should create multiple OpenAgentAuthMcpClient instances")
    void shouldCreateMultipleOpenAgentAuthMcpClientInstances() {
        OpenAgentAuthMcpAutoConfiguration configuration = new OpenAgentAuthMcpAutoConfiguration();
        OpenAgentAuthMcpClient client1 = configuration.openAgentAuthMcpClient();
        OpenAgentAuthMcpClient client2 = configuration.openAgentAuthMcpClient();
        
        assertNotNull(client1);
        assertNotNull(client2);
        assertNotSame(client1, client2);
    }

    @Test
    @DisplayName("Should create multiple OpenAgentAuthMcpServer instances")
    void shouldCreateMultipleOpenAgentAuthMcpServerInstances() {
        OpenAgentAuthMcpAutoConfiguration configuration = new OpenAgentAuthMcpAutoConfiguration();
        ResourceServer resourceServer = mock(ResourceServer.class);
        OpenAgentAuthMcpServer server1 = configuration.openAgentAuthMcpServer(resourceServer);
        OpenAgentAuthMcpServer server2 = configuration.openAgentAuthMcpServer(resourceServer);
        
        assertNotNull(server1);
        assertNotNull(server2);
        assertNotSame(server1, server2);
    }
}
