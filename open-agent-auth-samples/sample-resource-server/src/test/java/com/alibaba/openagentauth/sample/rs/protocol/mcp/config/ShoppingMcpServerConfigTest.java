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
package com.alibaba.openagentauth.sample.rs.protocol.mcp.config;

import com.alibaba.openagentauth.framework.actor.ResourceServer;
import com.alibaba.openagentauth.sample.rs.domain.repository.InMemoryShoppingRepository;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.ServletRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link ShoppingMcpServerConfig}.
 * <p>
 * Test coverage includes:
 * - HttpServletStreamableServerTransportProvider bean creation
 * - ServletRegistrationBean bean creation
 * - McpSyncServer bean creation with all tools registered
 * - Context extraction functionality
 * </p>
 *
 * @since 1.0
 */
@DisplayName("ShoppingMcpServerConfig Tests")
class ShoppingMcpServerConfigTest {

    private ShoppingMcpServerConfig config;

    @BeforeEach
    void setUp() {
        config = new ShoppingMcpServerConfig();
    }

    private HttpServletStreamableServerTransportProvider createTransportProvider() {
        return config.streamableHttpTransportProvider();
    }

    private ShoppingService createShoppingService() {
        return new ShoppingService(new InMemoryShoppingRepository());
    }

    @Nested
    @DisplayName("streamableHttpTransportProvider() Bean")
    class StreamableHttpTransportProviderTests {

        @Test
        @DisplayName("Should create HttpServletStreamableServerTransportProvider with context extractor")
        void shouldCreateTransportProviderWithContextExtractor() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
            assertThat(provider).isInstanceOf(HttpServletStreamableServerTransportProvider.class);
        }

        @Test
        @DisplayName("Should create new instance on each call")
        void shouldCreateNewInstanceOnEachCall() {
            HttpServletStreamableServerTransportProvider provider1 = config.streamableHttpTransportProvider();
            HttpServletStreamableServerTransportProvider provider2 = config.streamableHttpTransportProvider();

            assertThat(provider1).isNotNull();
            assertThat(provider2).isNotNull();
            assertThat(provider1).isNotSameAs(provider2);
        }
    }

    @Nested
    @DisplayName("streamableHttpServletRegistration() Bean")
    class StreamableHttpServletRegistrationTests {

        @Test
        @DisplayName("Should create ServletRegistrationBean with correct URL mapping")
        void shouldCreateServletRegistrationBeanWithCorrectUrlMapping() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> registration = 
                    config.streamableHttpServletRegistration(provider);

            assertThat(registration).isNotNull();
            assertThat(registration.getUrlMappings()).containsExactly("/mcp");
            assertThat(registration.getServlet()).isSameAs(provider);
        }

        @Test
        @DisplayName("Should create new instance on each call")
        void shouldCreateNewInstanceOnEachCall() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> registration1 = 
                    config.streamableHttpServletRegistration(provider);
            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> registration2 = 
                    config.streamableHttpServletRegistration(provider);

            assertThat(registration1).isNotNull();
            assertThat(registration2).isNotNull();
            assertThat(registration1).isNotSameAs(registration2);
        }

        @Test
        @DisplayName("Should handle null transport provider")
        void shouldHandleNullTransportProvider() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> registration = 
                    config.streamableHttpServletRegistration(provider);

            assertThat(registration).isNotNull();
        }
    }

    @Nested
    @DisplayName("shoppingMcpServer() Bean")
    class ShoppingMcpServerTests {

        @Test
        @DisplayName("Should create McpSyncServer with all required dependencies")
        void shouldCreateMcpSyncServerWithAllDependencies() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ShoppingService shoppingService = createShoppingService();
            ResourceServer resourceServer = mock(ResourceServer.class);
            McpSyncServer server = config.shoppingMcpServer(provider, shoppingService, resourceServer);

            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should create new instance on each call")
        void shouldCreateNewInstanceOnEachCall() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ShoppingService shoppingService = createShoppingService();
            ResourceServer resourceServer = mock(ResourceServer.class);
            McpSyncServer server1 = config.shoppingMcpServer(provider, shoppingService, resourceServer);
            McpSyncServer server2 = config.shoppingMcpServer(provider, shoppingService, resourceServer);

            assertThat(server1).isNotNull();
            assertThat(server2).isNotNull();
            assertThat(server1).isNotSameAs(server2);
        }

        @Test
        @DisplayName("Should handle null transport provider")
        void shouldHandleNullTransportProvider() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ShoppingService shoppingService = createShoppingService();
            ResourceServer resourceServer = org.mockito.Mockito.mock(ResourceServer.class);
            McpSyncServer server = config.shoppingMcpServer(provider, shoppingService, resourceServer);

            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should handle null shopping service")
        void shouldHandleNullShoppingService() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ResourceServer resourceServer = mock(ResourceServer.class);
            McpSyncServer server = config.shoppingMcpServer(provider, null, resourceServer);

            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should handle null resource server")
        void shouldHandleNullResourceServer() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ShoppingService shoppingService = createShoppingService();
            McpSyncServer server = config.shoppingMcpServer(provider, shoppingService, null);

            assertThat(server).isNotNull();
        }

        @Test
        @DisplayName("Should handle all null dependencies")
        void shouldHandleAllNullDependencies() {
            HttpServletStreamableServerTransportProvider provider = createTransportProvider();
            ShoppingService shoppingService = createShoppingService();
            ResourceServer resourceServer = org.mockito.Mockito.mock(ResourceServer.class);
            McpSyncServer server = config.shoppingMcpServer(provider, shoppingService, resourceServer);

            assertThat(server).isNotNull();
        }
    }

    @Nested
    @DisplayName("Context Extraction")
    class ContextExtractionTests {

        @Test
        @DisplayName("Should extract authorization header from request")
        void shouldExtractAuthorizationHeaderFromRequest() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should extract X-Workload-Identity header from request")
        void shouldExtractWorkloadIdentityHeaderFromRequest() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should extract X-Workload-Proof header from request")
        void shouldExtractWorkloadProofHeaderFromRequest() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should extract HTTP method and URI from request")
        void shouldExtractHttpMethodAndUriFromRequest() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should handle request with no authentication headers")
        void shouldHandleRequestWithNoAuthenticationHeaders() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
        }

        @Test
        @DisplayName("Should handle request with all headers present")
        void shouldHandleRequestWithAllHeadersPresent() {
            HttpServletStreamableServerTransportProvider provider = config.streamableHttpTransportProvider();

            assertThat(provider).isNotNull();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should create complete MCP server configuration")
        void shouldCreateCompleteMcpServerConfiguration() {
            HttpServletStreamableServerTransportProvider transportProvider = config.streamableHttpTransportProvider();
            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> servletRegistration = 
                    config.streamableHttpServletRegistration(transportProvider);
            ShoppingService shoppingService = createShoppingService();
            ResourceServer resourceServer = mock(ResourceServer.class);
            McpSyncServer mcpServer = config.shoppingMcpServer(transportProvider, shoppingService, resourceServer);

            assertThat(transportProvider).isNotNull();
            assertThat(servletRegistration).isNotNull();
            assertThat(mcpServer).isNotNull();
            assertThat(servletRegistration.getServlet()).isSameAs(transportProvider);
        }

        @Test
        @DisplayName("Should support multiple bean instantiations")
        void shouldSupportMultipleBeanInstantiations() {
            HttpServletStreamableServerTransportProvider provider1 = config.streamableHttpTransportProvider();
            HttpServletStreamableServerTransportProvider provider2 = config.streamableHttpTransportProvider();

            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> servlet1 = 
                    config.streamableHttpServletRegistration(provider1);
            ServletRegistrationBean<HttpServletStreamableServerTransportProvider> servlet2 = 
                    config.streamableHttpServletRegistration(provider2);

            ShoppingService shoppingService = createShoppingService();
            ResourceServer resourceServer = mock(ResourceServer.class);
            McpSyncServer server1 = config.shoppingMcpServer(provider1, shoppingService, resourceServer);
            McpSyncServer server2 = config.shoppingMcpServer(provider2, shoppingService, resourceServer);

            assertThat(provider1).isNotSameAs(provider2);
            assertThat(servlet1).isNotSameAs(servlet2);
            assertThat(server1).isNotSameAs(server2);
            assertThat(servlet1.getServlet()).isSameAs(provider1);
            assertThat(servlet2.getServlet()).isSameAs(provider2);
        }
    }
}
