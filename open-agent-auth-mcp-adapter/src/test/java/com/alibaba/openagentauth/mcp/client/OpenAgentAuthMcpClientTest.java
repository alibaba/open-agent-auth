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

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenAgentAuthMcpClient}.
 *
 * @since 1.0
 */
@DisplayName("OpenAgentAuthMcpClient Tests")
@ExtendWith(MockitoExtension.class)
class OpenAgentAuthMcpClientTest {

    @Mock
    private McpSyncClient mockClient;

    private OpenAgentAuthMcpClient mcpClient;

    @BeforeEach
    void setUp() {
        mcpClient = new OpenAgentAuthMcpClient();
    }

    @Test
    @DisplayName("Should create client with default timeout")
    void shouldCreateClientWithDefaultTimeout() {
        // Arrange
        // Act
        OpenAgentAuthMcpClient client = new OpenAgentAuthMcpClient();

        // Assert
        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Should create client with custom timeout")
    void shouldCreateClientWithCustomTimeout() {
        // Arrange
        Duration customTimeout = Duration.ofSeconds(60);

        // Act
        OpenAgentAuthMcpClient client = new OpenAgentAuthMcpClient(customTimeout);

        // Assert
        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Should create HTTP client successfully")
    void shouldCreateHttpClientSuccessfully() {
        // Arrange
        String serverUrl = "https://mcp-server.example.com";

        // Act
        McpSyncClient client = mcpClient.createHttpClient(serverUrl);

        // Assert
        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("Should initialize client successfully")
    void shouldInitializeClientSuccessfully() throws Exception {
        // Arrange
        McpSchema.InitializeResult initResult = mock(McpSchema.InitializeResult.class);
        McpSchema.Implementation serverInfo = mock(McpSchema.Implementation.class);
        when(serverInfo.name()).thenReturn("test-server");
        when(serverInfo.version()).thenReturn("1.0.0");
        when(initResult.serverInfo()).thenReturn(serverInfo);
        when(mockClient.initialize()).thenReturn(initResult);

        // Act
        boolean result = mcpClient.initialize(mockClient);

        // Assert
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("Should return false when initialization fails with exception")
    void shouldReturnFalseWhenInitializationFailsWithException() throws Exception {
        // Arrange
        when(mockClient.initialize()).thenThrow(new RuntimeException("Connection failed"));

        // Act
        boolean result = mcpClient.initialize(mockClient);

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should return false when initialization times out")
    void shouldReturnFalseWhenInitializationTimesOut() throws Exception {
        // Arrange
        when(mockClient.initialize()).thenAnswer(invocation -> {
            Thread.sleep(35000); // Exceed the 30 second timeout
            return null;
        });

        // Act
        boolean result = mcpClient.initialize(mockClient);

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should list tools successfully")
    void shouldListToolsSuccessfully() {
        // Arrange
        McpSchema.Tool tool1 = mock(McpSchema.Tool.class);
        McpSchema.Tool tool2 = mock(McpSchema.Tool.class);
        when(tool1.name()).thenReturn("tool1");
        when(tool1.description()).thenReturn("First tool");
        when(tool2.name()).thenReturn("tool2");
        when(tool2.description()).thenReturn("Second tool");
        
        McpSchema.ListToolsResult listResult = mock(McpSchema.ListToolsResult.class);
        when(listResult.tools()).thenReturn(List.of(tool1, tool2));
        when(mockClient.listTools()).thenReturn(listResult);

        // Act
        List<McpSchema.Tool> tools = mcpClient.listTools(mockClient);

        // Assert
        assertThat(tools).hasSize(2);
        assertThat(tools.get(0).name()).isEqualTo("tool1");
        assertThat(tools.get(1).name()).isEqualTo("tool2");
    }

    @Test
    @DisplayName("Should return empty list when listing tools fails")
    void shouldReturnEmptyListWhenListingToolsFails() {
        // Arrange
        when(mockClient.listTools()).thenThrow(new RuntimeException("Server error"));

        // Act
        List<McpSchema.Tool> tools = mcpClient.listTools(mockClient);

        // Assert
        assertThat(tools).isEmpty();
    }

    @Test
    @DisplayName("Should return empty list when listing tools throws exception")
    void shouldReturnEmptyListWhenListingToolsThrowsException() {
        // Arrange
        when(mockClient.listTools()).thenThrow(new IllegalStateException("Invalid state"));

        // Act
        List<McpSchema.Tool> tools = mcpClient.listTools(mockClient);

        // Assert
        assertThat(tools).isEmpty();
    }

    @Test
    @DisplayName("Should call tool successfully")
    void shouldCallToolSuccessfully() {
        // Arrange
        String toolName = "test_tool";
        Map<String, Object> arguments = Map.of("param1", "value1");
        
        McpSchema.TextContent content = mock(McpSchema.TextContent.class);
        McpSchema.CallToolResult callResult = mock(McpSchema.CallToolResult.class);
        when(callResult.isError()).thenReturn(false);
        when(callResult.content()).thenReturn(List.of(content));
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class))).thenReturn(callResult);

        // Act
        McpSchema.CallToolResult result = mcpClient.callTool(mockClient, toolName, arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
        assertThat(result.content()).hasSize(1);
    }

    @Test
    @DisplayName("Should throw runtime exception when tool call fails")
    void shouldThrowRuntimeExceptionWhenToolCallFails() {
        // Arrange
        String toolName = "failing_tool";
        Map<String, Object> arguments = Map.of("param", "value");
        
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class)))
                .thenThrow(new RuntimeException("Tool execution error"));

        // Act & Assert
        assertThatThrownBy(() -> mcpClient.callTool(mockClient, toolName, arguments))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Tool execution failed");
    }

    @Test
    @DisplayName("Should throw runtime exception with original cause when tool call fails")
    void shouldThrowRuntimeExceptionWithOriginalCauseWhenToolCallFails() {
        // Arrange
        String toolName = "error_tool";
        Map<String, Object> arguments = Map.of();
        
        Exception originalException = new IllegalArgumentException("Invalid arguments");
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class)))
                .thenThrow(originalException);

        // Act & Assert
        assertThatThrownBy(() -> mcpClient.callTool(mockClient, toolName, arguments))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Tool execution failed")
                .hasCause(originalException);
    }

    @Test
    @DisplayName("Should call tool with empty arguments")
    void shouldCallToolWithEmptyArguments() {
        // Arrange
        String toolName = "no_args_tool";
        Map<String, Object> arguments = Map.of();
        
        McpSchema.TextContent content = mock(McpSchema.TextContent.class);
        McpSchema.CallToolResult callResult = mock(McpSchema.CallToolResult.class);
        when(callResult.isError()).thenReturn(false);
        when(callResult.content()).thenReturn(List.of(content));
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class))).thenReturn(callResult);

        // Act
        McpSchema.CallToolResult result = mcpClient.callTool(mockClient, toolName, arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
    }

    @Test
    @DisplayName("Should call tool with complex arguments")
    void shouldCallToolWithComplexArguments() {
        // Arrange
        String toolName = "complex_tool";
        Map<String, Object> arguments = Map.of(
                "stringParam", "value",
                "numberParam", 123,
                "booleanParam", true,
                "arrayParam", List.of("a", "b", "c"),
                "objectParam", Map.of("nested", "value")
        );
        
        McpSchema.TextContent content = mock(McpSchema.TextContent.class);
        McpSchema.CallToolResult callResult = mock(McpSchema.CallToolResult.class);
        when(callResult.isError()).thenReturn(false);
        when(callResult.content()).thenReturn(List.of(content));
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class))).thenReturn(callResult);

        // Act
        McpSchema.CallToolResult result = mcpClient.callTool(mockClient, toolName, arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
    }

    @Test
    @DisplayName("Should handle tool call with error result")
    void shouldHandleToolCallWithErrorResult() {
        // Arrange
        String toolName = "error_result_tool";
        Map<String, Object> arguments = Map.of();
        
        McpSchema.TextContent content = mock(McpSchema.TextContent.class);
        McpSchema.CallToolResult callResult = mock(McpSchema.CallToolResult.class);
        when(callResult.isError()).thenReturn(true);
        when(callResult.content()).thenReturn(List.of(content));
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class))).thenReturn(callResult);

        // Act
        McpSchema.CallToolResult result = mcpClient.callTool(mockClient, toolName, arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isTrue();
    }

    @Test
    @DisplayName("Should handle tool call with multiple content items")
    void shouldHandleToolCallWithMultipleContentItems() {
        // Arrange
        String toolName = "multi_content_tool";
        Map<String, Object> arguments = Map.of();
        
        McpSchema.TextContent content1 = mock(McpSchema.TextContent.class);
        McpSchema.TextContent content2 = mock(McpSchema.TextContent.class);
        McpSchema.CallToolResult callResult = mock(McpSchema.CallToolResult.class);
        when(callResult.isError()).thenReturn(false);
        when(callResult.content()).thenReturn(List.of(content1, content2));
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class))).thenReturn(callResult);

        // Act
        McpSchema.CallToolResult result = mcpClient.callTool(mockClient, toolName, arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.content()).hasSize(2);
    }

    @Test
    @DisplayName("Should handle null content in tool result")
    void shouldHandleNullContentInToolResult() {
        // Arrange
        String toolName = "null_content_tool";
        Map<String, Object> arguments = Map.of();
        
        McpSchema.CallToolResult callResult = mock(McpSchema.CallToolResult.class);
        when(callResult.isError()).thenReturn(false);
        when(callResult.content()).thenReturn(null);
        when(mockClient.callTool(any(McpSchema.CallToolRequest.class))).thenReturn(callResult);

        // Act
        McpSchema.CallToolResult result = mcpClient.callTool(mockClient, toolName, arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.content()).isNull();
    }

    @Test
    @DisplayName("Should handle empty tool list")
    void shouldHandleEmptyToolList() {
        // Arrange
        McpSchema.ListToolsResult listResult = mock(McpSchema.ListToolsResult.class);
        when(listResult.tools()).thenReturn(List.of());
        when(mockClient.listTools()).thenReturn(listResult);

        // Act
        List<McpSchema.Tool> tools = mcpClient.listTools(mockClient);

        // Assert
        assertThat(tools).isEmpty();
    }

    @Test
    @DisplayName("Should handle initialization with null result")
    void shouldHandleInitializationWithNullResult() throws Exception {
        // Arrange
        when(mockClient.initialize()).thenReturn(null);

        // Act
        boolean result = mcpClient.initialize(mockClient);

        // Assert
        assertThat(result).isTrue();
    }
}