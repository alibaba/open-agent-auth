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
package com.alibaba.openagentauth.sample.agent.service;

import com.alibaba.openagentauth.sample.agent.adapter.ToolAdapter;
import com.alibaba.openagentauth.sample.agent.exception.AgentException;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.model.ToolResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link ToolAdapterManager}.
 * <p>
 * This test class verifies the tool adapter management functionality.
 * </p>
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ToolAdapterManager Tests")
class ToolAdapterManagerTest {

    @Mock
    private ToolAdapter mockAdapter;

    @Mock
    private ToolAdapter mockAdapter2;

    private ToolAdapterManager manager;

    private static final String SERVER_NAME = "test-server";
    private static final String SERVER_NAME_2 = "test-server-2";

    @BeforeEach
    void setUp() {
        manager = new ToolAdapterManager();
    }

    @Nested
    @DisplayName("Register Adapter")
    class RegisterAdapterTests {

        @Test
        @DisplayName("Should register adapter successfully")
        void shouldRegisterAdapterSuccessfully() throws Exception {
            // When
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // Then
            assertTrue(manager.isAdapterRegistered(SERVER_NAME),
                    "Adapter should be registered");
            verify(mockAdapter, times(1)).initialize();
        }

        @Test
        @DisplayName("Should throw exception when server name is null")
        void shouldThrowExceptionWhenServerNameIsNull() {
            // When & Then
            assertThrows(IllegalArgumentException.class, () -> {
                manager.registerAdapter(null, mockAdapter);
            });
        }

        @Test
        @DisplayName("Should throw exception when adapter is null")
        void shouldThrowExceptionWhenAdapterIsNull() {
            // When & Then
            assertThrows(IllegalArgumentException.class, () -> {
                manager.registerAdapter(SERVER_NAME, null);
            });
        }

        @Test
        @DisplayName("Should throw exception when adapter initialization fails")
        void shouldThrowExceptionWhenAdapterInitializationFails() throws Exception {
            // Given
            doThrow(new RuntimeException("Initialization failed")).when(mockAdapter).initialize();

            // When & Then
            assertThrows(AgentException.class, () -> {
                manager.registerAdapter(SERVER_NAME, mockAdapter);
            });
        }
    }

    @Nested
    @DisplayName("Unregister Adapter")
    class UnregisterAdapterTests {

        @Test
        @DisplayName("Should unregister adapter successfully")
        void shouldUnregisterAdapterSuccessfully() throws Exception {
            // Given
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            manager.unregisterAdapter(SERVER_NAME);

            // Then
            assertFalse(manager.isAdapterRegistered(SERVER_NAME),
                    "Adapter should be unregistered");
            verify(mockAdapter, times(1)).close();
        }

        @Test
        @DisplayName("Should handle unregister of non-existent adapter")
        void shouldHandleUnregisterOfNonExistentAdapter() {
            // When & Then - should not throw exception
            assertDoesNotThrow(() -> {
                manager.unregisterAdapter(SERVER_NAME);
            });
        }
    }

    @Nested
    @DisplayName("Get All Tools")
    class GetAllToolsTests {

        @Test
        @DisplayName("Should return empty list when no adapters registered")
        void shouldReturnEmptyListWhenNoAdaptersRegistered() {
            // When
            List<ToolDefinition> tools = manager.getAllTools();

            // Then
            assertNotNull(tools, "Tools list should not be null");
            assertTrue(tools.isEmpty(), "Tools list should be empty");
        }

        @Test
        @DisplayName("Should return tools from all registered adapters")
        void shouldReturnToolsFromAllRegisteredAdapters() throws Exception {
            // Given
            ToolDefinition tool1 = new ToolDefinition();
            tool1.setToolName("tool1");
            ToolDefinition tool2 = new ToolDefinition();
            tool2.setToolName("tool2");

            when(mockAdapter.listTools()).thenReturn(List.of(tool1));
            when(mockAdapter2.listTools()).thenReturn(List.of(tool2));

            manager.registerAdapter(SERVER_NAME, mockAdapter);
            manager.registerAdapter(SERVER_NAME_2, mockAdapter2);

            // When
            List<ToolDefinition> tools = manager.getAllTools();

            // Then
            assertNotNull(tools, "Tools list should not be null");
            assertEquals(2, tools.size(), "Should return 2 tools");
        }

        @Test
        @DisplayName("Should handle adapter list tools failure gracefully")
        void shouldHandleAdapterListToolsFailureGracefully() throws Exception {
            // Given
            when(mockAdapter.listTools()).thenThrow(new RuntimeException("List failed"));
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            List<ToolDefinition> tools = manager.getAllTools();

            // Then
            assertNotNull(tools, "Tools list should not be null");
            assertTrue(tools.isEmpty(), "Should return empty list on error");
        }
    }

    @Nested
    @DisplayName("Get Tools By Server")
    class GetToolsByServerTests {

        @Test
        @DisplayName("Should return tools for specific server")
        void shouldReturnToolsForSpecificServer() throws Exception {
            // Given
            ToolDefinition tool = new ToolDefinition();
            tool.setToolName("test-tool");
            when(mockAdapter.listTools()).thenReturn(List.of(tool));
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            List<ToolDefinition> tools = manager.getToolsByServer(SERVER_NAME);

            // Then
            assertNotNull(tools, "Tools list should not be null");
            assertEquals(1, tools.size(), "Should return 1 tool");
            assertEquals("test-tool", tools.get(0).getToolName());
        }

        @Test
        @DisplayName("Should throw exception when adapter not found")
        void shouldThrowExceptionWhenAdapterNotFound() {
            // When & Then
            assertThrows(AgentException.class, () -> {
                manager.getToolsByServer(SERVER_NAME);
            });
        }
    }

    @Nested
    @DisplayName("Call Tool")
    class CallToolTests {

        @Test
        @DisplayName("Should call tool successfully")
        void shouldCallToolSuccessfully() throws Exception {
            // Given
            Map<String, Object> arguments = new HashMap<>();
            ToolResult expectedResult = ToolResult.success("result");
            when(mockAdapter.callTool(anyString(), any())).thenReturn(expectedResult);
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            ToolResult result = manager.callTool(SERVER_NAME, "test-tool", arguments);

            // Then
            assertEquals(expectedResult, result, "Result should match expected");
            verify(mockAdapter, times(1)).callTool("test-tool", arguments);
        }

        @Test
        @DisplayName("Should return error when adapter not found")
        void shouldReturnErrorWhenAdapterNotFound() {
            // Given
            Map<String, Object> arguments = new HashMap<>();

            // When
            ToolResult result = manager.callTool(SERVER_NAME, "test-tool", arguments);

            // Then
            assertNotNull(result, "Result should not be null");
            assertFalse(result.isSuccess(), "Result should not be successful");
            assertTrue(result.getError().contains("Tool adapter not found"),
                    "Error message should mention adapter not found");
        }

        @Test
        @DisplayName("Should return error when tool call fails")
        void shouldReturnErrorWhenToolCallFails() throws Exception {
            // Given
            Map<String, Object> arguments = new HashMap<>();
            when(mockAdapter.callTool(anyString(), any()))
                    .thenThrow(new RuntimeException("Tool call failed"));
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            ToolResult result = manager.callTool(SERVER_NAME, "test-tool", arguments);

            // Then
            assertNotNull(result, "Result should not be null");
            assertFalse(result.isSuccess(), "Result should not be successful");
        }
    }

    @Nested
    @DisplayName("Get Adapters")
    class GetAdaptersTests {

        @Test
        @DisplayName("Should return unmodifiable map of adapters")
        void shouldReturnUnmodifiableMapOfAdapters() throws Exception {
            // Given
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            Map<String, ToolAdapter> adapters = manager.getAdapters();

            // Then
            assertNotNull(adapters, "Adapters map should not be null");
            assertEquals(1, adapters.size(), "Should have 1 adapter");
            assertThrows(UnsupportedOperationException.class, () -> {
                adapters.put("new-server", mockAdapter2);
            });
        }
    }

    @Nested
    @DisplayName("Is Adapter Registered")
    class IsAdapterRegisteredTests {

        @Test
        @DisplayName("Should return true when adapter is registered")
        void shouldReturnTrueWhenAdapterIsRegistered() throws Exception {
            // Given
            manager.registerAdapter(SERVER_NAME, mockAdapter);

            // When
            boolean result = manager.isAdapterRegistered(SERVER_NAME);

            // Then
            assertTrue(result, "Should return true for registered adapter");
        }

        @Test
        @DisplayName("Should return false when adapter is not registered")
        void shouldReturnFalseWhenAdapterIsNotRegistered() {
            // When
            boolean result = manager.isAdapterRegistered(SERVER_NAME);

            // Then
            assertFalse(result, "Should return false for unregistered adapter");
        }
    }
}