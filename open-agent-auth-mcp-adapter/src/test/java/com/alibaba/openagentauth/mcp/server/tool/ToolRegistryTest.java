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
package com.alibaba.openagentauth.mcp.server.tool;

import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ToolRegistry}.
 *
 * @since 1.0
 */
@DisplayName("ToolRegistry Tests")
class ToolRegistryTest {

    private ToolRegistry toolRegistry;

    @BeforeEach
    void setUp() {
        toolRegistry = new ToolRegistry();
    }

    @Test
    @DisplayName("Should initialize with empty registry")
    void shouldInitializeWithEmptyRegistry() {
        // Arrange
        // Act
        boolean isEmpty = toolRegistry.isEmpty();
        int size = toolRegistry.size();

        // Assert
        assertThat(isEmpty).isTrue();
        assertThat(size).isZero();
    }

    @Test
    @DisplayName("Should register tool successfully")
    void shouldRegisterToolSuccessfully() {
        // Arrange
        McpTool mockTool = createMockTool("test_tool", "Test tool description");

        // Act
        toolRegistry.register(mockTool);

        // Assert
        assertThat(toolRegistry.size()).isOne();
        assertThat(toolRegistry.hasTool("test_tool")).isTrue();
        assertThat(toolRegistry.getTool("test_tool")).isSameAs(mockTool);
    }

    @Test
    @DisplayName("Should throw exception when registering null tool")
    void shouldThrowExceptionWhenRegisteringNullTool() {
        // Arrange
        // Act & Assert
        assertThatThrownBy(() -> toolRegistry.register(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Tool");
    }

    @Test
    @DisplayName("Should throw exception when registering tool with null name")
    void shouldThrowExceptionWhenRegisteringToolWithNullName() {
        // Arrange
        McpTool mockTool = mock(McpTool.class);
        when(mockTool.getName()).thenReturn(null);

        // Act & Assert
        assertThatThrownBy(() -> toolRegistry.register(mockTool))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Tool name cannot be null or empty");
    }

    @Test
    @DisplayName("Should throw exception when registering tool with empty name")
    void shouldThrowExceptionWhenRegisteringToolWithEmptyName() {
        // Arrange
        McpTool mockTool = mock(McpTool.class);
        when(mockTool.getName()).thenReturn("");

        // Act & Assert
        assertThatThrownBy(() -> toolRegistry.register(mockTool))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Tool name cannot be null or empty");
    }

    @Test
    @DisplayName("Should replace existing tool when registering with same name")
    void shouldReplaceExistingToolWhenRegisteringWithSameName() {
        // Arrange
        McpTool originalTool = createMockTool("test_tool", "Original tool");
        McpTool newTool = createMockTool("test_tool", "New tool");
        toolRegistry.register(originalTool);

        // Act
        toolRegistry.register(newTool);

        // Assert
        assertThat(toolRegistry.size()).isOne();
        assertThat(toolRegistry.getTool("test_tool")).isSameAs(newTool);
        assertThat(toolRegistry.getTool("test_tool")).isNotSameAs(originalTool);
    }

    @Test
    @DisplayName("Should register multiple tools")
    void shouldRegisterMultipleTools() {
        // Arrange
        McpTool tool1 = createMockTool("tool1", "First tool");
        McpTool tool2 = createMockTool("tool2", "Second tool");
        McpTool tool3 = createMockTool("tool3", "Third tool");

        // Act
        toolRegistry.register(tool1);
        toolRegistry.register(tool2);
        toolRegistry.register(tool3);

        // Assert
        assertThat(toolRegistry.size()).isEqualTo(3);
        assertThat(toolRegistry.hasTool("tool1")).isTrue();
        assertThat(toolRegistry.hasTool("tool2")).isTrue();
        assertThat(toolRegistry.hasTool("tool3")).isTrue();
    }

    @Test
    @DisplayName("Should get tool by name when exists")
    void shouldGetToolByNameWhenExists() {
        // Arrange
        McpTool mockTool = createMockTool("search_tool", "Search tool");
        toolRegistry.register(mockTool);

        // Act
        McpTool retrievedTool = toolRegistry.getTool("search_tool");

        // Assert
        assertThat(retrievedTool).isNotNull();
        assertThat(retrievedTool).isSameAs(mockTool);
    }

    @Test
    @DisplayName("Should return null when getting non-existent tool")
    void shouldReturnNullWhenGettingNonExistentTool() {
        // Arrange
        toolRegistry.register(createMockTool("existing_tool", "Existing"));

        // Act
        McpTool tool = toolRegistry.getTool("non_existent_tool");

        // Assert
        assertThat(tool).isNull();
    }

    @Test
    @DisplayName("Should return null when getting tool with null name")
    void shouldReturnNullWhenGettingToolWithNullName() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        McpTool tool = toolRegistry.getTool(null);

        // Assert
        assertThat(tool).isNull();
    }

    @Test
    @DisplayName("Should return null when getting tool with empty name")
    void shouldReturnNullWhenGettingToolWithEmptyName() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        McpTool tool = toolRegistry.getTool("");

        // Assert
        assertThat(tool).isNull();
    }

    @Test
    @DisplayName("Should check if tool exists")
    void shouldCheckIfToolExists() {
        // Arrange
        McpTool mockTool = createMockTool("check_tool", "Check tool");
        toolRegistry.register(mockTool);

        // Act
        boolean exists = toolRegistry.hasTool("check_tool");
        boolean notExists = toolRegistry.hasTool("non_existent");

        // Assert
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should return false when checking tool with null name")
    void shouldReturnFalseWhenCheckingToolWithNullName() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        boolean result = toolRegistry.hasTool(null);

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should return false when checking tool with empty name")
    void shouldReturnFalseWhenCheckingToolWithEmptyName() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        boolean result = toolRegistry.hasTool("");

        // Assert
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Should get all registered tools")
    void shouldGetAllRegisteredTools() {
        // Arrange
        McpTool tool1 = createMockTool("tool1", "Tool 1");
        McpTool tool2 = createMockTool("tool2", "Tool 2");
        McpTool tool3 = createMockTool("tool3", "Tool 3");
        toolRegistry.register(tool1);
        toolRegistry.register(tool2);
        toolRegistry.register(tool3);

        // Act
        Collection<McpTool> allTools = toolRegistry.getAllTools();

        // Assert
        assertThat(allTools).hasSize(3);
        assertThat(allTools).containsExactlyInAnyOrder(tool1, tool2, tool3);
    }

    @Test
    @DisplayName("Should return empty collection when registry is empty")
    void shouldReturnEmptyCollectionWhenRegistryIsEmpty() {
        // Arrange
        // Act
        Collection<McpTool> allTools = toolRegistry.getAllTools();

        // Assert
        assertThat(allTools).isEmpty();
    }

    @Test
    @DisplayName("Should return correct size")
    void shouldReturnCorrectSize() {
        // Arrange
        toolRegistry.register(createMockTool("tool1", "Tool 1"));
        toolRegistry.register(createMockTool("tool2", "Tool 2"));

        // Act
        int size = toolRegistry.size();

        // Assert
        assertThat(size).isEqualTo(2);
    }

    @Test
    @DisplayName("Should check if registry is empty")
    void shouldCheckIfRegistryIsEmpty() {
        // Arrange
        // Act
        boolean isEmptyBefore = toolRegistry.isEmpty();

        toolRegistry.register(createMockTool("tool", "Tool"));
        boolean isEmptyAfter = toolRegistry.isEmpty();

        // Assert
        assertThat(isEmptyBefore).isTrue();
        assertThat(isEmptyAfter).isFalse();
    }

    @Test
    @DisplayName("Should unregister tool successfully")
    void shouldUnregisterToolSuccessfully() {
        // Arrange
        McpTool tool = createMockTool("remove_tool", "Remove me");
        toolRegistry.register(tool);

        // Act
        McpTool removedTool = toolRegistry.unregister("remove_tool");

        // Assert
        assertThat(removedTool).isSameAs(tool);
        assertThat(toolRegistry.size()).isZero();
        assertThat(toolRegistry.hasTool("remove_tool")).isFalse();
    }

    @Test
    @DisplayName("Should return null when unregistering non-existent tool")
    void shouldReturnNullWhenUnregisteringNonExistentTool() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        McpTool removedTool = toolRegistry.unregister("non_existent");

        // Assert
        assertThat(removedTool).isNull();
        assertThat(toolRegistry.size()).isOne();
    }

    @Test
    @DisplayName("Should return null when unregistering with null name")
    void shouldReturnNullWhenUnregisteringWithNullName() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        McpTool removedTool = toolRegistry.unregister(null);

        // Assert
        assertThat(removedTool).isNull();
    }

    @Test
    @DisplayName("Should return null when unregistering with empty name")
    void shouldReturnNullWhenUnregisteringWithEmptyName() {
        // Arrange
        toolRegistry.register(createMockTool("tool", "Tool"));

        // Act
        McpTool removedTool = toolRegistry.unregister("");

        // Assert
        assertThat(removedTool).isNull();
    }

    @Test
    @DisplayName("Should clear all tools")
    void shouldClearAllTools() {
        // Arrange
        toolRegistry.register(createMockTool("tool1", "Tool 1"));
        toolRegistry.register(createMockTool("tool2", "Tool 2"));
        toolRegistry.register(createMockTool("tool3", "Tool 3"));
        assertThat(toolRegistry.size()).isEqualTo(3);

        // Act
        toolRegistry.clear();

        // Assert
        assertThat(toolRegistry.size()).isZero();
        assertThat(toolRegistry.isEmpty()).isTrue();
        assertThat(toolRegistry.getAllTools()).isEmpty();
    }

    @Test
    @DisplayName("Should clear empty registry without error")
    void shouldClearEmptyRegistryWithoutError() {
        // Arrange
        assertThat(toolRegistry.size()).isZero();

        // Act
        toolRegistry.clear();

        // Assert
        assertThat(toolRegistry.size()).isZero();
    }

    @Test
    @DisplayName("Should handle tool registration and retrieval in sequence")
    void shouldHandleToolRegistrationAndRetrievalInSequence() {
        // Arrange
        McpTool tool1 = createMockTool("tool_a", "Tool A");
        McpTool tool2 = createMockTool("tool_b", "Tool B");
        McpTool tool3 = createMockTool("tool_c", "Tool C");

        // Act
        toolRegistry.register(tool1);
        assertThat(toolRegistry.getTool("tool_a")).isSameAs(tool1);

        toolRegistry.register(tool2);
        assertThat(toolRegistry.getTool("tool_b")).isSameAs(tool2);

        toolRegistry.register(tool3);
        assertThat(toolRegistry.getTool("tool_c")).isSameAs(tool3);

        // Assert
        assertThat(toolRegistry.size()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should handle mixed operations on registry")
    void shouldHandleMixedOperationsOnRegistry() {
        // Arrange
        McpTool tool1 = createMockTool("tool1", "Tool 1");
        McpTool tool2 = createMockTool("tool2", "Tool 2");
        McpTool tool3 = createMockTool("tool3", "Tool 3");

        // Act
        toolRegistry.register(tool1);
        toolRegistry.register(tool2);
        toolRegistry.unregister("tool1");
        toolRegistry.register(tool3);
        toolRegistry.unregister("tool2");

        // Assert
        assertThat(toolRegistry.size()).isOne();
        assertThat(toolRegistry.hasTool("tool3")).isTrue();
        assertThat(toolRegistry.hasTool("tool1")).isFalse();
        assertThat(toolRegistry.hasTool("tool2")).isFalse();
    }

    /**
     * Helper method to create a mock McpTool with specified name and description.
     */
    private McpTool createMockTool(String name, String description) {
        McpTool mockTool = mock(McpTool.class);
        McpSchema.Tool definition = new McpSchema.Tool(name, null, description, null, null, null, null);

        when(mockTool.getName()).thenReturn(name);
        when(mockTool.getDefinition()).thenReturn(definition);

        return mockTool;
    }
}
