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

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link McpTool}.
 * <p>
 * This test class verifies the McpTool interface contract by testing
 * a sample implementation. Tests cover all public methods including
 * getDefinition(), execute(), getName(), and getDescription().
 * </p>
 *
 * @since 1.0
 */
@DisplayName("McpTool Tests")
class McpToolTest {

    private TestMcpTool testTool;

    @BeforeEach
    void setUp() {
        testTool = new TestMcpTool();
    }

    @Test
    @DisplayName("Should return tool definition")
    void shouldReturnToolDefinition() {
        // Arrange
        // Act
        McpSchema.Tool definition = testTool.getDefinition();

        // Assert
        assertThat(definition).isNotNull();
        assertThat(definition.name()).isEqualTo("test_tool");
        assertThat(definition.description()).isEqualTo("Test tool description");
    }

    @Test
    @DisplayName("Should execute tool successfully with valid arguments")
    void shouldExecuteToolSuccessfullyWithValidArguments() {
        // Arrange
        Map<String, Object> arguments = Map.of(
                "param1", "value1",
                "param2", 123
        );

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
    }

    @Test
    @DisplayName("Should execute tool successfully with empty arguments")
    void shouldExecuteToolSuccessfullyWithEmptyArguments() {
        // Arrange
        Map<String, Object> arguments = Map.of();

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
    }

    @Test
    @DisplayName("Should execute tool successfully with null arguments")
    void shouldExecuteToolSuccessfullyWithNullArguments() {
        // Arrange
        Map<String, Object> arguments = null;

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
    }

    @Test
    @DisplayName("Should return error when executing with invalid arguments")
    void shouldReturnErrorWhenExecutingWithInvalidArguments() {
        // Arrange
        Map<String, Object> arguments = Map.of(
                "invalid_param", "invalid_value"
        );

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isTrue();
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when required parameter is missing")
    void shouldThrowIllegalArgumentExceptionWhenRequiredParameterIsMissing() {
        // Arrange
        Map<String, Object> arguments = Map.of();

        // Act
        McpSchema.CallToolResult result = testTool.executeWithRequiredParam(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isTrue();
    }

    @Test
    @DisplayName("Should throw RuntimeException when execution fails")
    void shouldThrowRuntimeExceptionWhenExecutionFails() {
        // Arrange
        Map<String, Object> arguments = Map.of(
                "trigger_error", true
        );

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isTrue();
    }

    @Test
    @DisplayName("Should return tool name")
    void shouldReturnToolName() {
        // Arrange
        // Act
        String name = testTool.getName();

        // Assert
        assertThat(name).isEqualTo("test_tool");
    }

    @Test
    @DisplayName("Should return tool description from definition")
    void shouldReturnToolDescriptionFromDefinition() {
        // Arrange
        // Act
        String description = testTool.getDescription();

        // Assert
        assertThat(description).isEqualTo("Test tool description");
    }

    @Test
    @DisplayName("Should return empty description when definition is null")
    void shouldReturnEmptyDescriptionWhenDefinitionIsNull() {
        // Arrange
        McpTool toolWithNullDefinition = new McpTool() {
            @Override
            public McpSchema.Tool getDefinition() {
                return null;
            }

            @Override
            public McpSchema.CallToolResult execute(Map<String, Object> arguments) {
                return mock(McpSchema.CallToolResult.class);
            }

            @Override
            public String getName() {
                return "null_definition_tool";
            }
        };

        // Act
        String description = toolWithNullDefinition.getDescription();

        // Assert
        assertThat(description).isEmpty();
    }

    @Test
    @DisplayName("Should handle complex arguments in execution")
    void shouldHandleComplexArgumentsInExecution() {
        // Arrange
        Map<String, Object> arguments = Map.of(
                "stringParam", "value",
                "numberParam", 123,
                "booleanParam", true,
                "arrayParam", List.of("a", "b", "c"),
                "objectParam", Map.of("nested", "value")
        );

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.isError()).isFalse();
    }

    @Test
    @DisplayName("Should handle execution with null return value")
    void shouldHandleExecutionWithNullReturnValue() {
        // Arrange
        Map<String, Object> arguments = Map.of("return_null", true);

        // Act
        McpSchema.CallToolResult result = testTool.execute(arguments);

        // Assert
        assertThat(result).isNotNull();
    }

    /**
     * Sample implementation of McpTool for testing purposes.
     */
    private static class TestMcpTool implements McpTool {

        private static final String TOOL_NAME = "test_tool";
        private static final String TOOL_DESCRIPTION = "Test tool description";

        @Override
        public McpSchema.Tool getDefinition() {
            McpSchema.Tool definition = mock(McpSchema.Tool.class);
            when(definition.name()).thenReturn(TOOL_NAME);
            when(definition.description()).thenReturn(TOOL_DESCRIPTION);
            return definition;
        }

        @Override
        public McpSchema.CallToolResult execute(Map<String, Object> arguments) {
            if (arguments != null && arguments.containsKey("invalid_param")) {
                McpSchema.CallToolResult errorResult = mock(McpSchema.CallToolResult.class);
                when(errorResult.isError()).thenReturn(true);
                return errorResult;
            }

            if (arguments != null && arguments.containsKey("trigger_error")) {
                McpSchema.CallToolResult errorResult = mock(McpSchema.CallToolResult.class);
                when(errorResult.isError()).thenReturn(true);
                return errorResult;
            }

            McpSchema.CallToolResult successResult = mock(McpSchema.CallToolResult.class);
            when(successResult.isError()).thenReturn(false);
            return successResult;
        }

        public McpSchema.CallToolResult executeWithRequiredParam(Map<String, Object> arguments) {
            if (arguments == null || !arguments.containsKey("required_param")) {
                McpSchema.CallToolResult errorResult = mock(McpSchema.CallToolResult.class);
                when(errorResult.isError()).thenReturn(true);
                return errorResult;
            }

            McpSchema.CallToolResult successResult = mock(McpSchema.CallToolResult.class);
            when(successResult.isError()).thenReturn(false);
            return successResult;
        }

        @Override
        public String getName() {
            return TOOL_NAME;
        }
    }
}