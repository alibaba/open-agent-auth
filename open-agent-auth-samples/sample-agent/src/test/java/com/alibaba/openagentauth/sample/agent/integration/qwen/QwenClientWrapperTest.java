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
package com.alibaba.openagentauth.sample.agent.integration.qwen;

import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.qwen.code.cli.QwenCodeCli;
import com.alibaba.qwen.code.cli.protocol.data.AssistantContent;
import com.alibaba.qwen.code.cli.session.event.consumers.AssistantContentSimpleConsumers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.springframework.test.util.ReflectionTestUtils;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link QwenClientWrapper}.
 * <p>
 * This test class validates the Qwen client wrapper functionality
 * including session creation, chat with tools, and response generation.
 * </p>
 * 
 * Test scenarios:
 * - Successful LLM calls with and without tool calls
 * - Failure scenarios (runtime exceptions, network errors)
 * - Parameter validation (empty messages, null parameters)
 * - Boundary conditions (long messages, multiple tools, special characters)
 * </p>
 * 
 * Note: These tests mock the Qwen SDK static methods to avoid external dependencies.
 * </p>
 */
@DisplayName("QwenClientWrapper Tests")
@ExtendWith(MockitoExtension.class)
class QwenClientWrapperTest {

    private QwenClientWrapper qwenClientWrapper;
    private MockedStatic<QwenCodeCli> mockedQwenCodeCli;

    @BeforeEach
    void setUp() {
        qwenClientWrapper = new QwenClientWrapper();
        ReflectionTestUtils.setField(qwenClientWrapper, "model", "test-model");
        ReflectionTestUtils.setField(qwenClientWrapper, "timeoutSeconds", 120L);
        
        // Initialize mocked static
        mockedQwenCodeCli = mockStatic(QwenCodeCli.class);
    }

    @AfterEach
    void tearDown() {
        if (mockedQwenCodeCli != null) {
            mockedQwenCodeCli.close();
        }
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize successfully")
        void shouldInitializeSuccessfully() {
            assertThat(qwenClientWrapper).isNotNull();
        }
    }

    @Nested
    @DisplayName("LLMChatResponse Class")
    class LLMChatResponseTests {

        @Test
        @DisplayName("Should create response with all fields")
        void shouldCreateResponseWithAllFields() {
            LLMClient.LLMChatResponse response = new LLMClient.LLMChatResponse(
                    true,
                    "Test content",
                    new LLMClient.ToolCall("server", "tool", "{}")
            );

            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getContent()).isEqualTo("Test content");
            assertThat(response.getToolCall()).isNotNull();
            assertThat(response.getToolCall().getServerName()).isEqualTo("server");
        }

        @Test
        @DisplayName("Should set and get all fields")
        void shouldSetAndGetAllFields() {
            LLMClient.LLMChatResponse response = new LLMClient.LLMChatResponse();
            
            response.setNeedToolCall(true);
            response.setContent("Updated content");
            response.setToolCall(new LLMClient.ToolCall("server2", "tool2", "{\"arg\":\"value\"}"));

            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getContent()).isEqualTo("Updated content");
            assertThat(response.getToolCall().getToolName()).isEqualTo("tool2");
        }
    }

    @Nested
    @DisplayName("ToolCall Class")
    class ToolCallTests {

        @Test
        @DisplayName("Should create tool call with all fields")
        void shouldCreateToolCallWithAllFields() {
            LLMClient.ToolCall toolCall = new LLMClient.ToolCall(
                    "test-server",
                    "test-tool",
                    "{\"param\":\"value\"}"
            );

            assertThat(toolCall.getServerName()).isEqualTo("test-server");
            assertThat(toolCall.getToolName()).isEqualTo("test-tool");
            assertThat(toolCall.getArguments()).isEqualTo("{\"param\":\"value\"}");
        }

        @Test
        @DisplayName("Should set and get all fields")
        void shouldSetAndGetAllFields() {
            LLMClient.ToolCall toolCall = new LLMClient.ToolCall();
            
            toolCall.setServerName("updated-server");
            toolCall.setToolName("updated-tool");
            toolCall.setArguments("{\"updated\":\"value\"}");

            assertThat(toolCall.getServerName()).isEqualTo("updated-server");
            assertThat(toolCall.getToolName()).isEqualTo("updated-tool");
            assertThat(toolCall.getArguments()).isEqualTo("{\"updated\":\"value\"}");
        }
    }

    // ==================== Success Scenarios ====================
    
    @Nested
    @DisplayName("Success Scenarios")
    class SuccessScenariosTests {

        @Test
        @DisplayName("Should handle successful chat without tool call")
        void shouldHandleSuccessfulChatWithoutToolCall() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Hello, how are you?");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                // Simulate text response
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn("Hello! I'm doing well, thank you for asking.");
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).isEqualTo("Hello! I'm doing well, thank you for asking.");
            assertThat(response.getToolCall()).isNull();
        }
        
        @Test
        @DisplayName("Should handle successful chat with tool call in JSON block")
        void shouldHandleSuccessfulChatWithToolCallInJsonBlock() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Search for iPhone 15");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                // Simulate tool call response in JSON format
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn(
                    "```json\n" +
                    "{\n" +
                    "  \"name\": \"search_products\",\n" +
                    "  \"arguments\": {\n" +
                    "    \"keywords\": \"iPhone 15\"\n" +
                    "  }\n" +
                    "}\n" +
                    "```"
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getToolCall()).isNotNull();
            assertThat(response.getToolCall().getToolName()).isEqualTo("search_products");
            assertThat(response.getToolCall().getServerName()).isEqualTo("default-server");
            assertThat(response.getToolCall().getArguments()).contains("iPhone 15");
        }
        
        @Test
        @DisplayName("Should accumulate multiple text fragments")
        void shouldAccumulateMultipleTextFragments() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Tell me a story");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                // Simulate streaming response with multiple fragments
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                
                AssistantContent.TextAssistantContent fragment1 = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(fragment1.getText()).thenReturn("Once upon a time, ");
                consumers.onText(null, fragment1);
                
                AssistantContent.TextAssistantContent fragment2 = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(fragment2.getText()).thenReturn("there was a brave knight ");
                consumers.onText(null, fragment2);
                
                AssistantContent.TextAssistantContent fragment3 = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(fragment3.getText()).thenReturn("who saved the kingdom.");
                consumers.onText(null, fragment3);
                
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).isEqualTo("Once upon a time, there was a brave knight who saved the kingdom.");
        }
        
        @Test
        @DisplayName("Should handle tool call with plain JSON format")
        void shouldHandleToolCallWithPlainJsonFormat() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Plain JSON");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn(
                    "{\"name\":\"search_products\",\"arguments\":{\"keywords\":\"test\"}}"
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getToolCall().getToolName()).isEqualTo("search_products");
        }
    }

    // ==================== Failure Scenarios ====================
    
    @Nested
    @DisplayName("Failure Scenarios")
    class FailureScenariosTests {

        @Test
        @DisplayName("Should handle runtime exception gracefully")
        void shouldHandleRuntimeExceptionGracefully() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Test error");
            List<ToolDefinition> tools = createTestTools();
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                any(AssistantContentSimpleConsumers.class)
            )).thenThrow(new RuntimeException("Network error: Connection timeout"));
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("error");
            assertThat(response.getContent()).contains("Network error");
        }
        
        @Test
        @DisplayName("Should handle null pointer exception")
        void shouldHandleNullPointerException() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Test null");
            List<ToolDefinition> tools = createTestTools();
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                any(AssistantContentSimpleConsumers.class)
            )).thenThrow(new NullPointerException("Unexpected null value"));
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("error");
        }
        
        @Test
        @DisplayName("Should handle invalid tool call JSON")
        void shouldHandleInvalidToolCallJson() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Invalid JSON");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                // Simulate malformed JSON
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn(
                    "```json\n" +
                    "{ invalid json }\n" +
                    "```\n" +
                    "This is a text response instead."
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("This is a text response instead.");
        }
        
        @Test
        @DisplayName("Should handle empty JSON in tool call")
        void shouldHandleEmptyJsonInToolCall() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Empty JSON");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn(
                    "```json\n" +
                    "{}\n" +
                    "```\n"
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            // Empty JSON in ```json``` block will be treated as tool call by current implementation
            assertThat(response.isNeedToolCall()).isTrue();
        }
    }

    // ==================== Parameter Validation ====================
    
    @Nested
    @DisplayName("Parameter Validation")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should handle empty messages list")
        void shouldHandleEmptyMessagesList() {
            // Arrange
            List<Map<String, String>> messages = new ArrayList<>();
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn("How can I help you?");
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).isEqualTo("How can I help you?");
        }
        
        @Test
        @DisplayName("Should handle empty tools list")
        void shouldHandleEmptyToolsList() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Hello");
            List<ToolDefinition> tools = new ArrayList<>();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn("Hello! I'm ready to help.");
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).isEqualTo("Hello! I'm ready to help.");
        }
        
        @Test
        @DisplayName("Should handle null content in message")
        void shouldHandleNullContentInMessage() {
            // Arrange
            List<Map<String, String>> messages = new ArrayList<>();
            Map<String, String> message1 = new HashMap<>();
            message1.put("role", "user");
            message1.put("content", null);
            messages.add(message1);
            
            Map<String, String> message2 = new HashMap<>();
            message2.put("role", "user");
            message2.put("content", "Valid message");
            messages.add(message2);
            
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn("Valid message received");
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).isEqualTo("Valid message received");
        }
        
        @Test
        @DisplayName("Should handle null tool name")
        void shouldHandleNullToolName() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Test");
            List<ToolDefinition> tools = new ArrayList<>();
            ToolDefinition tool = new ToolDefinition();
            tool.setToolName(null);
            tool.setServerName("default-server");
            tools.add(tool);
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn("Response");
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
        }
    }

    // ==================== Boundary Conditions ====================
    
    @Nested
    @DisplayName("Boundary Conditions")
    class BoundaryConditionsTests {

        @Test
        @DisplayName("Should handle very long message")
        void shouldHandleVeryLongMessage() {
            // Arrange
            StringBuilder longContent = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                longContent.append("This is a very long message. ");
            }
            
            List<Map<String, String>> messages = createTestMessages("user", longContent.toString());
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn("Message received and processed.");
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).isEqualTo("Message received and processed.");
        }
        
        @Test
        @DisplayName("Should handle multiple tools")
        void shouldHandleMultipleTools() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Use multiple tools");
            List<ToolDefinition> tools = new ArrayList<>();
            
            for (int i = 1; i <= 10; i++) {
                ToolDefinition tool = new ToolDefinition();
                tool.setToolName("tool_" + i);
                tool.setServerName("server_" + i);
                tool.setDescription("Tool number " + i);
                tools.add(tool);
            }
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn(
                    "```json\n" +
                    "{\n" +
                    "  \"name\": \"tool_5\",\n" +
                    "  \"arguments\": {\"param\": \"value\"}\n" +
                    "}\n" +
                    "```"
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getToolCall().getToolName()).isEqualTo("tool_5");
            assertThat(response.getToolCall().getServerName()).isEqualTo("server_5");
        }
        
        @Test
        @DisplayName("Should sanitize special characters in response")
        void shouldSanitizeSpecialCharactersInResponse() {
            // Arrange
            List<Map<String, String>> messages = createTestMessages("user", "Special chars");
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                // Include control characters that should be sanitized
                when(textContent.getText()).thenReturn(
                    "Hello! \u0000\u0007\u001F Special chars: \n\t\r !@#$%^&*()"
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            // Control characters should be sanitized
            assertThat(response.getContent()).doesNotContain("\u0000");
            assertThat(response.getContent()).doesNotContain("\u0007");
            assertThat(response.getContent()).contains("Special chars");
        }
        
        @Test
        @DisplayName("Should handle tool result message")
        void shouldHandleToolResultMessage() {
            // Arrange
            List<Map<String, String>> messages = new ArrayList<>();
            messages.add(createTestMessage("user", "Search for product"));
            messages.add(createTestMessage("assistant", "```json\n{\"name\":\"search\",\"arguments\":{}}\n```"));
            messages.add(createTestMessage("tool", "Product found: iPhone 15"));
            
            List<ToolDefinition> tools = createTestTools();
            
            ArgumentCaptor<AssistantContentSimpleConsumers> consumersCaptor = 
                ArgumentCaptor.forClass(AssistantContentSimpleConsumers.class);
            
            mockedQwenCodeCli.when(() -> QwenCodeCli.simpleQuery(
                any(String.class),
                any(com.alibaba.qwen.code.cli.transport.TransportOptions.class),
                consumersCaptor.capture()
            )).thenAnswer(invocation -> {
                AssistantContentSimpleConsumers consumers = consumersCaptor.getValue();
                AssistantContent.TextAssistantContent textContent = 
                    mock(AssistantContent.TextAssistantContent.class);
                when(textContent.getText()).thenReturn(
                    "Based on the search results, I found the iPhone 15 for you."
                );
                consumers.onText(null, textContent);
                return null;
            });
            
            // Act
            LLMClient.LLMChatResponse response = qwenClientWrapper.chatWithTools(messages, tools);
            
            // Assert
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("iPhone 15");
        }
    }

    @Nested
    @DisplayName("Sanitization Methods")
    class SanitizationTests {

        @Test
        @DisplayName("Should sanitize text content")
        void shouldSanitizeTextContent() throws Exception {
            String dirtyText = "Hello\u0000World\u001F";
            String sanitized = (String) ReflectionTestUtils.invokeMethod(
                    qwenClientWrapper, 
                    "sanitizeTextContent", 
                    dirtyText
            );

            assertThat(sanitized).isEqualTo("HelloWorld");
        }

        @Test
        @DisplayName("Should handle null text")
        void shouldHandleNullText() throws Exception {
            String sanitized = (String) ReflectionTestUtils.invokeMethod(
                    qwenClientWrapper, 
                    "sanitizeTextContent", 
                    (String) null
            );

            assertThat(sanitized).isNull();
        }

        @Test
        @DisplayName("Should remove line separator")
        void shouldRemoveLineSeparator() throws Exception {
            String textWithSeparator = "Hello\u2028World";
            String sanitized = (String) ReflectionTestUtils.invokeMethod(
                    qwenClientWrapper, 
                    "sanitizeTextContent", 
                    textWithSeparator
            );

            assertThat(sanitized).isEqualTo("HelloWorld");
        }
    }

    @Nested
    @DisplayName("Tool Call Extraction")
    class ToolCallExtractionTests {

        @Test
        @DisplayName("Should extract tool call from JSON block")
        void shouldExtractToolCallFromJsonBlock() throws Exception {
            String text = "Here is the result:\n```json\n{\"name\":\"search\",\"arguments\":{\"query\":\"iPhone\"}}\n```\nDone";
            String extracted = (String) ReflectionTestUtils.invokeMethod(
                    qwenClientWrapper, 
                    "extractToolCallFromText", 
                    text
            );

            assertThat(extracted).isNotNull();
            assertThat(extracted).contains("name");
            assertThat(extracted).contains("search");
            assertThat(extracted).contains("arguments");
        }

        @Test
        @DisplayName("Should return null when no tool call found")
        void shouldReturnNullWhenNoToolCallFound() throws Exception {
            String text = "Just regular text without tool calls";
            String extracted = (String) ReflectionTestUtils.invokeMethod(
                    qwenClientWrapper, 
                    "extractToolCallFromText", 
                    text
            );

            assertThat(extracted).isNull();
        }

        @Test
        @DisplayName("Should extract text before tool call")
        void shouldExtractTextBeforeToolCall() throws Exception {
            String text = "I'll search for products\n```json\n{\"name\":\"search\"}\n```";
            String extracted = (String) ReflectionTestUtils.invokeMethod(
                    qwenClientWrapper, 
                    "extractTextBeforeToolCall", 
                    text
            );

            assertThat(extracted).isEqualTo("I'll search for products");
        }
    }
    
    // ==================== Helper Methods ====================
    
    private List<Map<String, String>> createTestMessages(String role, String content) {
        List<Map<String, String>> messages = new ArrayList<>();
        messages.add(createTestMessage(role, content));
        return messages;
    }
    
    private Map<String, String> createTestMessage(String role, String content) {
        Map<String, String> message = new HashMap<>();
        message.put("role", role);
        message.put("content", content);
        return message;
    }
    
    private List<ToolDefinition> createTestTools() {
        List<ToolDefinition> tools = new ArrayList<>();
        
        ToolDefinition tool1 = new ToolDefinition();
        tool1.setToolName("search_products");
        tool1.setServerName("default-server");
        tool1.setDescription("Search for products by keywords");
        tool1.setInputSchema(createInputSchema());
        tools.add(tool1);
        
        return tools;
    }
    
    private Map<String, Object> createInputSchema() {
        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        
        Map<String, Object> properties = new HashMap<>();
        Map<String, Object> keywords = new HashMap<>();
        keywords.put("type", "string");
        keywords.put("description", "Search keywords");
        properties.put("keywords", keywords);
        
        schema.put("properties", properties);
        schema.put("required", List.of("keywords"));
        
        return schema;
    }
}