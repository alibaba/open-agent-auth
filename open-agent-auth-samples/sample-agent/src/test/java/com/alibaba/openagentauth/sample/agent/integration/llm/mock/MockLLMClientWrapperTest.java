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
package com.alibaba.openagentauth.sample.agent.integration.llm.mock;

import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link MockLLMClientWrapper}.
 * <p>
 * This test class validates the mock LLM client functionality
 * including session creation, chat with tools, and intent-based responses.
 * </p>
 */
@DisplayName("MockLLMClientWrapper Tests")
@ExtendWith(MockitoExtension.class)
class MockLLMClientWrapperTest {

    private MockLLMClientWrapper mockLLMClientWrapper;
    private MockConfig mockConfig;

    @BeforeEach
    void setUp() {
        mockConfig = new MockConfig();
        mockConfig.setEnabled(true);
        
        // Create strategies
        List<MockConfig.Strategy> strategies = new ArrayList<>();
        
        // Search strategy
        MockConfig.Strategy searchStrategy = new MockConfig.Strategy();
        searchStrategy.setName("search");
        searchStrategy.setIntent("search for products");
        searchStrategy.setKeywords(List.of("search", "find"));
        searchStrategy.setToolServer("product-server");
        searchStrategy.setToolName("search_products");
        
        List<MockConfig.ParamRule> searchRules = new ArrayList<>();
        MockConfig.ParamRule searchRule = new MockConfig.ParamRule();
        searchRule.setParam("keywords");
        searchRule.setPattern("search for (.+)");
        searchRules.add(searchRule);
        searchStrategy.setParamRules(searchRules);
        
        searchStrategy.setResponseTemplate("Found {result} products");
        strategies.add(searchStrategy);
        
        // Purchase strategy
        MockConfig.Strategy purchaseStrategy = new MockConfig.Strategy();
        purchaseStrategy.setName("purchase");
        purchaseStrategy.setIntent("purchase a product");
        purchaseStrategy.setKeywords(List.of("buy", "purchase"));
        purchaseStrategy.setToolServer("product-server");
        purchaseStrategy.setToolName("purchase_product");
        
        List<MockConfig.ParamRule> purchaseRules = new ArrayList<>();
        MockConfig.ParamRule purchaseRule = new MockConfig.ParamRule();
        purchaseRule.setParam("productId");
        purchaseRule.setPattern("buy (.+)");
        purchaseRules.add(purchaseRule);
        purchaseStrategy.setParamRules(purchaseRules);
        
        purchaseStrategy.setResponseTemplate("Purchased {result}");
        strategies.add(purchaseStrategy);
        
        // Default strategy
        MockConfig.Strategy defaultStrategy = new MockConfig.Strategy();
        defaultStrategy.setName("default");
        defaultStrategy.setIntent("general conversation");
        defaultStrategy.setNoTool(true);
        defaultStrategy.setResponse("I'm not sure how to help with that.");
        strategies.add(defaultStrategy);
        
        mockConfig.setStrategies(strategies);
        
        mockLLMClientWrapper = new MockLLMClientWrapper(mockConfig);
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should initialize with mock config")
        void shouldInitializeWithMockConfig() {
            assertThat(mockLLMClientWrapper).isNotNull();
        }
    }

    @Nested
    @DisplayName("chatWithTools()")
    class ChatWithToolsTests {

        @Test
        @DisplayName("Should return greeting for empty messages")
        void shouldReturnGreetingForEmptyMessages() {
            List<ToolDefinition> tools = new ArrayList<>();
            
            LLMClient.LLMChatResponse response = mockLLMClientWrapper.chatWithTools(new ArrayList<>(), tools);
            
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("I'm ready to help you");
        }

        @Test
        @DisplayName("Should match search intent and return tool call")
        void shouldMatchSearchIntentAndReturnToolCall() {
            List<Map<String, String>> messages = List.of(
                    Map.of("role", "user", "content", "search for iPhone 15")
            );
            
            List<ToolDefinition> tools = List.of(
                    createToolDefinition("product-server", "search_products", "Search products")
            );
            
            LLMClient.LLMChatResponse response = mockLLMClientWrapper.chatWithTools(messages, tools);
            
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getToolCall()).isNotNull();
            assertThat(response.getToolCall().getToolName()).isEqualTo("search_products");
            assertThat(response.getToolCall().getServerName()).isEqualTo("product-server");
        }

        @Test
        @DisplayName("Should match purchase intent and return tool call")
        void shouldMatchPurchaseIntentAndReturnToolCall() {
            List<Map<String, String>> messages = List.of(
                    Map.of("role", "user", "content", "buy iPhone 15")
            );
            
            List<ToolDefinition> tools = List.of(
                    createToolDefinition("product-server", "purchase_product", "Purchase product")
            );
            
            LLMClient.LLMChatResponse response = mockLLMClientWrapper.chatWithTools(messages, tools);
            
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isTrue();
            assertThat(response.getToolCall()).isNotNull();
            assertThat(response.getToolCall().getToolName()).isEqualTo("purchase_product");
        }

        @Test
        @DisplayName("Should return default response for unmatched intent")
        void shouldReturnDefaultResponseForUnmatchedIntent() {
            List<Map<String, String>> messages = List.of(
                    Map.of("role", "user", "content", "Hello, how are you?")
            );
            
            List<ToolDefinition> tools = new ArrayList<>();
            
            LLMClient.LLMChatResponse response = mockLLMClientWrapper.chatWithTools(messages, tools);
            
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("I'm not sure how to help");
        }

        @Test
        @DisplayName("Should generate response for tool result")
        void shouldGenerateResponseForToolResult() {
            List<Map<String, String>> messages = List.of(
                    Map.of("role", "user", "content", "search for iPhone 15"),
                    Map.of("role", "assistant", "content", "I'll help you search for products"),
                    Map.of("role", "tool", "content", "Found 5 products")
            );
            
            List<ToolDefinition> tools = List.of(
                    createToolDefinition("product-server", "search_products", "Search products")
            );
            
            LLMClient.LLMChatResponse response = mockLLMClientWrapper.chatWithTools(messages, tools);
            
            assertThat(response).isNotNull();
            assertThat(response.isNeedToolCall()).isFalse();
            assertThat(response.getContent()).contains("Found 5 products");
        }

        @Test
        @DisplayName("Should extract parameters correctly")
        void shouldExtractParametersCorrectly() {
            List<Map<String, String>> messages = List.of(
                    Map.of("role", "user", "content", "search for iPhone 15")
            );
            
            List<ToolDefinition> tools = List.of(
                    createToolDefinition("product-server", "search_products", "Search products")
            );
            
            LLMClient.LLMChatResponse response = mockLLMClientWrapper.chatWithTools(messages, tools);
            
            assertThat(response).isNotNull();
            assertThat(response.getToolCall().getArguments()).contains("iPhone 15");
        }
    }

    /**
     * Helper method to create a tool definition.
     */
    private ToolDefinition createToolDefinition(String serverName, String toolName, String description) {
        ToolDefinition tool = new ToolDefinition();
        tool.setServerName(serverName);
        tool.setToolName(toolName);
        tool.setDescription(description);
        
        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("properties", new HashMap<>());
        tool.setInputSchema(schema);
        
        return tool;
    }
}
