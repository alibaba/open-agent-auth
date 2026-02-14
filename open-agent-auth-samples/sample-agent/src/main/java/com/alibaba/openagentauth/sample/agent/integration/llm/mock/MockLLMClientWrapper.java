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
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMSession;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Mock LLM Client Wrapper
 * 
 * A mock implementation of LLMClient that simulates LLM behavior without requiring
 * a real LLM backend. This is useful for:
 * <ul>
 *   <li>Quick development and testing without LLM configuration</li>
 *   <li>E2E automated testing with predictable responses</li>
 *   <li>Demonstrations and training scenarios</li>
 * </ul>
 * 
 * <p>This implementation uses:
 * <ul>
 *   <li>IntentMatcher to identify user intent from keywords</li>
 *   <li>ParamExtractor to extract tool parameters from user input</li>
 *   <li>ResponseGenerator to generate natural language responses</li>
 * </ul>
 * 
 * @since 1.0
 * 
 * Note: This class is managed by AgentConfiguration via @ConditionalOnProperty,
 * not by @Component annotation.
 */
public class MockLLMClientWrapper implements LLMClient {
    
    private static final Logger log = LoggerFactory.getLogger(MockLLMClientWrapper.class);
    
    private final MockConfig mockConfig;
    private final IntentMatcher intentMatcher;
    private final ParamExtractor paramExtractor;
    private final ResponseGenerator responseGenerator;
    
    public MockLLMClientWrapper(MockConfig mockConfig) {
        this.mockConfig = mockConfig;
        this.intentMatcher = new IntentMatcher(mockConfig.getStrategies());
        this.paramExtractor = new ParamExtractor();
        this.responseGenerator = new ResponseGenerator();
        
        log.info("MockLLMClientWrapper initialized with {} strategies", 
                mockConfig.getStrategies().size());
    }
    
    @Override
    public LLMSession createSession() {
        log.info("Creating mock session");
        return new MockLLMSession();
    }
    
    @Override
    public LLMChatResponse chatWithTools(List<Map<String, String>> messages, List<ToolDefinition> tools) {
        log.info("Mock chat with tools, message count: {}, tool count: {}", 
                messages.size(), tools.size());
        
        if (messages == null || messages.isEmpty()) {
            LLMChatResponse response = new LLMChatResponse();
            response.setNeedToolCall(false);
            response.setContent("I'm ready to help you! I have access to the following tools: " + 
                    getToolListDescription(tools));
            return response;
        }
        
        // Check if the last message is a tool result (this is the second LLM call after tool execution)
        if (isToolResultMessage(messages)) {
            return generateResponseForToolResult(messages);
        }
        
        // Get the last user message
        String lastUserMessage = getLastUserMessage(messages);
        
        // Match intent
        MockConfig.Strategy strategy = intentMatcher.match(lastUserMessage);
        
        if (strategy.isNoTool()) {
            // Return static response for non-tool strategies
            LLMChatResponse response = new LLMChatResponse();
            response.setNeedToolCall(false);
            response.setContent(strategy.getResponse());
            return response;
        }
        
        // Check if strategy requires tool calling
        if (strategy.getToolName() != null && !strategy.getToolName().isBlank()) {
            // Extract parameters
            Map<String, Object> params = paramExtractor.extract(lastUserMessage, strategy);
            String argumentsJson = paramExtractor.toJson(params);
            
            log.info("Mock tool call: server={}, tool={}, arguments={}", 
                    strategy.getToolServer(), strategy.getToolName(), argumentsJson);
            
            // Create tool call response
            LLMChatResponse response = new LLMChatResponse();
            response.setNeedToolCall(true);
            response.setContent(generateToolCallText(strategy, params));
            response.setToolCall(new ToolCall(
                    strategy.getToolServer(),
                    strategy.getToolName(),
                    argumentsJson
            ));
            
            return response;
        }
        
        // Default response
        LLMChatResponse response = new LLMChatResponse();
        response.setNeedToolCall(false);
        response.setContent("I'm not sure how to help with that. Available tools: " + 
                getToolListDescription(tools));
        return response;
    }
    
    /**
     * Check if the last message is a tool result.
     * This indicates that this is the second LLM call after tool execution.
     * 
     * @param messages the conversation history
     * @return true if the last message is a tool result
     */
    private boolean isToolResultMessage(List<Map<String, String>> messages) {
        if (messages == null || messages.isEmpty()) {
            return false;
        }
        
        Map<String, String> lastMessage = messages.get(messages.size() - 1);
        String role = lastMessage.get("role");
        return "tool".equals(role);
    }
    
    /**
     * Generate a response for tool result.
     * This is called when the LLM receives a tool result and needs to generate a final response.
     * 
     * @param messages the conversation history
     * @return the LLM chat response
     */
    private LLMChatResponse generateResponseForToolResult(List<Map<String, String>> messages) {
        log.info("Generating response for tool result");
        
        // Find the tool result content
        String toolResult = "";
        for (int i = messages.size() - 1; i >= 0; i--) {
            Map<String, String> message = messages.get(i);
            String role = message.get("role");
            if ("tool".equals(role)) {
                toolResult = message.get("content");
                break;
            }
        }
        
        // Find the previous tool call to determine the strategy
        MockConfig.Strategy strategy = null;
        for (int i = messages.size() - 1; i >= 0; i--) {
            Map<String, String> message = messages.get(i);
            String role = message.get("role");
            String content = message.get("content");
            if ("assistant".equals(role) && content != null && !content.isBlank()) {
                // Try to match the tool call text with a strategy
                for (MockConfig.Strategy s : mockConfig.getStrategies()) {
                    if (s.getToolName() != null && content.contains(s.getToolName())) {
                        strategy = s;
                        break;
                    }
                }
                if (strategy != null) {
                    break;
                }
            }
        }
        
        // Generate response based on tool result and strategy
        String responseContent;
        if (strategy != null && strategy.getResponseTemplate() != null) {
            // Use the response template from strategy
            responseContent = strategy.getResponseTemplate()
                    .replace("{result}", toolResult != null ? toolResult : "No result")
                    .replace("{error}", toolResult != null ? toolResult : "Unknown error");
        } else {
            // Default response
            responseContent = "I've processed your request. " + 
                    (toolResult != null ? "Result: " + toolResult : "No result available.");
        }
        
        log.info("Generated tool result response: {}", responseContent);
        
        LLMChatResponse response = new LLMChatResponse();
        response.setNeedToolCall(false);
        response.setContent(responseContent);
        return response;
    }
    
    /**
     * Get the last user message from the conversation history.
     * 
     * @param messages the conversation history
     * @return the last user message, or empty string if not found
     */
    private String getLastUserMessage(List<Map<String, String>> messages) {
        if (messages == null || messages.isEmpty()) {
            return "";
        }
        
        // Iterate backwards to find the last user message
        for (int i = messages.size() - 1; i >= 0; i--) {
            Map<String, String> message = messages.get(i);
            String role = message.get("role");
            String content = message.get("content");
            
            if ("user".equals(role) && content != null && !content.isBlank()) {
                return content;
            }
        }
        
        return "";
    }
    
    /**
     * Generate text content for a tool call response.
     * 
     * @param strategy the matched strategy
     * @param params the extracted parameters
     * @return the text content
     */
    private String generateToolCallText(MockConfig.Strategy strategy, Map<String, Object> params) {
        StringBuilder text = new StringBuilder();
        text.append("I'll help you with that. ");
        
        if (strategy.getIntent() != null) {
            text.append("I understand you want to ").append(strategy.getIntent()).append(". ");
        }
        
        text.append("Let me call the ").append(strategy.getToolName()).append(" tool for you.");
        
        return text.toString();
    }
    
    /**
     * Generate a description of available tools.
     * 
     * @param tools the list of tools
     * @return a description string
     */
    private String getToolListDescription(List<ToolDefinition> tools) {
        if (tools == null || tools.isEmpty()) {
            return "none";
        }
        
        List<String> toolNames = new ArrayList<>();
        for (ToolDefinition tool : tools) {
            toolNames.add(tool.getToolName());
        }
        
        return String.join(", ", toolNames);
    }
}