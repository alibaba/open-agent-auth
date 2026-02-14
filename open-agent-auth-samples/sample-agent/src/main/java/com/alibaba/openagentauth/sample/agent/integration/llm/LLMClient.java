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
package com.alibaba.openagentauth.sample.agent.integration.llm;

import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;

import java.util.List;
import java.util.Map;

/**
 * LLM Client Interface
 * <p>
 * Defines the unified contract for LLM interactions.
 * This interface follows the Strategy Pattern, allowing different LLM implementations
 * (real LLM or mock) to be swapped at runtime without changing the business logic.
 * 
 * <p>Implementations of this interface are responsible for:
 * <ul>
 *   <li>Creating conversation sessions</li>
 *   <li>Processing user messages with or without tool calling capabilities</li>
 *   <li>Returning structured responses that may include tool calls</li>
 * </ul>
 * 
 * <p><b>Design Principle:</b> Dependency Inversion Principle - High-level modules depend on
 * abstractions (LLMSession) rather than concrete implementations.</p>
 * 
 * @since 1.0
 */
public interface LLMClient {
    
    /**
     * Create a new conversation session.
     * 
     * @return the created session
     */
    LLMSession createSession();

    /**
     * Process a chat message with tool calling capabilities.
     * 
     * @param messages the conversation history in role-based format
     * @param tools the list of available tools that the LLM can call
     * @return the LLM response, which may include a tool call request
     */
    LLMChatResponse chatWithTools(List<Map<String, String>> messages, List<ToolDefinition> tools);
    
    /**
     * LLM Chat Response
     * </p>
     * Represents the response from an LLM, which may include tool call requests.
     * This class maintains compatibility with the existing QwenChatResponse structure.
     */
    class LLMChatResponse {
        private boolean needToolCall;
        private String content;
        private ToolCall toolCall;
        
        public LLMChatResponse() {
        }
        
        public LLMChatResponse(boolean needToolCall, String content, ToolCall toolCall) {
            this.needToolCall = needToolCall;
            this.content = content;
            this.toolCall = toolCall;
        }
        
        public boolean isNeedToolCall() {
            return needToolCall;
        }
        
        public void setNeedToolCall(boolean needToolCall) {
            this.needToolCall = needToolCall;
        }
        
        public String getContent() {
            return content;
        }
        
        public void setContent(String content) {
            this.content = content;
        }
        
        public ToolCall getToolCall() {
            return toolCall;
        }
        
        public void setToolCall(ToolCall toolCall) {
            this.toolCall = toolCall;
        }
    }
    
    /**
     * Tool Call
     * 
     * Represents a tool call request from the LLM.
     * This class maintains compatibility with the existing QwenToolCall structure.
     */
    class ToolCall {
        private String serverName;
        private String toolName;
        private String arguments;
        
        public ToolCall() {
        }
        
        public ToolCall(String serverName, String toolName, String arguments) {
            this.serverName = serverName;
            this.toolName = toolName;
            this.arguments = arguments;
        }
        
        public String getServerName() {
            return serverName;
        }
        
        public void setServerName(String serverName) {
            this.serverName = serverName;
        }
        
        public String getToolName() {
            return toolName;
        }
        
        public void setToolName(String toolName) {
            this.toolName = toolName;
        }
        
        public String getArguments() {
            return arguments;
        }
        
        public void setArguments(String arguments) {
            this.arguments = arguments;
        }
    }
}