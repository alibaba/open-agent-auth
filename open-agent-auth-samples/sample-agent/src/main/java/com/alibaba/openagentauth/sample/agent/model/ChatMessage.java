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
package com.alibaba.openagentauth.sample.agent.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.LocalDateTime;

/**
 * Chat message model with authorization status support.
 * <p>
 * This class represents a chat message with support for authorization status tracking.
 * It includes the message role, content, tool call information, and authorization status
 * for tools that require authorization.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChatMessage {
    
    public static final String ROLE_USER = "user";
    public static final String ROLE_ASSISTANT = "assistant";
    public static final String ROLE_TOOL = "tool";
    public static final String ROLE_SYSTEM = "system";
    
    /**
     * Message role: user/assistant/tool/system
     */
    private String role;
    
    /**
     * Message content
     */
    private String content;
    
    /**
     * Tool call information (valid only when role=assistant)
     */
    private ToolCall toolCall;
    
    /**
     * Tool execution result (valid only when role=tool)
     */
    private String toolResult;
    
    /**
     * Authorization status (for messages that triggered authorization)
     */
    @JsonProperty("authorizationStatus")
    private AuthorizationStatus authorizationStatus;
    
    /**
     * Authorization URL (when authorization is required)
     */
    @JsonProperty("authorizationUrl")
    private String authorizationUrl;
    
    /**
     * Timestamp
     */
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime timestamp;
    
    public ChatMessage() {
        this.timestamp = LocalDateTime.now();
    }
    
    public ChatMessage(String role, String content) {
        this.role = role;
        this.content = content;
        this.timestamp = LocalDateTime.now();
    }
    
    public static ChatMessage userMessage(String content) {
        return new ChatMessage(ROLE_USER, content);
    }
    
    public static ChatMessage assistantMessage(String content) {
        return new ChatMessage(ROLE_ASSISTANT, content);
    }
    
    public static ChatMessage toolMessage(String toolResult) {
        ChatMessage message = new ChatMessage();
        message.setRole(ROLE_TOOL);
        message.setToolResult(toolResult);
        message.setTimestamp(LocalDateTime.now());
        return message;
    }
    
    public String getRole() {
        return role;
    }
    
    public void setRole(String role) {
        this.role = role;
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
    
    public String getToolResult() {
        return toolResult;
    }
    
    public void setToolResult(String toolResult) {
        this.toolResult = toolResult;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    
    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
    
    public AuthorizationStatus getAuthorizationStatus() {
        return authorizationStatus;
    }
    
    public void setAuthorizationStatus(AuthorizationStatus authorizationStatus) {
        this.authorizationStatus = authorizationStatus;
    }
    
    public String getAuthorizationUrl() {
        return authorizationUrl;
    }
    
    public void setAuthorizationUrl(String authorizationUrl) {
        this.authorizationUrl = authorizationUrl;
    }
    
    /**
     * Tool call information
     */
    public static class ToolCall {
        /**
         * Tool server name
         */
        private String serverName;
        
        /**
         * Tool name
         */
        private String toolName;
        
        /**
         * Tool arguments
         */
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
    
    /**
     * Authorization status enum
     */
    public enum AuthorizationStatus {

        /**
         * The tool does not require authorization.
         */
        NOT_REQUIRED,
        
        /**
         * Authorization is required but not yet initiated.
         */
        REQUIRED,
        
        /**
         * Authorization flow has been initiated, waiting for user action.
         */
        INITIATED,
        
        /**
         * Authorization has been granted successfully.
         */
        AUTHORIZED,
        
        /**
         * Authorization has been denied by the user.
         */
        DENIED,
        
        /**
         * Authorization flow has failed due to an error.
         */
        FAILED

    }
}
