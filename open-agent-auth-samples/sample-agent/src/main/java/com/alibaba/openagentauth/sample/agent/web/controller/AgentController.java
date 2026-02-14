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
package com.alibaba.openagentauth.sample.agent.web.controller;

import com.alibaba.openagentauth.sample.agent.model.ChatMessage;
import com.alibaba.openagentauth.sample.agent.service.EnhancedAgentService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Agent Web controller
 * 
 * Provides Web interface and API for Agent conversation
 */
@Controller
public class AgentController {
    
    private static final Logger log = LoggerFactory.getLogger(AgentController.class);
    
    private final EnhancedAgentService enhancedAgentService;
    
    public AgentController(EnhancedAgentService enhancedAgentService) {
        this.enhancedAgentService = enhancedAgentService;
    }
    
    /**
     * Chat page
     */
    @GetMapping("/")
    public String chatPage(Model model, jakarta.servlet.http.HttpSession session) {
        log.info("Rendering chat page");
        model.addAttribute("pageTitle", "Open Agent Auth Chat");
        
        // Check if there's a pending tool request that needs to be resumed
        Object pendingToolRequest = session.getAttribute("pendingToolRequest");
        if (pendingToolRequest != null) {
            log.info("Found pending tool request, will be processed on next chat message");
            model.addAttribute("hasPendingToolRequest", true);
        } else {
            model.addAttribute("hasPendingToolRequest", false);
        }
        
        return "chat";
    }
    
    /**
     * Send message (API)
     */
    @PostMapping("/api/chat")
    @ResponseBody
    public ChatMessage sendMessage(@RequestBody ChatRequest request) {
        log.info("Received chat message: {}", request.getMessage());
        return enhancedAgentService.processUserMessage(request.getMessage());
    }
    
    /**
     * Get conversation history (API)
     */
    @GetMapping("/api/history")
    @ResponseBody
    public List<ChatMessage> getHistory() {
        return enhancedAgentService.getConversationHistory();
    }
    
    /**
     * Clear conversation (API)
     */
    @PostMapping("/api/clear")
    @ResponseBody
    public String clearConversation() {
        enhancedAgentService.clearConversation();
        return "Conversation cleared";
    }
    
    /**
     * Create new session (API)
     */
    @PostMapping("/api/newSession")
    @ResponseBody
    public String newSession() {
        log.info("Creating new session via API");
        String sessionId = enhancedAgentService.createSession();
        log.info("New session created with ID: {}", sessionId);
        return "New session created with ID: " + sessionId;
    }
    
    /**
     * Get all sessions (API)
     */
    @GetMapping("/api/sessions")
    @ResponseBody
    public java.util.List<EnhancedAgentService.SessionInfo> getSessions() {
        log.info("Retrieving all sessions via API");
        return enhancedAgentService.getAllSessions();
    }
    
    /**
     * Delete a session (API)
     */
    @DeleteMapping("/api/sessions/{id}")
    @ResponseBody
    public String deleteSession(@PathVariable String id) {
        log.info("Deleting session via API: {}", id);
        enhancedAgentService.deleteSession(id);
        return "Session deleted: " + id;
    }
    
    /**
     * Select a session (API)
     */
    @PostMapping("/api/sessions/select")
    @ResponseBody
    public String selectSession(@RequestBody SessionSelectRequest request) {
        log.info("Selecting session via API: {}", request.getSessionId());
        enhancedAgentService.selectSession(request.getSessionId());
        return "Session selected: " + request.getSessionId();
    }
    
    /**
     * Session select request.
     */
    public static class SessionSelectRequest {
        private String sessionId;
        
        public String getSessionId() {
            return sessionId;
        }
        
        public void setSessionId(String sessionId) {
            this.sessionId = sessionId;
        }
    }
    
    /**
     * Resume pending tool request (API)
     * This endpoint is called automatically after OAuth callback to resume
     * the pending tool request that was interrupted by authentication
     */
    @PostMapping("/api/resumePendingTool")
    @ResponseBody
    public ChatMessage resumePendingTool() {
        log.info("Attempting to resume pending tool request");
        return enhancedAgentService.resumePendingToolRequest();
    }
    
    /**
     * Get tool call history (API)
     * Returns a list of tool calls from the conversation history
     */
    @GetMapping("/api/toolCalls")
    @ResponseBody
    public List<ToolCallHistoryItem> getToolCalls() {
        List<ChatMessage> history = enhancedAgentService.getConversationHistory();
        List<ToolCallHistoryItem> toolCalls = new java.util.ArrayList<>();
        
        for (ChatMessage message : history) {
            if (message.getToolCall() != null) {
                ToolCallHistoryItem item = new ToolCallHistoryItem();
                item.setServerName(message.getToolCall().getServerName());
                item.setToolName(message.getToolCall().getToolName());
                item.setArguments(message.getToolCall().getArguments());
                item.setResult(message.getToolResult());
                item.setTimestamp(message.getTimestamp());
                
                // Determine status based on authorization status
                if (message.getAuthorizationStatus() != null) {
                    item.setStatus(message.getAuthorizationStatus().name());
                } else {
                    item.setStatus("SUCCESS");
                }
                
                toolCalls.add(item);
            }
        }
        
        return toolCalls;
    }
    
    /**
     * Tool call history item
     */
    public static class ToolCallHistoryItem {
        private String serverName;
        private String toolName;
        private String arguments;
        private String result;
        private String status;
        private java.time.LocalDateTime timestamp;
        
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
        
        public String getResult() {
            return result;
        }
        
        public void setResult(String result) {
            this.result = result;
        }
        
        public String getStatus() {
            return status;
        }
        
        public void setStatus(String status) {
            this.status = status;
        }
        
        public java.time.LocalDateTime getTimestamp() {
            return timestamp;
        }
        
        public void setTimestamp(java.time.LocalDateTime timestamp) {
            this.timestamp = timestamp;
        }
    }
    
    /**
     * Chat request
     */
    public static class ChatRequest {
        private String message;
        
        public String getMessage() {
            return message;
        }
        
        public void setMessage(String message) {
            this.message = message;
        }
    }
}
