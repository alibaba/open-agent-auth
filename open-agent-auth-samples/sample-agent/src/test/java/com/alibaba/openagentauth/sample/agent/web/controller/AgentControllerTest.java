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
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ui.Model;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AgentController.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AgentController Tests")
class AgentControllerTest {

    @Mock
    private EnhancedAgentService enhancedAgentService;

    @Mock
    private Model model;

    @Mock
    private HttpSession session;

    @InjectMocks
    private AgentController agentController;

    @Test
    @DisplayName("Should return chat page with no pending tool request")
    void shouldReturnChatPageWithNoPendingToolRequest() {
        when(session.getAttribute("pendingToolRequest")).thenReturn(null);

        String viewName = agentController.chatPage(model, session);

        assertEquals("chat", viewName);
        verify(model).addAttribute("pageTitle", "Open Agent Auth Chat");
        verify(model).addAttribute("hasPendingToolRequest", false);
    }

    @Test
    @DisplayName("Should return chat page with pending tool request")
    void shouldReturnChatPageWithPendingToolRequest() {
        when(session.getAttribute("pendingToolRequest")).thenReturn(new Object());

        String viewName = agentController.chatPage(model, session);

        assertEquals("chat", viewName);
        verify(model).addAttribute("pageTitle", "Open Agent Auth Chat");
        verify(model).addAttribute("hasPendingToolRequest", true);
    }

    @Test
    @DisplayName("Should send message and return response")
    void shouldSendMessageAndReturnResponse() {
        AgentController.ChatRequest request = new AgentController.ChatRequest();
        request.setMessage("Hello");

        ChatMessage expectedResponse = ChatMessage.assistantMessage("Hi there!");
        when(enhancedAgentService.processUserMessage("Hello")).thenReturn(expectedResponse);

        ChatMessage response = agentController.sendMessage(request);

        assertEquals(expectedResponse, response);
        verify(enhancedAgentService).processUserMessage("Hello");
    }

    @Test
    @DisplayName("Should get conversation history")
    void shouldGetConversationHistory() {
        List<ChatMessage> history = new ArrayList<>();
        history.add(ChatMessage.userMessage("Hello"));
        
        when(enhancedAgentService.getConversationHistory()).thenReturn(history);

        List<ChatMessage> result = agentController.getHistory();

        assertEquals(history, result);
        verify(enhancedAgentService).getConversationHistory();
    }

    @Test
    @DisplayName("Should clear conversation")
    void shouldClearConversation() {
        doNothing().when(enhancedAgentService).clearConversation();

        String result = agentController.clearConversation();

        assertEquals("Conversation cleared", result);
        verify(enhancedAgentService).clearConversation();
    }

    @Test
    @DisplayName("Should create new session")
    void shouldCreateNewSession() {
        when(enhancedAgentService.createSession()).thenReturn("session-123");

        String result = agentController.newSession();

        assertTrue(result.contains("session-123"));
        verify(enhancedAgentService).createSession();
    }

    @Test
    @DisplayName("Should get all sessions")
    void shouldGetAllSessions() {
        List<EnhancedAgentService.SessionInfo> sessions = new ArrayList<>();
        EnhancedAgentService.SessionInfo sessionInfo = new EnhancedAgentService.SessionInfo();
        sessionInfo.setId("session-1");
        sessions.add(sessionInfo);

        when(enhancedAgentService.getAllSessions()).thenReturn(sessions);

        List<EnhancedAgentService.SessionInfo> result = agentController.getSessions();

        assertEquals(sessions, result);
        verify(enhancedAgentService).getAllSessions();
    }

    @Test
    @DisplayName("Should delete session")
    void shouldDeleteSession() {
        doNothing().when(enhancedAgentService).deleteSession(anyString());

        String result = agentController.deleteSession("session-123");

        assertEquals("Session deleted: session-123", result);
        verify(enhancedAgentService).deleteSession("session-123");
    }

    @Test
    @DisplayName("Should select session")
    void shouldSelectSession() {
        AgentController.SessionSelectRequest request = new AgentController.SessionSelectRequest();
        request.setSessionId("session-123");

        doNothing().when(enhancedAgentService).selectSession(anyString());

        String result = agentController.selectSession(request);

        assertEquals("Session selected: session-123", result);
        verify(enhancedAgentService).selectSession("session-123");
    }

    @Test
    @DisplayName("Should resume pending tool request")
    void shouldResumePendingToolRequest() {
        ChatMessage expectedMessage = ChatMessage.assistantMessage("Tool executed");
        when(enhancedAgentService.resumePendingToolRequest()).thenReturn(expectedMessage);

        ChatMessage result = agentController.resumePendingTool();

        assertEquals(expectedMessage, result);
        verify(enhancedAgentService).resumePendingToolRequest();
    }

    @Test
    @DisplayName("Should get tool call history")
    void shouldGetToolCallHistory() {
        List<ChatMessage> history = new ArrayList<>();
        ChatMessage message = ChatMessage.assistantMessage("Response");
        ChatMessage.ToolCall toolCall = new ChatMessage.ToolCall("server", "tool", "{}");
        message.setToolCall(toolCall);
        message.setToolResult("Success");
        message.setAuthorizationStatus(ChatMessage.AuthorizationStatus.AUTHORIZED);
        message.setTimestamp(java.time.LocalDateTime.now());
        history.add(message);

        when(enhancedAgentService.getConversationHistory()).thenReturn(history);

        List<AgentController.ToolCallHistoryItem> result = agentController.getToolCalls();

        assertEquals(1, result.size());
        assertEquals("server", result.get(0).getServerName());
        assertEquals("tool", result.get(0).getToolName());
        assertEquals("AUTHORIZED", result.get(0).getStatus());
    }

    @Test
    @DisplayName("ChatRequest should set and get message")
    void chatRequestShouldSetAndGetMessage() {
        AgentController.ChatRequest request = new AgentController.ChatRequest();
        request.setMessage("Test message");

        assertEquals("Test message", request.getMessage());
    }

    @Test
    @DisplayName("SessionSelectRequest should set and get sessionId")
    void sessionSelectRequestShouldSetAndGetSessionId() {
        AgentController.SessionSelectRequest request = new AgentController.SessionSelectRequest();
        request.setSessionId("session-123");

        assertEquals("session-123", request.getSessionId());
    }

    @Test
    @DisplayName("ToolCallHistoryItem should set all fields")
    void toolCallHistoryItemShouldSetAllFields() {
        AgentController.ToolCallHistoryItem item = new AgentController.ToolCallHistoryItem();
        item.setServerName("server");
        item.setToolName("tool");
        item.setArguments("{}");
        item.setResult("result");
        item.setStatus("SUCCESS");
        item.setTimestamp(java.time.LocalDateTime.now());

        assertEquals("server", item.getServerName());
        assertEquals("tool", item.getToolName());
        assertEquals("{}", item.getArguments());
        assertEquals("result", item.getResult());
        assertEquals("SUCCESS", item.getStatus());
        assertNotNull(item.getTimestamp());
    }
}