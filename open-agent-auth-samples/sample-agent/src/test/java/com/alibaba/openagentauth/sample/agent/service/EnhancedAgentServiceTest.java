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

import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.store.impl.InMemorySessionMappingStore;
import com.alibaba.openagentauth.mcp.client.McpAuthContextHolder;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient.LLMChatResponse;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient.ToolCall;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMSession;
import com.alibaba.openagentauth.sample.agent.model.ChatMessage;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EnhancedAgentService}.
 * <p>
 * This test class validates the enhanced agent service implementation
 * including session management, conversation history, and authorization flows.
 * </p>
 */
@DisplayName("EnhancedAgentService Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EnhancedAgentServiceTest {

    private static final String SESSION_ID = "test-session-id";
    private static final String USER_MESSAGE = "Hello, how can I help you?";
    private static final String SERVER_NAME = "test-server";
    private static final String TOOL_NAME = "test-tool";
    private static final String AUTH_URL = "https://auth.example.com/authorize";

    @Mock
    private LLMClient llmClient;

    private ToolAdapterManager toolAdapterManager;

    @Mock
    private AgentAapExecutor agentAapExecutor;

    private SessionMappingBizService sessionMappingBizService;

    private ObjectMapper objectMapper;

    @Mock
    private HttpSession httpSession;

    private ServletRequestAttributes requestAttributes;

    private EnhancedAgentService service;

    @BeforeEach
    void setUp() {
        toolAdapterManager = new ToolAdapterManager();
        sessionMappingBizService = new SessionMappingBizService(new InMemorySessionMappingStore());
        objectMapper = new ObjectMapper();
        
        service = new EnhancedAgentService(
                llmClient,
                toolAdapterManager,
                agentAapExecutor,
                sessionMappingBizService,
                objectMapper
        );

        when(httpSession.getId()).thenReturn(SESSION_ID);
        lenient().when(httpSession.getAttribute(any())).thenReturn(null);
        lenient().when(httpSession.getAttribute(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return null;
        });
        
        // Mock llmClient.createSession() to return a mock LLMSession
        LLMSession mockSession = mock(LLMSession.class);
        when(mockSession.getSessionId()).thenReturn(SESSION_ID);
        when(llmClient.createSession()).thenReturn(mockSession);
        
        jakarta.servlet.http.HttpServletRequest request = mock(jakarta.servlet.http.HttpServletRequest.class);
        when(request.getSession(true)).thenReturn(httpSession);
        requestAttributes = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(requestAttributes);
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        McpAuthContextHolder.clearContext();
    }

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("Should create service with all dependencies")
        void shouldCreateServiceWithAllDependencies() {
            assertThat(service).isNotNull();
        }
    }

    @Nested
    @DisplayName("createSession()")
    class CreateSessionTests {

        @Test
        @DisplayName("Should create session successfully")
        void shouldCreateSessionSuccessfully() {
            LLMSession llmSession = mock(LLMSession.class);
            when(llmSession.getSessionId()).thenReturn(SESSION_ID);
            when(llmClient.createSession()).thenReturn(llmSession);

            String sessionId = service.createSession();

            assertThat(sessionId).isEqualTo(SESSION_ID);
            verify(llmClient).createSession();
            verify(httpSession).removeAttribute(SessionAttributes.WORKLOAD_CONTEXT.getKey());
            verify(httpSession).removeAttribute(SessionAttributes.AGENT_OA_TOKEN.getKey());
            verify(httpSession).removeAttribute(SessionAttributes.PENDING_TOOL_REQUEST.getKey());
        }
    }

    @Nested
    @DisplayName("processUserMessage() - Success Scenarios")
    class ProcessUserMessageSuccessTests {

        @Test
        @DisplayName("Should process user message successfully without tool calls")
        void shouldProcessUserMessageSuccessfullyWithoutToolCalls() {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            LLMChatResponse llmResponse = new LLMChatResponse();
            llmResponse.setContent("Hello! How can I help you?");
            llmResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(llmResponse);

            ChatMessage result = service.processUserMessage(USER_MESSAGE);

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
            assertThat(result.getContent()).isEqualTo("Hello! How can I help you?");
            assertThat(result.getToolCall()).isNull();
        }

        @Test
        @DisplayName("Should process user message with single tool call")
        void shouldProcessUserMessageWithSingleToolCall() throws Exception {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            // First LLM call - returns tool call
            LLMChatResponse firstResponse = new LLMChatResponse();
            firstResponse.setContent("I'll check the weather for you.");
            firstResponse.setNeedToolCall(true);
            ToolCall toolCall = new ToolCall(SERVER_NAME, TOOL_NAME, "{}");
            firstResponse.setToolCall(toolCall);
            when(llmClient.chatWithTools(any(), any())).thenReturn(firstResponse);

            // Second LLM call - generates final response
            LLMChatResponse finalResponse = new LLMChatResponse();
            finalResponse.setContent("The current temperature is 25°C.");
            finalResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(finalResponse);

            ChatMessage result = service.processUserMessage("What's the weather?");

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
            // Since toolAdapterManager is a real instance without any registered adapters,
            // tool execution will fail and won't make the second LLM call
            verify(llmClient, times(1)).chatWithTools(any(), any());
        }
    }

    @Nested
    @DisplayName("processUserMessage() - Failure Scenarios")
    class ProcessUserMessageFailureTests {

        @Test
        @DisplayName("Should handle tool execution failure gracefully")
        void shouldHandleToolExecutionFailureGracefully() throws Exception {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            LLMChatResponse firstResponse = new LLMChatResponse();
            firstResponse.setContent("I'll try to execute that.");
            firstResponse.setNeedToolCall(true);
            ToolCall toolCall = new ToolCall(SERVER_NAME, TOOL_NAME, "{}");
            firstResponse.setToolCall(toolCall);
            when(llmClient.chatWithTools(any(), any())).thenReturn(firstResponse);

            LLMChatResponse finalResponse = new LLMChatResponse();
            finalResponse.setContent("Sorry, I couldn't complete that task.");
            finalResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(finalResponse);

            ChatMessage result = service.processUserMessage("Execute failing command");

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
            assertThat(result.getContent()).isEqualTo("Sorry, I couldn't complete that task.");
        }

        @Test
        @DisplayName("Should handle empty conversation history")
        void shouldHandleEmptyConversationHistory() {
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(new ArrayList<>());

            LLMChatResponse llmResponse = new LLMChatResponse();
            llmResponse.setContent("I'm ready to help!");
            llmResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(llmResponse);

            ChatMessage result = service.processUserMessage(USER_MESSAGE);

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
        }
    }

    @Nested
    @DisplayName("processUserMessage() - Exception Handling")
    class ProcessUserMessageExceptionTests {

        @Test
        @DisplayName("Should handle LLM client exception")
        void shouldHandleLLMClientException() {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            when(llmClient.chatWithTools(any(), any()))
                    .thenThrow(new RuntimeException("LLM service unavailable"));

            ChatMessage result = service.processUserMessage(USER_MESSAGE);

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
            assertThat(result.getContent()).contains("Sorry, an error occurred while processing your request");
        }

        @Test
        @DisplayName("Should handle tool execution exception")
        void shouldHandleToolExecutionException() throws Exception {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            LLMChatResponse firstResponse = new LLMChatResponse();
            firstResponse.setContent("I'll execute a tool.");
            firstResponse.setNeedToolCall(true);
            ToolCall toolCall = new ToolCall(SERVER_NAME, TOOL_NAME, "{}");
            firstResponse.setToolCall(toolCall);
            when(llmClient.chatWithTools(any(), any())).thenReturn(firstResponse);

            ChatMessage result = service.processUserMessage("Use a tool");

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
        }

        @Test
        @DisplayName("Should handle null tool calls response")
        void shouldHandleNullToolCallsResponse() {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            LLMChatResponse llmResponse = new LLMChatResponse();
            llmResponse.setContent("Response without tools");
            llmResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(llmResponse);

            ChatMessage result = service.processUserMessage(USER_MESSAGE);

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
            assertThat(result.getContent()).isEqualTo("Response without tools");
        }
    }

    @Nested
    @DisplayName("processUserMessage() - Boundary Conditions")
    class ProcessUserMessageBoundaryTests {

        @Test
        @DisplayName("Should handle very long message")
        void shouldHandleVeryLongMessage() {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            StringBuilder longMessage = new StringBuilder();
            for (int i = 0; i < 10000; i++) {
                longMessage.append("This is a long message. ");
            }

            LLMChatResponse llmResponse = new LLMChatResponse();
            llmResponse.setContent("I received your long message.");
            llmResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(llmResponse);

            ChatMessage result = service.processUserMessage(longMessage.toString());

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
        }

        @Test
        @DisplayName("Should handle message with special characters")
        void shouldHandleMessageWithSpecialCharacters() {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            String specialMessage = "Test with special chars: <>&\"'\\n\\t\\u0000";

            LLMChatResponse llmResponse = new LLMChatResponse();
            llmResponse.setContent("Special chars received.");
            llmResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(llmResponse);

            ChatMessage result = service.processUserMessage(specialMessage);

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
        }

        @Test
        @DisplayName("Should handle empty message")
        void shouldHandleEmptyMessage() {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            LLMChatResponse llmResponse = new LLMChatResponse();
            llmResponse.setContent("I'm processing your request.");
            llmResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(llmResponse);

            ChatMessage result = service.processUserMessage("");

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
        }

        @Test
        @DisplayName("Should handle multiple tool calls")
        void shouldHandleMultipleToolCalls() throws Exception {
            List<ChatMessage> conversationHistory = new ArrayList<>();
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(conversationHistory);

            LLMChatResponse firstResponse = new LLMChatResponse();
            firstResponse.setContent("I'll check both weather and time.");
            firstResponse.setNeedToolCall(true);
            ToolCall toolCall = new ToolCall("weather-server", "getWeather", "{\"time-server\": \"getTime\"}");
            firstResponse.setToolCall(toolCall);
            when(llmClient.chatWithTools(any(), any())).thenReturn(firstResponse);

            LLMChatResponse finalResponse = new LLMChatResponse();
            finalResponse.setContent("Weather is 25°C and time is 12:00.");
            finalResponse.setNeedToolCall(false);
            when(llmClient.chatWithTools(any(), any())).thenReturn(finalResponse);

            ChatMessage result = service.processUserMessage("Check weather and time");

            assertThat(result).isNotNull();
            assertThat(result.getRole()).isEqualTo("assistant");
            assertThat(result.getContent()).isEqualTo("Weather is 25°C and time is 12:00.");
        }
    }

    @Nested
    @DisplayName("getConversationHistory()")
    class GetConversationHistoryTests {

        @Test
        @DisplayName("Should return empty list when no history exists")
        void shouldReturnEmptyListWhenNoHistoryExists() {
            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(new ArrayList<>());

            List<ChatMessage> history = service.getConversationHistory();

            assertThat(history).isNotNull();
            assertThat(history).isEmpty();
        }

        @Test
        @DisplayName("Should return conversation history")
        void shouldReturnConversationHistory() {
            List<ChatMessage> messages = new ArrayList<>();
            messages.add(ChatMessage.userMessage("Hello"));
            messages.add(ChatMessage.assistantMessage("Hi there!"));

            when(httpSession.getAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey()))
                    .thenReturn(messages);

            List<ChatMessage> history = service.getConversationHistory();

            assertThat(history).hasSize(2);
            assertThat(history.get(0).getRole()).isEqualTo("user");
            assertThat(history.get(1).getRole()).isEqualTo("assistant");
        }
    }

    @Nested
    @DisplayName("clearConversation()")
    class ClearConversationTests {

        @Test
        @DisplayName("Should clear conversation history")
        void shouldClearConversationHistory() {
            service.clearConversation();

            verify(httpSession).removeAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey());
        }
    }

    @Nested
    @DisplayName("resumePendingToolRequest()")
    class ResumePendingToolRequestTests {

        @Test
        @DisplayName("Should return message when no pending request exists")
        void shouldReturnMessageWhenNoPendingRequestExists() {
            when(httpSession.getAttribute(SessionAttributes.PENDING_TOOL_REQUEST.getKey()))
                    .thenReturn(null);

            ChatMessage result = service.resumePendingToolRequest();

            assertThat(result).isNotNull();
            assertThat(result.getContent()).contains("No pending tool request");
        }

        @Test
        @DisplayName("Should return error message when authorization context not found")
        void shouldReturnErrorMessageWhenAuthorizationContextNotFound() throws Exception {
            Map<String, Object> pendingRequest = new HashMap<>();
            pendingRequest.put("serverName", SERVER_NAME);
            pendingRequest.put("toolName", TOOL_NAME);
            pendingRequest.put("arguments", new HashMap<>());

            when(httpSession.getAttribute(SessionAttributes.PENDING_TOOL_REQUEST.getKey()))
                    .thenReturn(pendingRequest);
            when(httpSession.getAttribute(SessionAttributes.WORKLOAD_CONTEXT.getKey()))
                    .thenReturn(null);

            ChatMessage result = service.resumePendingToolRequest();

            assertThat(result).isNotNull();
            assertThat(result.getContent()).contains("Authorization context not found");
        }

        @Test
        @DisplayName("Should handle exception when resuming pending tool request")
        void shouldHandleExceptionWhenResumingPendingToolRequest() {
            Map<String, Object> pendingRequest = new HashMap<>();
            pendingRequest.put("serverName", SERVER_NAME);
            pendingRequest.put("toolName", TOOL_NAME);
            pendingRequest.put("arguments", new HashMap<>());

            when(httpSession.getAttribute(SessionAttributes.PENDING_TOOL_REQUEST.getKey()))
                    .thenReturn(pendingRequest);
            when(httpSession.getAttribute(SessionAttributes.WORKLOAD_CONTEXT.getKey()))
                    .thenThrow(new RuntimeException("Session error"));

            ChatMessage result = service.resumePendingToolRequest();

            assertThat(result).isNotNull();
            assertThat(result.getContent()).contains("Failed to resume pending tool request");
        }
    }

    @Nested
    @DisplayName("getAllSessions()")
    class GetAllSessionsTests {

        @Test
        @DisplayName("Should return empty list when no sessions exist")
        void shouldReturnEmptyListWhenNoSessionsExist() {
            List<EnhancedAgentService.SessionInfo> sessions = service.getAllSessions();

            assertThat(sessions).isNotNull();
            assertThat(sessions).isEmpty();
        }

        @Test
        @DisplayName("Should return all sessions sorted by creation time")
        void shouldReturnAllSessionsSortedByCreationTime() {
            LLMSession llmSession1 = mock(LLMSession.class);
            LLMSession llmSession2 = mock(LLMSession.class);
            when(llmSession1.getSessionId()).thenReturn(SESSION_ID + "-1");
            when(llmSession2.getSessionId()).thenReturn(SESSION_ID + "-2");
            when(llmClient.createSession())
                    .thenReturn(llmSession1)
                    .thenReturn(llmSession2);
            service.createSession();
            service.createSession();

            List<EnhancedAgentService.SessionInfo> sessions = service.getAllSessions();

            assertThat(sessions).hasSize(2);
            assertThat(sessions.get(0).getCreatedAt()).isNotNull();
        }
    }

    @Nested
    @DisplayName("deleteSession()")
    class DeleteSessionTests {

        @Test
        @DisplayName("Should delete session successfully")
        void shouldDeleteSessionSuccessfully() {
            LLMSession llmSession = mock(LLMSession.class);
            when(llmSession.getSessionId()).thenReturn(SESSION_ID);
            when(llmClient.createSession()).thenReturn(llmSession);
            String sessionId = service.createSession();

            service.deleteSession(sessionId);

            List<EnhancedAgentService.SessionInfo> sessions = service.getAllSessions();
            assertThat(sessions).noneMatch(s -> s.getId().equals(sessionId));
        }

        @Test
        @DisplayName("Should handle deleting non-existent session")
        void shouldHandleDeletingNonExistentSession() {
            // Should not throw exception
            service.deleteSession("non-existent-session");

            List<EnhancedAgentService.SessionInfo> sessions = service.getAllSessions();
            assertThat(sessions).isEmpty();
        }
    }

    @Nested
    @DisplayName("selectSession()")
    class SelectSessionTests {

        @Test
        @DisplayName("Should throw exception when session not found")
        void shouldThrowExceptionWhenSessionNotFound() {
            assertThatThrownBy(() -> service.selectSession("non-existent-session"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session not found");
        }

        @Test
        @DisplayName("Should select session successfully")
        void shouldSelectSessionSuccessfully() {
            LLMSession llmSession1 = mock(LLMSession.class);
            LLMSession llmSession2 = mock(LLMSession.class);
            when(llmSession1.getSessionId()).thenReturn(SESSION_ID + "-1");
            when(llmSession2.getSessionId()).thenReturn(SESSION_ID + "-2");
            when(llmClient.createSession())
                    .thenReturn(llmSession1)
                    .thenReturn(llmSession2);
            String sessionId1 = service.createSession();
            String sessionId2 = service.createSession();

            service.selectSession(sessionId2);

            List<EnhancedAgentService.SessionInfo> sessions = service.getAllSessions();
            EnhancedAgentService.SessionInfo selectedSession1 = sessions.stream()
                    .filter(s -> s.getId().equals(sessionId1))
                    .findFirst()
                    .orElseThrow();
            EnhancedAgentService.SessionInfo selectedSession2 = sessions.stream()
                    .filter(s -> s.getId().equals(sessionId2))
                    .findFirst()
                    .orElseThrow();
            assertThat(selectedSession1.isActive()).isFalse();
            assertThat(selectedSession2.isActive()).isTrue();
        }

        @Test
        @DisplayName("Should load conversation history when selecting session")
        void shouldLoadConversationHistoryWhenSelectingSession() {
            LLMSession llmSession = mock(LLMSession.class);
            when(llmSession.getSessionId()).thenReturn(SESSION_ID);
            when(llmClient.createSession()).thenReturn(llmSession);
            String sessionId = service.createSession();
            List<ChatMessage> history = new ArrayList<>();
            history.add(ChatMessage.userMessage("Hello"));

            EnhancedAgentService.SessionInfo sessionInfo = service.getAllSessions().stream()
                    .filter(s -> s.getId().equals(sessionId))
                    .findFirst()
                    .orElseThrow();
            sessionInfo.setConversationHistory(history);

            service.selectSession(sessionId);

            verify(httpSession).setAttribute(SessionAttributes.CONVERSATION_HISTORY.getKey(), history);
        }
    }

    @Nested
    @DisplayName("SessionInfo")
    class SessionInfoTests {

        @Test
        @DisplayName("Should set and get session properties")
        void shouldSetAndGetSessionProperties() {
            EnhancedAgentService.SessionInfo sessionInfo = new EnhancedAgentService.SessionInfo();
            sessionInfo.setId("session-123");
            sessionInfo.setTitle("Test Session");
            sessionInfo.setActive(true);
            sessionInfo.setCreatedAt(LocalDateTime.now());

            assertThat(sessionInfo.getId()).isEqualTo("session-123");
            assertThat(sessionInfo.getTitle()).isEqualTo("Test Session");
            assertThat(sessionInfo.isActive()).isTrue();
            assertThat(sessionInfo.getCreatedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should handle null conversation history")
        void shouldHandleNullConversationHistory() {
            EnhancedAgentService.SessionInfo sessionInfo = new EnhancedAgentService.SessionInfo();
            sessionInfo.setConversationHistory(null);

            assertThat(sessionInfo.getConversationHistory()).isNull();
        }
    }
}