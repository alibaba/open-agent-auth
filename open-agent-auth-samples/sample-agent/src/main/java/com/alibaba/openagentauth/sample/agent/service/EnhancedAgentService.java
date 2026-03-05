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

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.token.aoat.AoatParser;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkAuthorizationContextException;
import com.alibaba.openagentauth.framework.executor.AgentAapExecutor;
import com.alibaba.openagentauth.framework.model.context.AgentAuthorizationContext;
import com.alibaba.openagentauth.framework.model.request.PrepareAuthorizationContextRequest;
import com.alibaba.openagentauth.framework.model.request.RequestAuthUrlRequest;
import com.alibaba.openagentauth.framework.model.response.RequestAuthUrlResponse;
import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.alibaba.openagentauth.framework.model.workload.WorkloadRequestContext;
import com.alibaba.openagentauth.framework.web.service.SessionMappingBizService;
import com.alibaba.openagentauth.framework.web.manager.SessionAttributes;
import com.alibaba.openagentauth.framework.web.manager.SessionManager;
import com.alibaba.openagentauth.mcp.client.McpAuthContext;
import com.alibaba.openagentauth.mcp.client.McpAuthContextHolder;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient.LLMChatResponse;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient.ToolCall;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMSession;
import com.alibaba.openagentauth.sample.agent.model.ChatMessage;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.openagentauth.sample.agent.model.ToolResult;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enhanced Agent service with authorization flow integration.
 * <p>
 * This service extends the basic AgentService with authorization flow support.
 * When a tool requires authorization, it initiates the authorization flow and
 * stores the authorization context for subsequent tool execution.
 * </p>
 *
 * @since 1.0
 */
@Service
public class EnhancedAgentService {
    
    private static final Logger log = LoggerFactory.getLogger(EnhancedAgentService.class);
    
    private final LLMClient llmClient;
    private final ToolAdapterManager toolAdapterManager;
    private final AgentAapExecutor agentAapExecutor;
    private final SessionMappingBizService sessionMappingBizService;
    private final ObjectMapper objectMapper;
    private final AoatParser aoatParser = new AoatParser();
    
    /**
     * In-memory storage for session list.
     * Key: sessionId, Value: session metadata (title, createdAt, conversation history, etc.)
     */
    private final Map<String, SessionInfo> sessionListStore = new ConcurrentHashMap<>();
    
    /**
     * Current active session ID.
     */
    private volatile String currentSessionId;
    
    /**
     * Conversation history - stored in HttpSession to persist across requests
     * This ensures conversation history is preserved during login flow
     */
    
    /**
     * Constructor.
     */
    public EnhancedAgentService(
            LLMClient llmClient,
            ToolAdapterManager toolAdapterManager,
            AgentAapExecutor agentAapExecutor,
            SessionMappingBizService sessionMappingBizService,
            ObjectMapper objectMapper) {
        this.llmClient = llmClient;
        this.toolAdapterManager = toolAdapterManager;
        this.agentAapExecutor = agentAapExecutor;
        this.sessionMappingBizService = sessionMappingBizService;
        this.objectMapper = objectMapper;
    }
    
    /**
     * Create a new session
     * 
     * @return session ID
     */
    public String createSession() {
        log.info("Creating new agent session");
        
        // Save current session's conversation history before creating new session
        HttpSession httpSession = getCurrentSession();
        if (currentSessionId != null) {
            List<ChatMessage> currentHistory = SessionManager.getAttributeAsList(
                httpSession, 
                SessionAttributes.CONVERSATION_HISTORY, 
                ChatMessage.class
            );
            SessionInfo currentSession = sessionListStore.get(currentSessionId);
            if (currentSession != null && !currentHistory.isEmpty()) {
                currentSession.setConversationHistory(new ArrayList<>(currentHistory));
                log.info("Saved conversation history for session: {}", currentSessionId);
            }
        }
        
        // Clear conversation history
        clearConversation();
        
        // Clear MCP authentication related session attributes
        SessionManager.removeAttribute(httpSession, SessionAttributes.WORKLOAD_CONTEXT);
        SessionManager.removeAttribute(httpSession, SessionAttributes.AGENT_OA_TOKEN);
        SessionManager.removeAttribute(httpSession, SessionAttributes.PENDING_TOOL_REQUEST);
        log.info("Cleared MCP authentication related session attributes");
        
        // Create new LLM session
        LLMSession llmSession = llmClient.createSession();
        
        // Get session ID
        String sessionId = llmSession.getSessionId();
        log.info("New agent session created with ID: {}", sessionId);
        
        // Store session metadata in session list
        SessionInfo sessionInfo = new SessionInfo();
        sessionInfo.setId(sessionId != null ? sessionId : "session_" + System.currentTimeMillis());
        sessionInfo.setTitle("New Session");
        sessionInfo.setCreatedAt(LocalDateTime.now());
        sessionInfo.setActive(true);
        
        // Mark all other sessions as inactive
        sessionListStore.values().forEach(s -> s.setActive(false));
        
        // Add to session list
        sessionListStore.put(sessionInfo.getId(), sessionInfo);
        currentSessionId = sessionInfo.getId();
        log.info("Session metadata stored: {}", sessionInfo.getId());
        
        return sessionInfo.getId();
    }
    
    /**
     * Generate a session title based on the first user message.
     * 
     * @param conversationHistory the conversation history
     * @return generated title
     */
    private String generateSessionTitle(List<ChatMessage> conversationHistory) {
        if (conversationHistory == null || conversationHistory.isEmpty()) {
            return "New Session";
        }
        
        // Find the first user message
        for (ChatMessage message : conversationHistory) {
            if ("user".equals(message.getRole())) {
                String content = message.getContent();
                if (content != null && !content.isBlank()) {
                    // Generate title from first user message
                    String title = content.trim();
                    // Limit title length to 50 characters
                    if (title.length() > 50) {
                        title = title.substring(0, 47) + "...";
                    }
                    return title;
                }
            }
        }
        
        return "New Session";
    }
    
    /**
     * Update session title based on current conversation.
     */
    private void updateSessionTitle() {
        if (currentSessionId == null) {
            return;
        }
        
        SessionInfo session = sessionListStore.get(currentSessionId);
        if (session == null) {
            return;
        }
        
        // Only update title if it's still "New Session"
        if ("New Session".equals(session.getTitle())) {
            HttpSession httpSession = getCurrentSession();
            List<ChatMessage> conversationHistory = SessionManager.getAttributeAsList(
                httpSession, 
                SessionAttributes.CONVERSATION_HISTORY, 
                ChatMessage.class
            );
            
            String newTitle = generateSessionTitle(conversationHistory);
            if (!"New Session".equals(newTitle)) {
                session.setTitle(newTitle);
                log.info("Updated session title: {} -> {}", currentSessionId, newTitle);
            }
        }
    }
    
    /**
     * Process user message with authorization flow support.
     * 
     * @param userMessage User message
     * @return AI response
     */
    public ChatMessage processUserMessage(String userMessage) {
        log.info("Processing user message: {}", userMessage);
        
        // Auto-create session if this is the first message and no session exists
        if (currentSessionId == null) {
            log.info("No current session exists, creating one automatically");
            createSession();
        }
        
        // Get conversation history from session
        HttpSession session = getCurrentSession();
        List<ChatMessage> conversationHistory = SessionManager.getAttributeAsList(
            session, 
            SessionAttributes.CONVERSATION_HISTORY, 
            ChatMessage.class
        );
        
        // Add user message to history
        ChatMessage userChatMessage = ChatMessage.userMessage(userMessage);
        SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, userChatMessage, ChatMessage.class);
        
        // Update session title based on conversation
        updateSessionTitle();
        
        // Refresh conversation history after adding user message
        conversationHistory = SessionManager.getAttributeAsList(
            session, 
            SessionAttributes.CONVERSATION_HISTORY, 
            ChatMessage.class
        );
        
        try {
            // Check if there's a pending tool request from before authentication
            Map<String, Object> pendingToolRequest = SessionManager.getAttribute(session, SessionAttributes.PENDING_TOOL_REQUEST);
            if (pendingToolRequest != null) {
                log.info("Found pending tool request, resuming authorization flow");
                
                // Resume tool call with authorization
                String serverName = (String) pendingToolRequest.get("serverName");
                String toolName = (String) pendingToolRequest.get("toolName");
                @SuppressWarnings("unchecked")
                Map<String, Object> arguments = (Map<String, Object>) pendingToolRequest.get("arguments");
                
                ChatMessage.ToolCall tc = new ChatMessage.ToolCall(serverName, toolName, 
                        new ObjectMapper().writeValueAsString(arguments));
                
                // Remove pending request from session
                SessionManager.removeAttribute(session, SessionAttributes.PENDING_TOOL_REQUEST);
                
                // Create a mock ToolCall for resuming
                ToolCall resumeToolCall = new ToolCall(serverName, toolName, 
                        new ObjectMapper().writeValueAsString(arguments));
                
                return handleToolWithAuthorization(resumeToolCall, arguments, tc);
            }
            
            // Get all available tools
            List<ToolDefinition> tools = toolAdapterManager.getAllTools();
            log.info("Available tools: {}", tools.size());
            
            // Convert to Qwen format
            List<Map<String, String>> llmMessages = convertMessagesToQwenFormat(conversationHistory);
            
            // Call LLM with tools
            LLMChatResponse response = llmClient.chatWithTools(llmMessages, tools);
            
            if (response.isNeedToolCall()) {
                // Need to call tool
                return handleToolCall(response);
            } else {
                // No tool call needed, return AI response directly
                ChatMessage assistantMessage = ChatMessage.assistantMessage(response.getContent());
                SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, assistantMessage, ChatMessage.class);
                return assistantMessage;
            }
            
        } catch (Exception e) {
            log.error("Failed to process user message", e);
            ChatMessage errorMessage = ChatMessage.assistantMessage("Sorry, an error occurred while processing your request: " + e.getMessage());
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
            return errorMessage;
        }
    }
    
    /**
     * Handle tool call with authorization flow support.
     */
    private ChatMessage handleToolCall(LLMChatResponse response) {
        ToolCall toolCall = response.getToolCall();
        
        log.info("=== FIRST LLM CALL: Tool request detected ===");
        log.info("Handling tool call: server={}, tool={}, arguments={}", 
                toolCall.getServerName(), toolCall.getToolName(), toolCall.getArguments());
        
        // Extract only the text content (without tool call XML tags) from response
        String textContent = extractTextContent(response.getContent());
        
        // Create tool call message with only the text content
        ChatMessage toolCallMessage = new ChatMessage();
        toolCallMessage.setRole(ChatMessage.ROLE_ASSISTANT);
        toolCallMessage.setContent(textContent);
        ChatMessage.ToolCall tc = new ChatMessage.ToolCall(
                toolCall.getServerName(), 
                toolCall.getToolName(), 
                toolCall.getArguments()
        );
        toolCallMessage.setToolCall(tc);
        
        // Get conversation history from session
        HttpSession session = getCurrentSession();
        SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, toolCallMessage, ChatMessage.class);
        
        try {
            // Parse arguments
            Map<String, Object> arguments = objectMapper.readValue(
                    toolCall.getArguments(),
                    new TypeReference<>() {}
            );
            
            // Check if tool requires authorization
            if (requiresAuthorization()) {
                log.info("Tool requires authorization, initiating authorization flow");
                return handleToolWithAuthorization(toolCall, arguments, tc);
            } else {
                // Call tool directly without authorization
                return callToolDirectly(toolCall, arguments, tc);
            }
            
        } catch (Exception e) {
            log.error("Failed to execute tool call", e);
            ChatMessage errorMessage = ChatMessage.assistantMessage("Sorry, tool call failed: " + e.getMessage());
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
            return errorMessage;
        }
    }
    
    /**
     * Check if a tool requires authorization.
     * <p>
     * For simplicity, we assume all tools require authorization if the user
     * is not authenticated. In a real implementation, this would check
     * the tool's metadata or configuration.
     * </p>

     * @return true if authorization is required
     */
    private boolean requiresAuthorization() {
        // Get current session
        HttpSession session = getCurrentSession();
        
        // Check if user is authenticated (has ID Token)
        String idToken = SessionManager.getAttribute(session, SessionAttributes.ID_TOKEN);
        if (idToken == null || idToken.isBlank()) {
            log.info("User not authenticated, authorization required");
            return true;
        }
        
        // Check if AOAT is already available in session
        String aoat = SessionManager.getAttribute(session, SessionAttributes.AGENT_OA_TOKEN);
        if (aoat != null) {
            log.info("AOAT already available in session, no authorization required");
            return false;
        }
        
        // Authorization required
        return true;
    }
    
    /**
     * Handle tool call with authorization.
     */
    private ChatMessage handleToolWithAuthorization(ToolCall toolCall, Map<String, Object> arguments, ChatMessage.ToolCall tc) 
            throws WorkloadCreationException, FrameworkAuthorizationException {
        
        HttpSession session = getCurrentSession();
        String idToken = SessionManager.getAttribute(session, SessionAttributes.ID_TOKEN);
        
        if (idToken == null || idToken.isBlank()) {
            // User not authenticated, store tool request info in session for later processing
            // Do NOT create WorkloadContext yet - wait until user is logged in
            log.warn("User not authenticated, storing tool request for later processing");
            
            // Store tool request information in session
            Map<String, Object> pendingToolRequest = new HashMap<>();
            pendingToolRequest.put("serverName", toolCall.getServerName());
            pendingToolRequest.put("toolName", toolCall.getToolName());
            pendingToolRequest.put("arguments", arguments);
            SessionManager.setAttribute(session, SessionAttributes.PENDING_TOOL_REQUEST, pendingToolRequest);
            
            ChatMessage authRequiredMessage = ChatMessage.assistantMessage(
                    "This tool requires authentication. Please log in first."
            );
            authRequiredMessage.setAuthorizationStatus(ChatMessage.AuthorizationStatus.REQUIRED);
            
            // Get conversation history from session
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, authRequiredMessage, ChatMessage.class);
            return authRequiredMessage;
        }
        
        // User is authenticated, proceed with authorization flow
        // Get tool definition
        ToolDefinition toolDefinition = findToolDefinition(toolCall.getServerName(), toolCall.getToolName());
        
        // CRITICAL: Extract user's original natural-language input from conversation history
        // According to draft-liu-agent-operation-authorization-01, the auditTrail.originalPromptText
        // MUST contain the user's original input (e.g., "i want to buy some programming book"),
        // NOT a system-generated description (e.g., "Execute tool: search_products")
        String userOriginalInput = extractOriginalUserInputFromHistory();
        if (userOriginalInput == null || userOriginalInput.isBlank()) {
            log.warn("Could not extract original user input from conversation history, using fallback");
            userOriginalInput = "User requested tool execution"; // Fallback value
        }
        log.info("Extracted original user input for evidence: {}", userOriginalInput);
        
        // IMPORTANT: Store tool request information in session for resuming after OAuth callback
        // This allows the system to automatically resume the tool call after user authorization
        log.info("Storing pending tool request for Agent Operation Authorization flow");
        Map<String, Object> pendingToolRequest = new HashMap<>();
        pendingToolRequest.put("serverName", toolCall.getServerName());
        pendingToolRequest.put("toolName", toolCall.getToolName());
        pendingToolRequest.put("arguments", arguments);
        SessionManager.setAttribute(session, SessionAttributes.PENDING_TOOL_REQUEST, pendingToolRequest);
        
        // Initiate authorization flow with user's original input
        String sessionId = session.getId();

        // Build RequestAuthUrlRequest from the parameters
        // Configuration parameters (clientId, redirectUri, channel, language, platform, agentClient, deviceFingerprint)
        // are now managed through AgentAapExecutorConfig and do not need to be set here
        WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType(toolDefinition.getToolName())
                .resourceId(toolDefinition.getServerName())
                .metadata(arguments)
                .build();

        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken(idToken)
                .userOriginalInput(userOriginalInput)
                .workloadContext(workloadContext)
                .sessionId(sessionId)
                .build();

        RequestAuthUrlResponse flowResult = agentAapExecutor.requestAuthUrl(request);
        
        // Store session mapping for later restoration
        // IMPORTANT: Use sessionId as key (not state) to match OAuth2CallbackController's lookup logic
        sessionMappingBizService.storeSession(sessionId, session);
        log.info("Session mapping stored: sessionId={}, state={}", sessionId, flowResult.getState());
        
        // IMPORTANT: Store state in session for CSRF validation during callback
        SessionManager.setAttribute(session, SessionAttributes.OAUTH_STATE, flowResult.getState());
        log.info("State stored in session for CSRF validation: {}", flowResult.getState());
        
        // Store WorkloadContext in session for callback handling
        SessionManager.setAttribute(session, SessionAttributes.WORKLOAD_CONTEXT, flowResult.getWorkloadContext());
        
        // Create message indicating authorization is required
        ChatMessage authRequiredMessage = new ChatMessage();
        authRequiredMessage.setRole("assistant");
        authRequiredMessage.setContent("This tool requires your authorization. Please click the link below to authorize the operation.");
        authRequiredMessage.setToolCall(tc);
        authRequiredMessage.setAuthorizationStatus(ChatMessage.AuthorizationStatus.INITIATED);
        authRequiredMessage.setAuthorizationUrl(flowResult.getAuthorizationUrl());
        
        // Get conversation history from session
        SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, authRequiredMessage, ChatMessage.class);
        
        log.info("Authorization flow initiated, authUrl: {}", flowResult.getAuthorizationUrl());
        log.info("WorkloadContext stored in session: {}", flowResult.getWorkloadContext().getWorkloadId());
        
        return authRequiredMessage;
    }
    
    /**
     * Call tool directly with authorization context.
     */
    private ChatMessage callToolWithAuthorization(ToolCall toolCall, Map<String, Object> arguments, ChatMessage.ToolCall tc) {
        HttpSession session = getCurrentSession();
        
        // Get authorization context from session
        WorkloadContext workloadContext = SessionManager.getAttribute(session, SessionAttributes.WORKLOAD_CONTEXT);
        String aoatString = SessionManager.getAttribute(session, SessionAttributes.AGENT_OA_TOKEN);
        
        if (workloadContext == null || aoatString == null) {
            log.error("Authorization context not found in session");
            ChatMessage errorMessage = ChatMessage.assistantMessage("Authorization context not found. Please authorize again.");
            
            // Get conversation history from session
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
            return errorMessage;
        }
        
        try {
            // Parse AOAT using AoatParser
            SignedJWT signedJwt = SignedJWT.parse(aoatString);
            AgentOperationAuthToken aoat = aoatParser.parse(signedJwt);
            if (aoat == null) {
                log.error("AOAT not found in session");
                throw new FrameworkAuthorizationContextException("AOAT not found in session, please authorize again");
            }
            
            // Prepare authorization context
            AgentAuthorizationContext authContext = agentAapExecutor.buildAuthorizationContext(
                    PrepareAuthorizationContextRequest.builder()
                            .workloadContext(workloadContext)
                            .aoat(aoat)
                            .build());
            
            // Create MCP auth context from ToolAuthorizationContext
            McpAuthContext mcpAuthContext = new McpAuthContext(
                    authContext.getAoat(),
                    authContext.getWit(),
                    authContext.getWpt()
            );
            
            // Set auth context to ThreadLocal for MCP tool calls
            McpAuthContextHolder.setContext(mcpAuthContext);
            log.info("MCP auth context set: aoat={}, wit={}, wpt={}", 
                    authContext.getAoat() != null ? "***" : null,
                    authContext.getWit() != null ? "***" : null,
                    authContext.getWpt() != null ? "***" : null);
            
            // Use the authorization context to call the tool
            // The auth context is now available in ThreadLocal for MCP adapters
            ToolResult result = toolAdapterManager.callTool(
                    toolCall.getServerName(), 
                    toolCall.getToolName(), 
                    arguments
            );
            
            // Clear auth context from ThreadLocal after tool call
            McpAuthContextHolder.clearContext();
            log.info("MCP auth context cleared after tool call");
            
            // Create tool result message
            ChatMessage toolResultMessage = ChatMessage.toolMessage(
                    result.isSuccess() ? result.getDataAsString() : result.getError()
            );
            toolResultMessage.setAuthorizationStatus(ChatMessage.AuthorizationStatus.AUTHORIZED);
            toolResultMessage.setToolCall(tc);
            
            // Get conversation history from session
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, toolResultMessage, ChatMessage.class);
            
            log.info("=== TOOL EXECUTION COMPLETED (AUTHORIZED) ===");
            log.info("Tool result: success={}, data={}", result.isSuccess(), 
                    result.isSuccess() ? result.getDataAsString() : result.getError());
            
            // Feed tool result back to LLM to generate final response
            log.info("=== SECOND LLM CALL: Feeding tool result back to LLM ===");
            List<ChatMessage> conversationHistory = SessionManager.getAttributeAsList(
                session, 
                SessionAttributes.CONVERSATION_HISTORY, 
                ChatMessage.class
            );
            List<Map<String, String>> llmMessages = convertMessagesToQwenFormat(conversationHistory);
            List<ToolDefinition> tools = toolAdapterManager.getAllTools();
            LLMChatResponse finalResponse = llmClient.chatWithTools(llmMessages, tools);
            
            log.info("=== SECOND LLM CALL: Final response received ===");
            ChatMessage finalMessage = ChatMessage.assistantMessage(finalResponse.getContent());
            // Note: finalMessage does NOT set toolCall, toolResult, or authorizationStatus
            // because it is just the LLM's final response, not the tool call itself
            // The tool call information is already captured in toolResultMessage
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, finalMessage, ChatMessage.class);

            // Clear authorization context after use
            agentAapExecutor.revokeWorkloadAndCleanup(workloadContext);
            SessionManager.removeAttribute(session, SessionAttributes.AGENT_OA_TOKEN);
            
            return finalMessage;
            
        } catch (FrameworkAuthorizationContextException e) {
            log.error("Failed to prepare authorization context", e);
            ChatMessage errorMessage = ChatMessage.assistantMessage("Failed to prepare authorization context: " + e.getMessage());
            
            // Get conversation history from session
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
            return errorMessage;
        } catch (Exception e) {
            log.error("Failed to execute tool with authorization", e);
            ChatMessage errorMessage = ChatMessage.assistantMessage("Sorry, tool call failed: " + e.getMessage());
            
            // Get conversation history from session
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
            return errorMessage;
        }
    }
    
    /**
     * Call tool directly without authorization.
     */
    private ChatMessage callToolDirectly(ToolCall toolCall, Map<String, Object> arguments, ChatMessage.ToolCall tc) {
        try {
            // Call tool
            ToolResult result = toolAdapterManager.callTool(
                    toolCall.getServerName(), 
                    toolCall.getToolName(), 
                    arguments
            );
            
            // Create tool result message
            ChatMessage toolResultMessage = ChatMessage.toolMessage(
                    result.isSuccess() ? result.getDataAsString() : result.getError()
            );
            
            // Get conversation history from session
            HttpSession session = getCurrentSession();
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, toolResultMessage, ChatMessage.class);
            
            log.info("=== TOOL EXECUTION COMPLETED ===");
            log.info("Tool result: success={}, data={}", result.isSuccess(), 
                    result.isSuccess() ? result.getDataAsString() : result.getError());
            
            // Feed tool result back to LLM to generate final response
            log.info("=== SECOND LLM CALL: Feeding tool result back to LLM ===");
            List<ChatMessage> conversationHistory = SessionManager.getAttributeAsList(
                session, 
                SessionAttributes.CONVERSATION_HISTORY, 
                ChatMessage.class
            );
            List<Map<String, String>> llmMessages = convertMessagesToQwenFormat(conversationHistory);
            List<ToolDefinition> tools = toolAdapterManager.getAllTools();
            LLMChatResponse finalResponse = llmClient.chatWithTools(llmMessages, tools);
            
            log.info("=== SECOND LLM CALL: Final response received ===");
            ChatMessage finalMessage = ChatMessage.assistantMessage(finalResponse.getContent());
            // Note: finalMessage does NOT set toolCall, toolResult, or authorizationStatus
            // because it is just the LLM's final response, not the tool call itself
            // The tool call information is already captured in toolResultMessage
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, finalMessage, ChatMessage.class);

            return finalMessage;
            
        } catch (Exception e) {
            log.error("Failed to execute tool call", e);
            ChatMessage errorMessage = ChatMessage.assistantMessage("Sorry, tool call failed: " + e.getMessage());
            
            // Get conversation history from session
            HttpSession session = getCurrentSession();
            SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
            return errorMessage;
        }
    }
    
    /**
     * Find tool definition by server name and tool name.
     */
    private ToolDefinition findToolDefinition(String serverName, String toolName) {
        List<ToolDefinition> tools = toolAdapterManager.getToolsByServer(serverName);
        return tools.stream()
                .filter(t -> t.getToolName().equals(toolName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Tool not found: " + serverName + "/" + toolName));
    }
    
    /**
     * Convert messages to Qwen format.
     * 
     * @param conversationHistory the conversation history to convert
     * @return list of Qwen-formatted messages
     */
    private List<Map<String, String>> convertMessagesToQwenFormat(List<ChatMessage> conversationHistory) {
        List<Map<String, String>> qwenMessages = new ArrayList<>();
        
        log.info("Converting {} messages to Qwen format", conversationHistory.size());
        
        for (ChatMessage message : conversationHistory) {
            // Skip authorization-related intermediate messages that should not be sent to LLM.
            // These messages (REQUIRED, INITIATED, DENIED, FAILED) are internal state transitions
            // of the authorization flow and would confuse the LLM if included in the prompt.
            ChatMessage.AuthorizationStatus authStatus = message.getAuthorizationStatus();
            if (authStatus != null && authStatus != ChatMessage.AuthorizationStatus.AUTHORIZED
                    && authStatus != ChatMessage.AuthorizationStatus.NOT_REQUIRED) {
                log.info("Skipping authorization intermediate message: role={}, status={}", 
                        message.getRole(), authStatus);
                continue;
            }
            
            Map<String, String> qwenMessage = new HashMap<>();
            qwenMessage.put("role", message.getRole());
            
            if ("assistant".equals(message.getRole()) && message.getToolCall() != null) {
                StringBuilder contentBuilder = new StringBuilder();
                if (!ValidationUtils.isNullOrEmpty(message.getContent())) {
                    contentBuilder.append(message.getContent());
                }
                qwenMessage.put("content", contentBuilder.toString());
                log.info("Converted assistant message with tool call: content={}", contentBuilder.toString());
            } else if ("tool".equals(message.getRole())) {
                String toolResult = message.getToolResult();
                if (!ValidationUtils.isNullOrEmpty(toolResult)) {
                    qwenMessage.put("content", toolResult);
                    log.info("Converted tool result message: content={}", toolResult);
                } else {
                    log.warn("Tool result message has empty toolResult field");
                }
            } else if (!ValidationUtils.isNullOrEmpty(message.getContent())) {
                qwenMessage.put("content", message.getContent());
                log.info("Converted {} message: content={}", message.getRole(), message.getContent());
            }
            
            if (qwenMessage.containsKey("content")) {
                qwenMessages.add(qwenMessage);
            } else {
                log.warn("Skipping message with no content: role={}", message.getRole());
            }
        }
        
        log.info("Final Qwen messages count: {}", qwenMessages.size());
        return qwenMessages;
    }
    
    /**
     * Extract text content from response.
     */
    private String extractTextContent(String content) {
        if (ValidationUtils.isNullOrEmpty(content)) {
            return "";
        }
        
        String result = content.replaceAll("<invoke>.*?</invoke>", "");
        result = result.trim();
        
        if (result.isEmpty()) {
            return "I'm processing your request.";
        }
        
        return result;
    }
    
    /**
     * Get conversation history.
     */
    public List<ChatMessage> getConversationHistory() {
        HttpSession session = getCurrentSession();
        List<ChatMessage> conversationHistory = SessionManager.getAttributeAsList(
            session, 
            SessionAttributes.CONVERSATION_HISTORY, 
            ChatMessage.class
        );
        return new ArrayList<>(conversationHistory);
    }
    
    /**
     * Extract the user's original natural-language input from conversation history.
     * <p>
     * This method searches through the conversation history to find the most recent
     * user message, which represents the user's original intent. This is critical for
     * the audit trail as per draft-liu-agent-operation-authorization-01 Section 4, Table 4.
     * </p>
     * <p>
     * The original input must be preserved and used in the auditTrail.originalPromptText
     * field to maintain intent provenance. System-generated descriptions (like tool names)
     * must NOT be used in place of the user's actual words.
     * </p>
     *
     * @return the user's original input, or null if not found
     */
    private String extractOriginalUserInputFromHistory() {
        HttpSession session = getCurrentSession();
        List<ChatMessage> conversationHistory = SessionManager.getAttributeAsList(
            session, 
            SessionAttributes.CONVERSATION_HISTORY, 
            ChatMessage.class
        );
        
        if (conversationHistory.isEmpty()) {
            log.warn("Conversation history is empty, cannot extract original user input");
            return null;
        }
        
        // Iterate backwards to find the most recent user message
        for (int i = conversationHistory.size() - 1; i >= 0; i--) {
            ChatMessage message = conversationHistory.get(i);
            if ("user".equals(message.getRole())) {
                String userContent = message.getContent();
                if (userContent != null && !userContent.isBlank()) {
                    log.info("Found original user input from history: {}", userContent);
                    return userContent;
                }
            }
        }
        
        log.warn("No user message found in conversation history");
        return null;
    }
    
    /**
     * Clear conversation history.
     */
    public void clearConversation() {
        HttpSession session = getCurrentSession();
        SessionManager.removeAttribute(session, SessionAttributes.CONVERSATION_HISTORY);
        log.info("Conversation history cleared");
    }
    
    /**
     * Resume pending tool request after OAuth callback.
     * This method is called automatically after user authentication to resume
     * the tool request that was interrupted by the authentication flow.
     * 
     * @return the result of processing the pending tool request
     */
    public ChatMessage resumePendingToolRequest() {
        HttpSession session = getCurrentSession();
        Map<String, Object> pendingToolRequest = SessionManager.getAttribute(session, SessionAttributes.PENDING_TOOL_REQUEST);
        
        if (pendingToolRequest == null) {
            log.info("No pending tool request found");
            return ChatMessage.assistantMessage("No pending tool request to resume.");
        }
        
        log.info("Resuming pending tool request after OAuth callback");
        
        // Remove pending request from session
        SessionManager.removeAttribute(session, SessionAttributes.PENDING_TOOL_REQUEST);
        
        try {
            // Resume tool call with authorization
            String serverName = (String) pendingToolRequest.get("serverName");
            String toolName = (String) pendingToolRequest.get("toolName");
            @SuppressWarnings("unchecked")
            Map<String, Object> arguments = (Map<String, Object>) pendingToolRequest.get("arguments");
            
            ChatMessage.ToolCall tc = new ChatMessage.ToolCall(serverName, toolName, 
                    new ObjectMapper().writeValueAsString(arguments));
            
            return callToolWithAuthorization(
                    new ToolCall(serverName, toolName, new ObjectMapper().writeValueAsString(arguments)),
                    arguments, tc);
        } catch (Exception e) {
            log.error("Failed to resume pending tool request", e);
            return ChatMessage.assistantMessage("Failed to resume pending tool request: " + e.getMessage());
        }
    }
    
    /**
     * Get current HTTP session.
     */
    private HttpSession getCurrentSession() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            throw new IllegalStateException("No current HTTP request");
        }
        return attributes.getRequest().getSession(true);
    }
    
    /**
     * Get all sessions sorted by creation time (newest first).
     * 
     * @return list of session information sorted by creation time
     */
    public List<SessionInfo> getAllSessions() {
        log.info("Retrieving all sessions, total count: {}", sessionListStore.size());
        return sessionListStore.values().stream()
                .sorted((s1, s2) -> {
                    if (s1.getCreatedAt() == null && s2.getCreatedAt() == null) return 0;
                    if (s1.getCreatedAt() == null) return 1;
                    if (s2.getCreatedAt() == null) return -1;
                    return s2.getCreatedAt().compareTo(s1.getCreatedAt());
                })
                .collect(java.util.stream.Collectors.toList());
    }
    
    /**
     * Delete a session.
     * 
     * @param sessionId the session ID to delete
     */
    public void deleteSession(String sessionId) {
        log.info("Deleting session: {}", sessionId);
        sessionListStore.remove(sessionId);
        log.info("Session deleted: {}", sessionId);
    }
    
    /**
     * Select a session and load its conversation history.
     * 
     * @param sessionId the session ID to select
     */
    public void selectSession(String sessionId) {
        log.info("Selecting session: {}", sessionId);
        
        SessionInfo targetSession = sessionListStore.get(sessionId);
        if (targetSession == null) {
            log.warn("Session not found: {}", sessionId);
            throw new IllegalArgumentException("Session not found: " + sessionId);
        }
        
        // Save current session's conversation history before switching
        HttpSession httpSession = getCurrentSession();
        if (currentSessionId != null && !currentSessionId.equals(sessionId)) {
            List<ChatMessage> currentHistory = SessionManager.getAttributeAsList(
                httpSession, 
                SessionAttributes.CONVERSATION_HISTORY, 
                ChatMessage.class
            );
            SessionInfo currentSession = sessionListStore.get(currentSessionId);
            if (currentSession != null && !currentHistory.isEmpty()) {
                currentSession.setConversationHistory(new ArrayList<>(currentHistory));
                log.info("Saved conversation history for session: {}", currentSessionId);
            }
        }
        
        // Load target session's conversation history
        List<ChatMessage> targetHistory = targetSession.getConversationHistory();
        if (targetHistory != null && !targetHistory.isEmpty()) {
            SessionManager.setAttribute(httpSession, SessionAttributes.CONVERSATION_HISTORY, targetHistory);
            log.info("Loaded conversation history for session: {} ({} messages)", sessionId, targetHistory.size());
        } else {
            clearConversation();
            log.info("Cleared conversation history for session: {} (no history)", sessionId);
        }
        
        // Update current session ID and active state
        currentSessionId = sessionId;
        sessionListStore.values().forEach(s -> s.setActive(false));
        targetSession.setActive(true);
        
        log.info("Session selected: {}", sessionId);
    }
    
    /**
     * Session information DTO.
     */
    public static class SessionInfo {
        private String id;
        private String title;
        private LocalDateTime createdAt;
        private boolean active;
        private List<ChatMessage> conversationHistory;
        
        public String getId() {
            return id;
        }
        
        public void setId(String id) {
            this.id = id;
        }
        
        public String getTitle() {
            return title;
        }
        
        public void setTitle(String title) {
            this.title = title;
        }
        
        public LocalDateTime getCreatedAt() {
            return createdAt;
        }
        
        public void setCreatedAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
        }
        
        public boolean isActive() {
            return active;
        }
        
        public void setActive(boolean active) {
            this.active = active;
        }
        
        public List<ChatMessage> getConversationHistory() {
            return conversationHistory;
        }
        
        public void setConversationHistory(List<ChatMessage> conversationHistory) {
            this.conversationHistory = conversationHistory;
        }
    }
}
