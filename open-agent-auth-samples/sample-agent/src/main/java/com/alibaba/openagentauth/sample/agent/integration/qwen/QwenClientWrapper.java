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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.integration.llm.LLMSession;
import com.alibaba.openagentauth.sample.agent.model.ToolDefinition;
import com.alibaba.qwen.code.cli.QwenCodeCli;
import com.alibaba.qwen.code.cli.protocol.data.AssistantContent;
import com.alibaba.qwen.code.cli.protocol.data.PermissionMode;
import com.alibaba.qwen.code.cli.session.Session;
import com.alibaba.qwen.code.cli.session.event.consumers.AssistantContentSimpleConsumers;
import com.alibaba.qwen.code.cli.transport.TransportOptions;
import com.alibaba.qwen.code.cli.utils.Timeout;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Qwen Client Wrapper
 * 
 * This implementation uses the real Qwen Code Java SDK (qwencode-sdk)
 * to interact with Qwen LLM for chat and tool calling capabilities.
 *
 * Implements the LLMClient interface to provide a consistent abstraction
 * for different LLM implementations.
 *
 * Note: This class is managed by AgentConfiguration via @ConditionalOnProperty,
 * not by @Component annotation.
 */
public class QwenClientWrapper implements LLMClient {
    
    private static final Logger log = LoggerFactory.getLogger(QwenClientWrapper.class);
    
    @Value("${qwen.model:qwen3-coder-flash}")
    private String model;
    
    @Value("${qwen.timeout:120}")
    private long timeoutSeconds;
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Create a new session
     * 
     * @return the created session
     */
    public LLMSession createSession() {
        log.info("Creating new Qwen session");
        
        try {
            // Create transport options
            TransportOptions options = new TransportOptions()
                    .setModel(model)
                    .setPermissionMode(PermissionMode.AUTO_EDIT)
                    .setCwd("./")
                    .setTurnTimeout(new Timeout(timeoutSeconds, TimeUnit.SECONDS))
                    .setMessageTimeout(new Timeout(timeoutSeconds, TimeUnit.SECONDS));
            
            // Create new session using Qwen SDK
            Session qwenSession = QwenCodeCli.newSession(options);
            
            log.info("New session created successfully");
            return new QwenSessionAdapter(qwenSession);
            
        } catch (Exception e) {
            log.error("Failed to create new session", e);
            throw new RuntimeException("Failed to create new Qwen session: " + e.getMessage(), e);
        }
    }

    /**
     * Chat conversation with tools
     * 
     * @param messages Chat message list
     * @param tools Tool definition list
     * @return AI response (may contain tool calls)
     */
    public LLMChatResponse chatWithTools(List<Map<String, String>> messages, List<ToolDefinition> tools) {
        log.info("Chatting with Qwen model with tools: {}, available tools: {}", model, tools.size());
        
        // Log tool definitions for debugging
        for (ToolDefinition tool : tools) {
            log.info("Tool definition - Name: {}, Description: {}, InputSchema: {}", 
                    tool.getToolName(), tool.getDescription(), tool.getInputSchema());
        }
        
        try {
            // Convert messages to prompt format with tool definitions
            String prompt = buildPromptWithToolDefinitions(messages, tools);
            log.info("Full prompt sent to model: {}", prompt);
            
            // Create transport options with allowed tools
            List<String> allowedToolNames = new ArrayList<>();
            for (ToolDefinition tool : tools) {
                allowedToolNames.add(tool.getToolName());
            }
            log.debug("Allowed tools: {}", allowedToolNames);
            
            TransportOptions options = new TransportOptions()
                    .setModel(model)
                    .setPermissionMode(PermissionMode.AUTO_EDIT)
                    .setCwd("./")
                    .setIncludePartialMessages(true)
                    .setCoreTools(allowedToolNames)
                    .setAllowedTools(allowedToolNames)
                    .setTurnTimeout(new Timeout(timeoutSeconds, TimeUnit.SECONDS))
                    .setMessageTimeout(new Timeout(timeoutSeconds, TimeUnit.SECONDS));
            
            // Create response holders
            AtomicBoolean needToolCall = new AtomicBoolean(false);
            AtomicReference<String> content = new AtomicReference<>();
            AtomicReference<ToolCall> toolCallRef = new AtomicReference<>();
            StringBuilder accumulatedText = new StringBuilder(); // Accumulate all text fragments
            
            // Create content consumer
            AssistantContentSimpleConsumers consumers = new AssistantContentSimpleConsumers() {

                @Override
                public void onText(Session session, AssistantContent.TextAssistantContent textAssistantContent) {
                    String text = textAssistantContent.getText();

                    // Sanitize text to remove control characters that can cause display issues
                    String sanitizedText = sanitizeTextContent(text);

                    // Accumulate text fragments
                    accumulatedText.append(sanitizedText);
                }
                
                @Override
                public void onToolUse(Session session, AssistantContent.ToolUseAssistantContent toolUseContent) {
                    Map<String, Object> input = toolUseContent.getInput();
                    log.info("Received tool use input: {}", input);
                    
                    needToolCall.set(true);
                    String currentContent = content.get();
                    content.set(currentContent != null ? currentContent : "I need to use a tool.");
                    
                    // Extract tool call information from input map
                    String toolName = "unknown";
                    String arguments = "{}";
                    
                    if (input != null) {
                        // Try to extract tool name from input map
                        Object nameObj = input.get("name");
                        if (nameObj != null) {
                            toolName = nameObj.toString();
                        }
                        
                        // Try to extract arguments from input map
                        Object argsObj = input.get("arguments");
                        if (argsObj != null) {
                            arguments = argsObj.toString();
                        } else {
                            arguments = input.toString();
                        }
                    }
                    
                    // Map tool name to server name (simplified approach)
                    String serverName = "default";
                    for (ToolDefinition tool : tools) {
                        if (tool.getToolName().equals(toolName)) {
                            serverName = tool.getServerName();
                            break;
                        }
                    }
                    
                    toolCallRef.set(new ToolCall(serverName, toolName, arguments));
                }
                
                @Override
                public void onToolResult(Session session, AssistantContent.ToolResultAssistantContent toolResultContent) {
                    String content = sanitizeTextContent(toolResultContent.getContent());
                    log.info("Received tool result: {}", content);
                }
            };
            
            // Call Qwen SDK with custom content consumer
            QwenCodeCli.simpleQuery(prompt, options, consumers);
            
            // After stream completes, try to extract tool call from accumulated text
            String fullText = accumulatedText.toString();
            log.info("Full accumulated text: {}", fullText);
            
            // Try to parse tool call from accumulated text
            String toolCallText = extractToolCallFromText(fullText);
            if (toolCallText != null) {
                log.info("Found tool call in accumulated text: {}", toolCallText);
                
                try {
                    // Parse JSON string
                    Map toolCall = objectMapper.readValue(toolCallText, Map.class);
                    String toolName = (String) toolCall.get("name");
                    String arguments = objectMapper.writeValueAsString(toolCall.get("arguments"));
                    
                    needToolCall.set(true);
                    
                    // Extract text content before the tool call
                    String textContent = extractTextBeforeToolCall(fullText);
                    content.set(textContent.trim());
                    
                    // Map tool name to server name
                    String serverName = "default";
                    for (ToolDefinition tool : tools) {
                        if (tool.getToolName().equals(toolName)) {
                            serverName = tool.getServerName();
                            break;
                        }
                    }
                    
                    toolCallRef.set(new ToolCall(serverName, toolName, arguments));
                } catch (Exception e) {
                    log.error("Failed to parse tool call from accumulated text", e);
                    content.set(fullText);
                }
            } else {
                // No tool call found, use the full text as content
                content.set(fullText);
            }
            
            // Build response using LLMClient interface types
            LLMChatResponse response = new LLMChatResponse();
            response.setNeedToolCall(needToolCall.get());
            
            // Final sanitization pass on the content to catch any remaining ChatML tokens.
            // Even though onText already sanitizes each fragment, the model may produce
            // tokens that span across multiple text fragments or appear in edge cases.
            // Trim the final output since sanitizeTextContent preserves internal whitespace
            // for correct fragment accumulation.
            String finalContent = sanitizeTextContent(content.get());
            if (finalContent != null) {
                finalContent = finalContent.trim();
            }
            if (ValidationUtils.isNullOrEmpty(finalContent)) {
                if (needToolCall.get()) {
                    log.warn("Tool result was fed to LLM but no response content was received");
                    finalContent = "I've processed the tool results. Please check the tool output for details.";
                } else {
                    finalContent = "I'm processing your request.";
                }
            }
            response.setContent(finalContent);

            // Set tool call if present
            if (toolCallRef.get() != null) {
                response.setToolCall(toolCallRef.get());
            }
            
            log.info("Response: needToolCall={}, content={}, toolCall={}", 
                    needToolCall.get(), finalContent, toolCallRef.get());
            
            return response;
            
        } catch (Exception e) {
            log.error("Failed to chat with Qwen model with tools", e);
            
            LLMChatResponse response = new LLMChatResponse();
            response.setNeedToolCall(false);
            response.setContent("Sorry, I encountered an error while processing your request: " + e.getMessage());
            return response;
        }
    }

    /**
     * Build prompt with tool definitions using Qwen3 standard ChatML format
     * 
     * This method constructs a comprehensive prompt that includes:
     * - Detailed system message with role definition and tool usage guidelines
     * - Structured tool definitions with enhanced descriptions
     * - Few-shot examples for better tool calling accuracy
     * - Clear instructions for tool call format and error handling
     * 
     * @param messages Message list
     * @param tools Tool definition list
     * @return Formatted prompt with tool definitions in Qwen3 format
     */
    private String buildPromptWithToolDefinitions(List<Map<String, String>> messages, List<ToolDefinition> tools) {
        StringBuilder prompt = new StringBuilder();
        
        // Build system message using plain-text role markers.
        // IMPORTANT: Do NOT use ChatML special tokens (<|im_start|>, <|im_end|>, </s>) here.
        // The Qwen Code SDK (QwenCodeCli.simpleQuery) internally wraps the prompt with
        // ChatML delimiters. Adding them manually causes double-wrapping, which makes the
        // model leak tokens like "<|im_end|>" or "<|im_start|>user" into generated text.
        prompt.append("[SYSTEM]\n");
        
        // === Optimized System Prompt ===
        prompt.append("You are an intelligent AI assistant that can use tools to complete tasks.\n\n");
        
        prompt.append("## Core Principles\n");
        prompt.append("1. **Analyze before acting**: Carefully understand the user's intent before deciding whether to call a tool\n");
        prompt.append("2. **Use tools when necessary**: Only call tools when they are needed to fulfill the user's request\n");
        prompt.append("3. **Validate parameters**: Ensure all required parameters are present and valid before calling a tool\n");
        prompt.append("4. **Handle errors gracefully**: If a tool call fails, explain the error and suggest alternatives\n");
        prompt.append("5. **Be helpful and clear**: Provide clear, actionable responses to the user\n\n");
        
        prompt.append("## Tool Call Protocol\n");
        prompt.append("When you need to use a tool, follow these rules:\n\n");
        
        prompt.append("### When to Call a Tool\n");
        prompt.append("- Call a tool when the user's request requires data or actions that cannot be answered from general knowledge\n");
        prompt.append("- Examples: searching products, processing purchases, querying orders, etc.\n");
        prompt.append("- DO NOT call a tool if you can answer from your training data\n\n");
        
        prompt.append("### Tool Call Format\n");
        prompt.append("Output the tool call in the following JSON format:\n");
        prompt.append("```json\n");
        prompt.append("{\n");
        prompt.append("  \"name\": \"exact_tool_name\",\n");
        prompt.append("  \"arguments\": {\n");
        prompt.append("    \"parameter1\": \"value1\",\n");
        prompt.append("    \"parameter2\": \"value2\"\n");
        prompt.append("  }\n");
        prompt.append("}\n");
        prompt.append("```\n\n");
        
        prompt.append("### Critical Rules\n");
        prompt.append("1. **Output ONLY the JSON** when calling a tool - no explanatory text before or after\n");
        prompt.append("2. **Use exact tool names** - match the name exactly as defined in the tool list below\n");
        prompt.append("3. **Provide all required parameters** - missing required parameters will cause the tool call to fail\n");
        prompt.append("4. **Validate parameter values** - ensure values match the expected types and formats\n");
        prompt.append("5. **Ask for clarification** if the user's request is ambiguous or missing required information\n");
        prompt.append("6. **Handle tool results** - after receiving tool results, provide a helpful summary to the user\n\n");
        
        prompt.append("### Tool Call Examples\n");
        prompt.append("**Correct Tool Call:**\n");
        prompt.append("User: Search for iPhone 15\n");
        prompt.append("Assistant: ```json\n");
        prompt.append("{\n");
        prompt.append("  \"name\": \"search_products\",\n");
        prompt.append("  \"arguments\": {\n");
        prompt.append("    \"keywords\": \"iPhone 15\"\n");
        prompt.append("  }\n");
        prompt.append("}\n");
        prompt.append("```\n\n");
        
        prompt.append("**Incorrect Tool Call (has extra text):**\n");
        prompt.append("Assistant: I'll search for iPhone 15 for you.\n");
        prompt.append("```json\n");
        prompt.append("{\n");
        prompt.append("  \"name\": \"search_products\",\n");
        prompt.append("  \"arguments\": {...}\n");
        prompt.append("}\n");
        prompt.append("```\n");
        prompt.append("❌ WRONG - Do not include text before the JSON\n\n");
        
        prompt.append("**Asking for Clarification:**\n");
        prompt.append("User: I want to buy something\n");
        prompt.append("Assistant: I'd be happy to help you make a purchase! To proceed, I need to know:\n");
        prompt.append("- Which product would you like to buy? (product ID or name)\n");
        prompt.append("- How many units would you like to purchase?\n\n");
        prompt.append("Could you please provide these details?\n\n");
        
        // === Tool Definitions ===
        prompt.append("## Available Tools\n\n");
        for (ToolDefinition tool : tools) {
            prompt.append("### Tool: `").append(tool.getToolName()).append("`\n\n");
            
            if (tool.getDescription() != null) {
                prompt.append("**Description:** ").append(tool.getDescription()).append("\n\n");
            }
            
            if (tool.getInputSchema() != null) {
                prompt.append("**Parameters:**\n");
                prompt.append("```json\n");
                prompt.append(tool.getInputSchema()).append("\n");
                prompt.append("```\n\n");
            }
            
            prompt.append("---\n\n");
        }
        
        // === End System Message ===
        prompt.append("[/SYSTEM]\n\n");
        
        // Append conversation history using plain-text role markers
        for (Map<String, String> message : messages) {
            String role = message.get("role");
            String content = message.get("content");
            
            if (!ValidationUtils.isNullOrEmpty(content)) {
                if ("user".equals(role)) {
                    prompt.append("[USER]\n").append(content).append("\n[/USER]\n\n");
                } else if ("assistant".equals(role)) {
                    prompt.append("[ASSISTANT]\n").append(content).append("\n[/ASSISTANT]\n\n");
                } else if ("tool".equals(role)) {
                    prompt.append("[TOOL_RESULT]\n").append(content).append("\n[/TOOL_RESULT]\n\n");
                }
            }
        }
        
        prompt.append("[ASSISTANT]\n");
        return prompt.toString();
    }
    
    /**
     * Extract tool call from text content
     * Supports both ```json``` format and plain JSON format
     *
     * @param text Text content
     * @return Tool call JSON string, or null if not found
     */
    private String extractToolCallFromText(String text) {
        // First sanitize the text
        String sanitizedText = sanitizeTextContent(text);

        // Try to extract JSON from ```json``` code block first
        int jsonStart = sanitizedText.indexOf("```json");
        if (jsonStart != -1) {
            int jsonEnd = sanitizedText.indexOf("```", jsonStart + 7);
            if (jsonEnd != -1) {
                String jsonContent = sanitizedText.substring(jsonStart + 7, jsonEnd).trim();
                log.info("Extracted tool call from ```json``` block: {}", jsonContent);
                return jsonContent;
            }
        }

        // Try to extract plain JSON object
        int objStart = sanitizedText.indexOf("{");
        int objEnd = sanitizedText.lastIndexOf("}");

        if (objStart != -1 && objEnd != -1 && objEnd > objStart) {
            String jsonContent = sanitizedText.substring(objStart, objEnd + 1).trim();
            // Verify it's a valid JSON object with "name" and "arguments" fields
            try {
                Map<String, Object> parsed = objectMapper.readValue(jsonContent, Map.class);
                if (parsed.containsKey("name") && parsed.containsKey("arguments")) {
                    log.info("Extracted tool call from plain JSON: {}", jsonContent);
                    return jsonContent;
                }
            } catch (Exception e) {
                // Not a valid JSON, continue
            }
        }

        log.info("No tool call found in text");
        return null;
    }
    
    /**
     * Sanitize text content to remove problematic control characters
     *
     * @param text the input text to sanitize
     * @return sanitized text with control characters removed
     */
    private String sanitizeTextContent(String text) {
        if (text == null) {
            return null;
        }

        // Remove ChatML special tokens that may leak from the model output.
        // The Qwen Code SDK wraps prompts with ChatML internally, and the model
        // sometimes echoes these tokens back in its generated text.
        String cleaned = text
                .replace("<|im_start|>", "")
                .replace("<|im_end|>", "")
                .replace("</s>", "");

        // Remove residual role markers that may appear after stripping ChatML tokens
        // e.g., after removing "<|im_start|>" the text may contain bare "user", "assistant", "system"
        // at line boundaries that are artifacts, not real content
        cleaned = cleaned.replaceAll("(?m)^(user|assistant|system)\\s*$", "");

        // Remove control characters that might cause display issues
        cleaned = cleaned.replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "")
                .replace("\u2028", "")  // Line separator
                .replace("\u2029", ""); // Paragraph separator

        // Do NOT trim here — streaming text fragments may have meaningful leading/trailing
        // whitespace (e.g., "Once upon a time, " + "there was..."). Trimming is done at
        // the final output stage in chatWithTools() instead.
        return cleaned;
    }

    /**
     * Extract text content before the tool call
     *
     * @param text Full text content
     * @return Text content before tool call
     */
    private String extractTextBeforeToolCall(String text) {
        // First sanitize the text
        String sanitizedText = sanitizeTextContent(text);

        // Find the JSON code block or JSON object
        int jsonStart = sanitizedText.indexOf("```json");
        if (jsonStart != -1) {
            return sanitizedText.substring(0, jsonStart).trim();
        }

        int objStart = sanitizedText.indexOf("{");
        if (objStart != -1) {
            return sanitizedText.substring(0, objStart).trim();
        }

        return sanitizedText;
    }
    
    /**
     * Format input schema as JSON using Jackson ObjectMapper
     * 
     * @param inputSchema Input schema
     * @return Formatted JSON string
     */
    private String formatInputSchemaAsJson(Map<String, Object> inputSchema) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            // Pretty print with 6 spaces indentation to match the prompt format
            return objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(inputSchema)
                    .replace("\n", "\n      ")
                    .replace("  ", "      ");
        } catch (Exception e) {
            log.error("Failed to format input schema as JSON", e);
            // Fallback to simple format
            return "        \"type\": \"object\",\n        \"properties\": {}";
        }
    }
}