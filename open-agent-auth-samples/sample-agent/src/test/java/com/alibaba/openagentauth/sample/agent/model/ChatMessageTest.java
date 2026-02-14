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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for ChatMessage model.
 */
@DisplayName("ChatMessage Model Tests")
class ChatMessageTest {

    @Test
    @DisplayName("Should create user message with factory method")
    void shouldCreateUserMessageWithFactoryMethod() {
        ChatMessage message = ChatMessage.userMessage("Hello");
        
        assertEquals(ChatMessage.ROLE_USER, message.getRole());
        assertEquals("Hello", message.getContent());
        assertNotNull(message.getTimestamp());
    }

    @Test
    @DisplayName("Should create assistant message with factory method")
    void shouldCreateAssistantMessageWithFactoryMethod() {
        ChatMessage message = ChatMessage.assistantMessage("Hi there");
        
        assertEquals(ChatMessage.ROLE_ASSISTANT, message.getRole());
        assertEquals("Hi there", message.getContent());
        assertNotNull(message.getTimestamp());
    }

    @Test
    @DisplayName("Should create tool message with factory method")
    void shouldCreateToolMessageWithFactoryMethod() {
        ChatMessage message = ChatMessage.toolMessage("Tool executed successfully");
        
        assertEquals(ChatMessage.ROLE_TOOL, message.getRole());
        assertEquals("Tool executed successfully", message.getToolResult());
        assertNotNull(message.getTimestamp());
    }

    @Test
    @DisplayName("Should set and get role")
    void shouldSetAndGetRole() {
        ChatMessage message = new ChatMessage();
        message.setRole(ChatMessage.ROLE_SYSTEM);
        
        assertEquals(ChatMessage.ROLE_SYSTEM, message.getRole());
    }

    @Test
    @DisplayName("Should set and get content")
    void shouldSetAndGetContent() {
        ChatMessage message = new ChatMessage();
        message.setContent("Test content");
        
        assertEquals("Test content", message.getContent());
    }

    @Test
    @DisplayName("Should set and get tool call")
    void shouldSetAndGetToolCall() {
        ChatMessage message = new ChatMessage();
        ChatMessage.ToolCall toolCall = new ChatMessage.ToolCall("server", "tool", "{}");
        message.setToolCall(toolCall);
        
        assertEquals(toolCall, message.getToolCall());
    }

    @Test
    @DisplayName("Should set and get tool result")
    void shouldSetAndGetToolResult() {
        ChatMessage message = new ChatMessage();
        message.setToolResult("Result");
        
        assertEquals("Result", message.getToolResult());
    }

    @Test
    @DisplayName("Should set and get authorization status")
    void shouldSetAndGetAuthorizationStatus() {
        ChatMessage message = new ChatMessage();
        message.setAuthorizationStatus(ChatMessage.AuthorizationStatus.AUTHORIZED);
        
        assertEquals(ChatMessage.AuthorizationStatus.AUTHORIZED, message.getAuthorizationStatus());
    }

    @Test
    @DisplayName("Should set and get authorization URL")
    void shouldSetAndGetAuthorizationUrl() {
        ChatMessage message = new ChatMessage();
        message.setAuthorizationUrl("https://example.com/auth");
        
        assertEquals("https://example.com/auth", message.getAuthorizationUrl());
    }

    @Test
    @DisplayName("Should set and get timestamp")
    void shouldSetAndGetTimestamp() {
        LocalDateTime now = LocalDateTime.now();
        ChatMessage message = new ChatMessage();
        message.setTimestamp(now);
        
        assertEquals(now, message.getTimestamp());
    }

    @Test
    @DisplayName("ToolCall should set all fields")
    void toolCallShouldSetAllFields() {
        ChatMessage.ToolCall toolCall = new ChatMessage.ToolCall();
        toolCall.setServerName("test-server");
        toolCall.setToolName("test-tool");
        toolCall.setArguments("{\"key\":\"value\"}");
        
        assertEquals("test-server", toolCall.getServerName());
        assertEquals("test-tool", toolCall.getToolName());
        assertEquals("{\"key\":\"value\"}", toolCall.getArguments());
    }

    @Test
    @DisplayName("ToolCall constructor should initialize all fields")
    void toolCallConstructorShouldInitializeAllFields() {
        ChatMessage.ToolCall toolCall = new ChatMessage.ToolCall("server", "tool", "args");
        
        assertEquals("server", toolCall.getServerName());
        assertEquals("tool", toolCall.getToolName());
        assertEquals("args", toolCall.getArguments());
    }

    @Test
    @DisplayName("AuthorizationStatus enum should have all values")
    void authorizationStatusEnumShouldHaveAllValues() {
        ChatMessage.AuthorizationStatus[] statuses = ChatMessage.AuthorizationStatus.values();
        
        assertEquals(6, statuses.length);
        assertTrue(java.util.Arrays.asList(statuses).contains(ChatMessage.AuthorizationStatus.NOT_REQUIRED));
        assertTrue(java.util.Arrays.asList(statuses).contains(ChatMessage.AuthorizationStatus.REQUIRED));
        assertTrue(java.util.Arrays.asList(statuses).contains(ChatMessage.AuthorizationStatus.INITIATED));
        assertTrue(java.util.Arrays.asList(statuses).contains(ChatMessage.AuthorizationStatus.AUTHORIZED));
        assertTrue(java.util.Arrays.asList(statuses).contains(ChatMessage.AuthorizationStatus.DENIED));
        assertTrue(java.util.Arrays.asList(statuses).contains(ChatMessage.AuthorizationStatus.FAILED));
    }

    @Test
    @DisplayName("Constructor with role and content should set timestamp")
    void constructorWithRoleAndContentShouldSetTimestamp() {
        ChatMessage message = new ChatMessage(ChatMessage.ROLE_USER, "test");
        
        assertNotNull(message.getTimestamp());
        assertEquals(ChatMessage.ROLE_USER, message.getRole());
        assertEquals("test", message.getContent());
    }

    @Test
    @DisplayName("Default constructor should set timestamp")
    void defaultConstructorShouldSetTimestamp() {
        ChatMessage message = new ChatMessage();
        
        assertNotNull(message.getTimestamp());
    }
}
