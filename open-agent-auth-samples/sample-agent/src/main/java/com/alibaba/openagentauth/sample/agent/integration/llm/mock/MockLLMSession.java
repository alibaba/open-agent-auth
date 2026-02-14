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

import com.alibaba.openagentauth.sample.agent.integration.llm.LLMSession;

/**
 * Mock implementation of LLMSession for testing purposes.
 * 
 * This class provides a lightweight mock session that does not require
 * any external LLM dependencies. It's useful for:
 * <ul>
 *   <li>Unit testing without LLM backend</li>
 *   <li>Integration testing with predictable behavior</li>
 *   <li>Development and demonstration scenarios</li>
 * </ul>
 * 
 * <p><b>Design Pattern:</b> Mock Object Pattern + Null Object Pattern</p>
 * 
 * <p><b>Key Characteristics:</b></p>
 * <ul>
 *   <li><b>Lightweight:</b> No external dependencies</li>
 *   <li><b>Immutable:</b> Session ID cannot be changed after construction</li>
 *   <li><b>Simple:</b> Minimal implementation focused on testing needs</li>
 * </ul>
 * 
 * @since 1.0
 */
public class MockLLMSession implements LLMSession {
    
    private final String sessionId;
    
    /**
     * Creates a new mock session with a generated ID.
     * The ID is generated using a UUID to ensure uniqueness.
     */
    public MockLLMSession() {
        this.sessionId = "mock-session-" + java.util.UUID.randomUUID().toString();
    }
    
    /**
     * Creates a new mock session with a specific ID.
     * This constructor is useful for testing when you need predictable session IDs.
     * 
     * @param sessionId the session ID to use, must not be null
     * @throws NullPointerException if sessionId is null
     */
    public MockLLMSession(String sessionId) {
        this.sessionId = java.util.Objects.requireNonNull(sessionId, "Session ID must not be null");
    }
    
    @Override
    public String getSessionId() {
        return sessionId;
    }

}
