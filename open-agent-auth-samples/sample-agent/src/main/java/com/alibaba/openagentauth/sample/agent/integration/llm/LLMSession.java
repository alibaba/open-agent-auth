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

/**
 * LLM Session Interface
 * 
 * Abstract representation of an LLM conversation session.
 * This interface decouples the application from specific LLM implementations
 * (e.g., Qwen, OpenAI, etc.) following the Dependency Inversion Principle.
 * 
 * <p><b>Design Pattern:</b> Strategy Pattern + Dependency Inversion Principle</p>
 * 
 * <p><b>Key Characteristics:</b></p>
 * <ul>
 *   <li><b>Abstraction:</b> Provides a minimal interface for session management</li>
 *   <li><b>Decoupling:</b> Application code depends on this interface, not concrete implementations</li>
 *   <li><b>Extensibility:</b> New LLM providers can be added by implementing this interface</li>
 * </ul>
 * 
 * <p><b>Implementations:</b></p>
 * <ul>
 *   <li>{@code QwenSessionAdapter} - Wraps Qwen SDK's Session</li>
 *   <li>{@code MockLLMSession} - Mock implementation for testing</li>
 * </ul>
 * 
 * @since 1.0
 */
public interface LLMSession {
    
    /**
     * Gets the unique session identifier.
     * 
     * @return the session ID, never null
     */
    String getSessionId();

}
