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

import com.alibaba.openagentauth.sample.agent.integration.llm.LLMSession;
import com.alibaba.qwen.code.cli.session.Session;

/**
 * Adapter for Qwen SDK Session to LLMSession interface.
 * 
 * This class implements the Adapter Pattern to bridge Qwen's concrete Session
 * implementation with our abstract LLMSession interface. This allows the
 * application to work with the abstraction while using Qwen as the underlying
 * implementation.
 * 
 * <p><b>Design Pattern:</b> Adapter Pattern</p>
 * 
 * <p><b>Key Characteristics:</b></p>
 * <ul>
 *   <li><b>Wrapper:</b> Wraps Qwen's Session instance</li>
 *   <li><b>Delegation:</b> Delegates getSessionId() to the wrapped Session</li>
 *   <li><b>Immutability:</b> The wrapped Session cannot be changed after construction</li>
 * </ul>
 * 
 * @since 1.0
 */
public class QwenSessionAdapter implements LLMSession {
    
    private final Session qwenSession;
    
    /**
     * Creates a new adapter wrapping the Qwen Session.
     * 
     * @param qwenSession the Qwen Session to wrap, must not be null
     * @throws NullPointerException if qwenSession is null
     */
    public QwenSessionAdapter(Session qwenSession) {
        this.qwenSession = java.util.Objects.requireNonNull(qwenSession, "Qwen Session must not be null");
    }
    
    @Override
    public String getSessionId() {
        return qwenSession.getSessionId();
    }
    
    /**
     * Gets the underlying Qwen Session.
     * This method is provided for internal use by QwenClientWrapper.
     * 
     * @return the wrapped Qwen Session
     */
    Session getQwenSession() {
        return qwenSession;
    }
}
