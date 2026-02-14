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
package com.alibaba.openagentauth.sample.agent.config;

import com.alibaba.openagentauth.sample.agent.integration.llm.LLMClient;
import com.alibaba.openagentauth.sample.agent.integration.llm.mock.MockConfig;
import com.alibaba.openagentauth.sample.agent.integration.llm.mock.MockLLMClientWrapper;
import com.alibaba.openagentauth.sample.agent.integration.qwen.QwenClientWrapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for AgentConfiguration.
 *
 * <p>This test class verifies the bean configuration and dependency injection
 * correctness in AgentConfiguration class without loading Spring context.</p>
 *
 * @since 1.0
 */
@DisplayName("AgentConfiguration Tests")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AgentConfigurationTest {

    private AgentConfiguration agentConfiguration;

    @BeforeEach
    void setUp() {
        agentConfiguration = new AgentConfiguration();
    }

    @Test
    @DisplayName("Should create QwenClientWrapper bean when mock is disabled")
    void shouldCreateQwenClientWrapperBeanWhenMockDisabled() {
        LLMClient client = agentConfiguration.qwenLLMClient("qwen3-coder-flash", 120);

        assertNotNull(client, "QwenClientWrapper bean should not be null");
        assertTrue(client instanceof QwenClientWrapper,
            "LLMClient should be instance of QwenClientWrapper when mock is disabled");
    }

    @Test
    @DisplayName("Should create MockConfig bean when mock is enabled")
    void shouldCreateMockConfigBeanWhenMockEnabled() {
        MockConfig config = agentConfiguration.mockConfig();

        assertNotNull(config, "MockConfig bean should not be null");
    }

    @Test
    @DisplayName("Should create MockLLMClient bean when mock is enabled")
    void shouldCreateMockLLMClientBeanWhenMockEnabled() {
        MockConfig mockConfig = agentConfiguration.mockConfig();
        LLMClient client = agentConfiguration.mockLLMClient(mockConfig);

        assertNotNull(client, "MockLLMClient bean should not be null");
        assertTrue(client instanceof MockLLMClientWrapper,
            "LLMClient should be instance of MockLLMClientWrapper when mock is enabled");
    }

    @Test
    @DisplayName("Should verify bean configuration correctness")
    void shouldVerifyBeanConfigurationCorrectness() {
        // Verify all critical beans can be created
        assertDoesNotThrow(() -> {
            agentConfiguration.qwenLLMClient("qwen3-coder-flash", 120);
            agentConfiguration.mockConfig();
        }, "All bean creation methods should execute without exceptions");
    }
}