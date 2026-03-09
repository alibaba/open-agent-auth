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
package com.alibaba.openagentauth.sample.authz.config;

import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;
import com.alibaba.openagentauth.sample.authz.renderer.QwenLlmOperationTextRenderer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link LlmRendererConfiguration}.
 * <p>
 * Verifies that the configuration correctly creates an {@link OperationTextRenderer} bean
 * with the expected model name and timeout parameters.
 * </p>
 */
@DisplayName("LlmRendererConfiguration Tests")
class LlmRendererConfigurationTest {

    @Test
    @DisplayName("Should create OperationTextRenderer with default model and timeout")
    void shouldCreateOperationTextRendererWithDefaults() {
        LlmRendererConfiguration configuration = new LlmRendererConfiguration();

        OperationTextRenderer renderer = configuration.operationTextRenderer(
                "qwen3-coder-flash", 120);

        assertThat(renderer).isNotNull();
        assertThat(renderer).isInstanceOf(QwenLlmOperationTextRenderer.class);
    }

    @Test
    @DisplayName("Should create OperationTextRenderer with custom model name")
    void shouldCreateOperationTextRendererWithCustomModel() {
        LlmRendererConfiguration configuration = new LlmRendererConfiguration();

        OperationTextRenderer renderer = configuration.operationTextRenderer(
                "qwen-plus", 60);

        assertThat(renderer).isNotNull();
        assertThat(renderer).isInstanceOf(QwenLlmOperationTextRenderer.class);
    }

    @Test
    @DisplayName("Should create OperationTextRenderer with custom timeout")
    void shouldCreateOperationTextRendererWithCustomTimeout() {
        LlmRendererConfiguration configuration = new LlmRendererConfiguration();

        OperationTextRenderer renderer = configuration.operationTextRenderer(
                "qwen3-coder-flash", 300);

        assertThat(renderer).isNotNull();
        assertThat(renderer).isInstanceOf(QwenLlmOperationTextRenderer.class);
    }
}
