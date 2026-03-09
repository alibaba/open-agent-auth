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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for the LLM-based operation text renderer in the sample Authorization Server.
 * <p>
 * This configuration registers a {@link QwenLlmOperationTextRenderer} bean that uses
 * Alibaba Cloud's Qwen model via qwencode-sdk to generate human-readable operation
 * descriptions. It overrides the default {@code PatternBasedOperationTextRenderer}
 * provided by the framework's auto-configuration.
 * </p>
 * <p>
 * The SDK usage is consistent with the sample-agent's {@code QwenClientWrapper},
 * using the same qwencode-sdk dependency and similar configuration patterns
 * (model name, timeout).
 * </p>
 * <p>
 * The renderer is conditionally enabled via the {@code sample.llm-renderer.enabled} property.
 * When disabled, the framework falls back to the default pattern-based renderer.
 * </p>
 *
 * @since 1.0
 */
@Configuration
@ConditionalOnProperty(name = "sample.llm-renderer.enabled", havingValue = "true")
public class LlmRendererConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(LlmRendererConfiguration.class);

    /**
     * Creates a Qwen LLM-based operation text renderer.
     * <p>
     * The model name defaults to {@code qwen3-coder-flash} (consistent with sample-agent)
     * but can be overridden via {@code sample.llm-renderer.model}.
     * The timeout defaults to 120 seconds but can be overridden via
     * {@code sample.llm-renderer.timeout}.
     * </p>
     *
     * @param modelName the Qwen model name
     * @param timeoutSeconds the timeout in seconds for LLM calls
     * @return a configured QwenLlmOperationTextRenderer instance
     */
    @Bean
    public OperationTextRenderer operationTextRenderer(
            @Value("${sample.llm-renderer.model:qwen3-coder-flash}") String modelName,
            @Value("${sample.llm-renderer.timeout:120}") long timeoutSeconds) {

        logger.info("Creating QwenLlmOperationTextRenderer with model: {}, timeout: {}s",
                modelName, timeoutSeconds);
        return new QwenLlmOperationTextRenderer(modelName, timeoutSeconds);
    }
}
