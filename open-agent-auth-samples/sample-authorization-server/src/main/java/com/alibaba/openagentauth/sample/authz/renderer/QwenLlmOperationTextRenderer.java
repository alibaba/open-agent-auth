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
package com.alibaba.openagentauth.sample.authz.renderer;

import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderContext;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;
import com.alibaba.openagentauth.core.audit.model.SemanticExpansionLevel;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.qwen.code.cli.QwenCodeCli;
import com.alibaba.qwen.code.cli.protocol.data.AssistantContent;
import com.alibaba.qwen.code.cli.protocol.data.PermissionMode;
import com.alibaba.qwen.code.cli.session.Session;
import com.alibaba.qwen.code.cli.session.event.consumers.AssistantContentSimpleConsumers;
import com.alibaba.qwen.code.cli.transport.TransportOptions;
import com.alibaba.qwen.code.cli.utils.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * LLM-based implementation of {@link OperationTextRenderer} using Alibaba Cloud's Qwen model
 * via the qwencode-sdk.
 * <p>
 * This renderer leverages the Qwen large language model to intelligently interpret Rego policies
 * and generate natural-language descriptions of authorized operations. Compared to the
 * {@link com.alibaba.openagentauth.core.audit.impl.PatternBasedOperationTextRenderer},
 * this implementation produces more natural, context-aware, and user-friendly descriptions.
 * </p>
 * <p>
 * The SDK usage is consistent with the sample-agent's {@code QwenClientWrapper}, using
 * {@link QwenCodeCli#simpleQuery(String, TransportOptions, AssistantContentSimpleConsumers)}
 * for LLM interaction.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization-01 Section 4, the rendered text serves
 * the Semantic Audit Trail by documenting how the system interpreted the user's input into
 * a concrete operation description.
 * </p>
 *
 * @see OperationTextRenderer
 * @since 1.0
 */
public class QwenLlmOperationTextRenderer implements OperationTextRenderer {

    private static final Logger logger = LoggerFactory.getLogger(QwenLlmOperationTextRenderer.class);

    private static final String SYSTEM_INSTRUCTION = """
            You are an authorization consent page assistant. Translate a machine-readable Rego policy \
            into a concise, scannable explanation for a non-technical user.
            
            Output MUST use this exact structure:
            
            What this authorizes: [ONE sentence. State the action, the target resource, and any scope \
            in a single concise sentence. Do NOT repeat or paraphrase the same information twice.]
            
            Key constraints: [Bullet each REAL constraint from the policy, prefixed with "- ". \
            Only list limits that ARE explicitly present (e.g., spending caps, time windows, category \
            restrictions, rate limits, geographic bounds). NEVER list the absence of a constraint \
            (e.g., do NOT write "No spending cap is set"). If no constraints exist beyond what is \
            already stated above, omit this section entirely.]
            
            What this means for you: [ONE sentence. State what the agent can do after approval. \
            Only mention token expiration if an explicit expiration time is provided in the input.]
            
            Rules:
            1. Be extremely concise. The user should grasp the meaning within 5 seconds of reading.
            2. No greetings, no markdown, no extra commentary.
            3. Use plain language. Avoid jargon like "Rego", "OPA", "policy", "predicate".
            4. Never repeat information across sections. Each section adds NEW information only.
            5. Prefer concrete terms: "search for books" over "perform search operations".
            6. Respond in English.
            """;

    private final String modelName;
    private final long timeoutSeconds;

    /**
     * Constructs a new QwenLlmOperationTextRenderer with the specified model name and timeout.
     *
     * @param modelName the Qwen model name to use (e.g., "qwen3-coder-flash", "qwen-plus")
     * @param timeoutSeconds the timeout in seconds for LLM calls
     */
    public QwenLlmOperationTextRenderer(String modelName, long timeoutSeconds) {
        this.modelName = Objects.requireNonNull(modelName, "Model name must not be null");
        this.timeoutSeconds = timeoutSeconds;
        logger.info("Initialized QwenLlmOperationTextRenderer with model: {}, timeout: {}s",
                modelName, timeoutSeconds);
    }

    @Override
    public OperationTextRenderResult render(OperationTextRenderContext context) {
        logger.debug("Rendering operation text using Qwen LLM (model: {})", modelName);

        String prompt = buildPrompt(context);

        try {
            String renderedText = callQwenModel(prompt);
            SemanticExpansionLevel expansionLevel = determineExpansionLevel(context);

            logger.info("Qwen LLM rendered operation text: '{}' (expansion: {})",
                    renderedText, expansionLevel);
            return new OperationTextRenderResult(renderedText, expansionLevel);
        } catch (Exception exception) {
            logger.warn("Qwen LLM call failed, falling back to basic rendering. Error: {}",
                    exception.getMessage());
            return buildFallbackResult(context);
        }
    }

    /**
     * Builds the full prompt from the rendering context.
     * <p>
     * Constructs a structured prompt that includes the system instruction, Rego policy,
     * original user prompt, and contextual information to help the LLM produce an accurate
     * description.
     * </p>
     */
    private String buildPrompt(OperationTextRenderContext context) {
        StringBuilder prompt = new StringBuilder();

        prompt.append(SYSTEM_INSTRUCTION).append("\n\n");
        prompt.append("--- Input ---\n\n");

        String operationProposal = context.getOperationProposal();
        if (operationProposal != null && !operationProposal.isEmpty()) {
            prompt.append("Rego Policy:\n").append(operationProposal).append("\n\n");
        }

        String originalPrompt = context.getOriginalPrompt();
        if (originalPrompt != null && !originalPrompt.isEmpty()) {
            prompt.append("User's Original Request: \"").append(originalPrompt).append("\"\n\n");
        }

        OperationRequestContext requestContext = context.getRequestContext();
        if (requestContext != null) {
            prompt.append("Context:\n");
            if (requestContext.getChannel() != null) {
                prompt.append("- Channel: ").append(requestContext.getChannel()).append("\n");
            }
            if (requestContext.getLanguage() != null) {
                prompt.append("- Language: ").append(requestContext.getLanguage()).append("\n");
            }
            if (requestContext.getAgent() != null) {
                if (requestContext.getAgent().getPlatform() != null) {
                    prompt.append("- Platform: ").append(requestContext.getAgent().getPlatform()).append("\n");
                }
                if (requestContext.getAgent().getClient() != null) {
                    prompt.append("- Client: ").append(requestContext.getAgent().getClient()).append("\n");
                }
            }
        }

        if (context.getTokenExpiration() != null) {
            prompt.append("\nAuthorization valid until: ").append(context.getTokenExpiration()).append("\n");
        }

        prompt.append("\nPlease provide the three-part explanation (What this authorizes / Key constraints / What this means for you).");
        return prompt.toString();
    }

    /**
     * Calls the Qwen model via qwencode-sdk and returns the generated text.
     * <p>
     * Uses {@link QwenCodeCli#simpleQuery(String, TransportOptions, AssistantContentSimpleConsumers)}
     * consistent with the sample-agent's {@code QwenClientWrapper} implementation.
     * </p>
     */
    private String callQwenModel(String prompt) {
        TransportOptions options = new TransportOptions()
                .setModel(modelName)
                .setPermissionMode(PermissionMode.AUTO_EDIT)
                .setCwd("./")
                .setTurnTimeout(new Timeout(timeoutSeconds, TimeUnit.SECONDS))
                .setMessageTimeout(new Timeout(timeoutSeconds, TimeUnit.SECONDS));

        StringBuilder accumulatedText = new StringBuilder();
        AtomicReference<Exception> errorRef = new AtomicReference<>();

        AssistantContentSimpleConsumers consumers = new AssistantContentSimpleConsumers() {
            @Override
            public void onText(Session session, AssistantContent.TextAssistantContent textContent) {
                String text = textContent.getText();
                if (text != null) {
                    accumulatedText.append(text);
                }
            }

            @Override
            public void onToolUse(Session session, AssistantContent.ToolUseAssistantContent toolUseContent) {
                logger.debug("Ignoring unexpected tool use in operation text rendering");
            }

            @Override
            public void onToolResult(Session session, AssistantContent.ToolResultAssistantContent toolResultContent) {
                logger.debug("Ignoring unexpected tool result in operation text rendering");
            }
        };

        try {
            QwenCodeCli.simpleQuery(prompt, options, consumers);
        } catch (Exception exception) {
            errorRef.set(exception);
        }

        if (errorRef.get() != null) {
            throw new RuntimeException("Qwen model call failed: " + errorRef.get().getMessage(), errorRef.get());
        }

        String result = accumulatedText.toString().strip();
        if (result.isEmpty()) {
            throw new IllegalStateException("Qwen model returned empty content");
        }

        return result;
    }

    /**
     * Determines the semantic expansion level based on the available context.
     * <p>
     * LLM-based rendering always involves interpretation, so the minimum level is MEDIUM.
     * When the original prompt is absent and only the Rego policy is available,
     * the expansion level is HIGH since the LLM must infer user intent entirely.
     * </p>
     */
    private SemanticExpansionLevel determineExpansionLevel(OperationTextRenderContext context) {
        if (context.getOriginalPrompt() == null || context.getOriginalPrompt().isEmpty()) {
            return SemanticExpansionLevel.HIGH;
        }
        return SemanticExpansionLevel.MEDIUM;
    }

    /**
     * Builds a fallback result when the LLM call fails.
     * Falls back to a simple pattern-based description.
     */
    private OperationTextRenderResult buildFallbackResult(OperationTextRenderContext context) {
        String originalPrompt = context.getOriginalPrompt();
        if (originalPrompt != null && !originalPrompt.isEmpty()) {
            return OperationTextRenderResult.withLowExpansion("Authorized: " + originalPrompt);
        }

        String operationProposal = context.getOperationProposal();
        if (operationProposal != null && !operationProposal.isEmpty()) {
            String preview = operationProposal.length() > 80
                    ? operationProposal.substring(0, 80) + "..."
                    : operationProposal;
            return OperationTextRenderResult.withLowExpansion(
                    "Authorized agent operation per policy: " + preview);
        }

        return OperationTextRenderResult.withNoExpansion("Authorized agent operation");
    }
}
