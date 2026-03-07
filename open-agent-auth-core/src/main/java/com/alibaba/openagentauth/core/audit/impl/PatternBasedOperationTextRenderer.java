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
package com.alibaba.openagentauth.core.audit.impl;

import com.alibaba.openagentauth.core.audit.model.OperationTextRenderContext;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;
import com.alibaba.openagentauth.core.audit.model.SemanticExpansionLevel;
import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;
import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Pattern-based implementation of {@link OperationTextRenderer}.
 * <p>
 * This renderer generates human-readable operation text by extracting structured
 * information from the rendering context and composing it using predefined patterns.
 * It serves as the default rendering strategy when no LLM or custom renderer is configured.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization-01, the rendered text should
 * provide a description like: "Purchase items under $50 during the Nov 11 promotion
 * (valid until 23:59)"
 * </p>
 *
 * @see OperationTextRenderer
 * @since 1.0
 */
public class PatternBasedOperationTextRenderer implements OperationTextRenderer {

    private static final Logger logger = LoggerFactory.getLogger(PatternBasedOperationTextRenderer.class);

    /**
     * Maximum number of characters to include from the operation proposal before truncating.
     * Longer proposals are trimmed and appended with "..." to keep the rendered text concise.
     */
    private static final int MAX_POLICY_PREVIEW_LENGTH = 50;

    /**
     * Formatter for rendering token expiration times in a human-readable "HH:mm" format.
     */
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm");

    /**
     * {@inheritDoc}
     * <p>
     * This implementation follows a priority-based rendering strategy:
     * </p>
     * <ol>
     *   <li>If the original user prompt is available, renders "Authorized: {prompt}"</li>
     *   <li>If only the operation proposal is available, renders a truncated policy preview</li>
     *   <li>Otherwise, renders a generic "Authorized agent operation" fallback</li>
     * </ol>
     * <p>
     * Context information (channel, platform) and token expiration are appended when available.
     * </p>
     */
    @Override
    public OperationTextRenderResult render(OperationTextRenderContext context) {
        logger.debug("Rendering operation text using pattern-based strategy");

        StringBuilder rendered = new StringBuilder();
        SemanticExpansionLevel expansionLevel = SemanticExpansionLevel.NONE;

        String originalPrompt = context.getOriginalPrompt();
        String operationProposal = context.getOperationProposal();

        if (originalPrompt != null && !originalPrompt.isEmpty()) {
            rendered.append("Authorized: ").append(originalPrompt);
            expansionLevel = SemanticExpansionLevel.LOW;
        } else if (operationProposal != null && !operationProposal.isEmpty()) {
            String policyPreview = operationProposal.length() > MAX_POLICY_PREVIEW_LENGTH
                    ? operationProposal.substring(0, MAX_POLICY_PREVIEW_LENGTH) + "..."
                    : operationProposal;
            rendered.append("Authorized agent operation per policy: ").append(policyPreview);
            expansionLevel = SemanticExpansionLevel.LOW;
        } else {
            rendered.append("Authorized agent operation");
        }

        appendContextInfo(rendered, context.getRequestContext());
        appendExpirationInfo(rendered, context);

        String resultText = rendered.toString();
        logger.debug("Rendered operation text: {}", resultText);
        return new OperationTextRenderResult(resultText, expansionLevel);
    }

    /**
     * Appends channel and platform information from the request context to the rendered text.
     * <p>
     * Adds " via {channel}" and/or " on {platform}" suffixes when the respective values
     * are present and non-empty.
     * </p>
     *
     * @param rendered the string builder to append to
     * @param requestContext the request context, may be null
     */
    private void appendContextInfo(StringBuilder rendered, OperationRequestContext requestContext) {
        if (requestContext == null) {
            return;
        }

        if (requestContext.getChannel() != null && !requestContext.getChannel().isEmpty()) {
            rendered.append(" via ").append(requestContext.getChannel());
        }

        if (requestContext.getAgent() != null && requestContext.getAgent().getPlatform() != null) {
            rendered.append(" on ").append(requestContext.getAgent().getPlatform());
        }
    }

    /**
     * Appends token expiration information to the rendered text.
     * <p>
     * Adds a " (valid until HH:mm)" suffix when the token expiration is set.
     * The time is formatted in the system's default time zone.
     * </p>
     *
     * @param rendered the string builder to append to
     * @param context the render context containing the token expiration
     */
    private void appendExpirationInfo(StringBuilder rendered, OperationTextRenderContext context) {
        if (context.getTokenExpiration() == null) {
            return;
        }

        String expiresTime = context.getTokenExpiration()
                .atZone(ZoneId.systemDefault())
                .format(TIME_FORMATTER);
        rendered.append(" (valid until ").append(expiresTime).append(")");
    }
}
