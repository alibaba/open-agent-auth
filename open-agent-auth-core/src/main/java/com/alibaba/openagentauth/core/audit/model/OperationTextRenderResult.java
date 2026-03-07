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
package com.alibaba.openagentauth.core.audit.model;

import com.alibaba.openagentauth.core.audit.api.OperationTextRenderer;

import java.util.Objects;

/**
 * Immutable result object returned by {@link OperationTextRenderer}.
 * <p>
 * This class encapsulates both the rendered operation text and the semantic expansion
 * level that was applied during rendering. According to draft-liu-agent-operation-authorization-01,
 * both pieces of information are required for the {@code auditTrail} claim in the AOAT.
 * </p>
 *
 * @see OperationTextRenderer
 * @see SemanticExpansionLevel
 * @since 1.0
 */
public class OperationTextRenderResult {

    /**
     * The human-readable description of the authorized operation.
     * This text is included in the AOAT's {@code auditTrail.renderedOperationText} claim.
     */
    private final String renderedText;

    /**
     * The level of semantic expansion applied during rendering.
     * Indicates how much interpretation was added beyond the user's original input.
     */
    private final SemanticExpansionLevel semanticExpansionLevel;

    /**
     * Constructs a new render result with the given text and expansion level.
     *
     * @param renderedText the rendered operation text, must not be null
     * @param semanticExpansionLevel the semantic expansion level applied, must not be null
     * @throws NullPointerException if either parameter is null
     */
    public OperationTextRenderResult(String renderedText, SemanticExpansionLevel semanticExpansionLevel) {
        this.renderedText = Objects.requireNonNull(renderedText, "renderedText must not be null");
        this.semanticExpansionLevel = Objects.requireNonNull(semanticExpansionLevel,
                "semanticExpansionLevel must not be null");
    }

    /**
     * Returns the human-readable rendered operation text.
     *
     * @return the rendered text, never null
     */
    public String getRenderedText() {
        return renderedText;
    }

    /**
     * Returns the semantic expansion level applied during rendering.
     *
     * @return the expansion level, never null
     */
    public SemanticExpansionLevel getSemanticExpansionLevel() {
        return semanticExpansionLevel;
    }

    /**
     * Creates a result with {@link SemanticExpansionLevel#NONE} expansion.
     * Use when the rendered text is a direct representation without interpretation.
     *
     * @param renderedText the rendered operation text, must not be null
     * @return a new result with no semantic expansion
     */
    public static OperationTextRenderResult withNoExpansion(String renderedText) {
        return new OperationTextRenderResult(renderedText, SemanticExpansionLevel.NONE);
    }

    /**
     * Creates a result with {@link SemanticExpansionLevel#LOW} expansion.
     * Use when the rendered text includes minor formatting or normalization.
     *
     * @param renderedText the rendered operation text, must not be null
     * @return a new result with low semantic expansion
     */
    public static OperationTextRenderResult withLowExpansion(String renderedText) {
        return new OperationTextRenderResult(renderedText, SemanticExpansionLevel.LOW);
    }

    /**
     * Creates a result with {@link SemanticExpansionLevel#MEDIUM} expansion.
     * Use when the rendered text includes interpretation of ambiguous terms.
     *
     * @param renderedText the rendered operation text, must not be null
     * @return a new result with medium semantic expansion
     */
    public static OperationTextRenderResult withMediumExpansion(String renderedText) {
        return new OperationTextRenderResult(renderedText, SemanticExpansionLevel.MEDIUM);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OperationTextRenderResult that = (OperationTextRenderResult) o;
        return Objects.equals(renderedText, that.renderedText)
                && semanticExpansionLevel == that.semanticExpansionLevel;
    }

    @Override
    public int hashCode() {
        return Objects.hash(renderedText, semanticExpansionLevel);
    }

    @Override
    public String toString() {
        return "OperationTextRenderResult{" +
                "renderedText='" + renderedText + '\'' +
                ", semanticExpansionLevel=" + semanticExpansionLevel +
                '}';
    }
}
